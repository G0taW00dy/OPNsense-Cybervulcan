import 'dart:math';

import '../api/opnsense_client.dart';
import '../api/shaper_models.dart';
import 'config.dart';

/// Auto-tuning for the router's FQ-CoDel shaper (v2.1).
///
/// The idea (like cake-autorate on Linux routers, which OPNsense lacks): a
/// mobile line's speed moves all the time, so a fixed shaper limit is either
/// too high (the queue builds in the carrier's network -> lag) or too low
/// (wasted speed). The tuner watches the VPN tunnel's latency (the router's
/// gateway monitor) and how busy each direction is (shaper byte counters):
///
/// * lag rising while a direction is busy -> lower that direction's limit;
/// * a busy direction with low lag -> raise its limit a little;
/// * lag without VPN load (e.g. CLEAR traffic on the shared line) -> leave
///   the limits alone, they can't help.
///
/// Limits stay between the min/max in Settings. Pure decision logic lives in
/// [decideTune] (unit-tested); [ShaperTuner] does the router I/O.

/// Added delay (ms) above the idle baseline that counts as bufferbloat.
const tuneBloatMs = 80.0;

/// Added delay (ms) below which a busy direction may be raised.
const tuneClearMs = 30.0;

/// A direction is "busy" above this share of its limit.
const tuneBusyShare = 0.7;

/// Min/max limits (Mbit/s) one tuner may move its pipes between.
class TuneRange {
  const TuneRange(this.minDown, this.maxDown, this.minUp, this.maxUp);
  TuneRange.vpn(AppConfig c) : this(c.shaperMinDown, c.shaperMaxDown, c.shaperMinUp, c.shaperMaxUp);
  TuneRange.clear(AppConfig c)
      : this(c.shaperClearMinDown, c.shaperClearMaxDown, c.shaperClearMinUp, c.shaperClearMaxUp);
  final int minDown, maxDown, minUp, maxUp;
}

class TuneDecision {
  const TuneDecision({this.down, this.up, required this.reason});
  final int? down;
  final int? up;
  final String reason;
  bool get changes => down != null || up != null;
}

TuneDecision decideTune({
  required double delayMs,
  required double baselineMs,
  required double rateDownMbit,
  required double rateUpMbit,
  required int down,
  required int up,
  required AppConfig cfg,
  TuneRange? range,
  String label = 'VPN',
}) {
  final r = range ?? TuneRange.vpn(cfg);
  final bloat = delayMs - baselineMs;
  final busyDown = rateDownMbit > tuneBusyShare * down;
  final busyUp = rateUpMbit > tuneBusyShare * up;
  int clampDown(double v) => v.round().clamp(r.minDown, max(r.minDown, r.maxDown));
  int clampUp(double v) => v.round().clamp(r.minUp, max(r.minUp, r.maxUp));
  int? changed(int now, int next) => next == now ? null : next;

  if (bloat > tuneBloatMs) {
    if (!busyDown && !busyUp) {
      return TuneDecision(reason: 'Lag +${bloat.round()} ms without much $label traffic - not the shaper\'s doing; no change.');
    }
    return TuneDecision(
      // Never let the clamp move a limit the other way (a pipe already below
      // the range must not be raised while lagging).
      down: busyDown ? changed(down, min(down, clampDown(down * 0.85))) : null,
      up: busyUp ? changed(up, min(up, clampUp(up * 0.85))) : null,
      reason: 'Lag +${bloat.round()} ms while busy - lowering the limit.',
    );
  }
  if (bloat < tuneClearMs && (busyDown || busyUp)) {
    return TuneDecision(
      down: busyDown ? changed(down, max(down, clampDown(max(down * 1.08, down + 1.0)))) : null,
      up: busyUp ? changed(up, max(up, clampUp(max(up * 1.08, up + 1.0)))) : null,
      reason: 'Busy with low lag (+${bloat.round()} ms) - raising the limit a little.',
    );
  }
  return TuneDecision(reason: 'Lag +${bloat.round()} ms - holding.');
}

/// Lowest delay seen recently while the line was quiet = the idle baseline.
class DelayBaseline {
  DelayBaseline({this.window = const Duration(minutes: 10)});
  final Duration window;
  final _samples = <(DateTime, double)>[];

  void add(DateTime at, double delayMs) {
    _samples.add((at, delayMs));
    _samples.removeWhere((s) => at.difference(s.$1) > window);
  }

  double? get value => _samples.isEmpty ? null : _samples.map((s) => s.$2).reduce(min);

  /// After a server switch the path is different: start again.
  void reset() => _samples.clear();
}

/// Router side of the tuner. One instance per controller; [tick] is called
/// after each good status poll while auto-tune is on.
class ShaperTuner {
  ShaperTuner({
    DateTime Function()? clock,
    this.minGap = const Duration(seconds: 30),
    this.label = 'VPN',
    ({ShaperPipe down, ShaperPipe up})? Function(List<ShaperPipe>)? find,
    TuneRange Function(AppConfig)? range,
  })  : _clock = clock ?? DateTime.now,
        _find = find ?? findVpnPipes,
        _range = range ?? TuneRange.vpn;

  /// The CLEAR (direct internet) tuner.
  ShaperTuner.clear({DateTime Function()? clock, Duration minGap = const Duration(seconds: 30)})
      : this(clock: clock, minGap: minGap, label: 'CLEAR', find: findClearPipes, range: TuneRange.clear);

  final String label;
  final ({ShaperPipe down, ShaperPipe up})? Function(List<ShaperPipe>) _find;
  final TuneRange Function(AppConfig) _range;

  final DateTime Function() _clock;
  final Duration minGap;
  final baseline = DelayBaseline();

  ({ShaperPipe down, ShaperPipe up})? _pipes;
  DateTime? _pipesAt;
  Map<int, int>? _lastBytes;
  DateTime? _lastBytesAt;
  DateTime? _lastChange;

  /// Last decision, for the Settings card.
  String? lastReason;
  int? currentDown;
  int? currentUp;

  /// Called after a server switch: new path, new baseline, fresh pipe read.
  void pathChanged() {
    baseline.reset();
    _pipes = null;
  }

  /// One tuning step. [delayMs] is the active VPN gateway's delay; returns
  /// the decision when something changed on the router.
  Future<TuneDecision?> tick(OpnsenseClient client, AppConfig cfg, double? delayMs) async {
    if (delayMs == null) return null;
    final now = _clock();
    if (_pipes == null || _pipesAt == null || now.difference(_pipesAt!) > const Duration(minutes: 10)) {
      _pipes = _find(await client.shaperPipes());
      _pipesAt = now;
      if (_pipes == null) {
        lastReason = 'No $label shaper pipes found (descriptions with "$label" and "download"/"upload").';
        return null;
      }
    }
    final p = _pipes!;
    currentDown ??= p.down.mbit.round();
    currentUp ??= p.up.mbit.round();

    final bytes = await client.shaperBytes();
    final prev = _lastBytes;
    final prevAt = _lastBytesAt;
    _lastBytes = bytes;
    _lastBytesAt = now;
    if (prev == null || prevAt == null) return null;
    final secs = now.difference(prevAt).inMilliseconds / 1000;
    if (secs <= 0) return null;
    double rate(ShaperPipe pipe) {
      final n = pipe.number;
      if (n == null) return 0;
      final d = (bytes[n] ?? 0) - (prev[n] ?? 0);
      return d <= 0 ? 0 : d * 8 / secs / 1e6; // counters reset on reconfigure
    }

    final down = rate(p.down), up = rate(p.up);
    final quiet = down < 0.2 * currentDown! && up < 0.2 * currentUp!;
    if (quiet) baseline.add(now, delayMs);
    final base = baseline.value;
    if (base == null) return null;

    final d = decideTune(
        delayMs: delayMs,
        baselineMs: base,
        rateDownMbit: down,
        rateUpMbit: up,
        down: currentDown!,
        up: currentUp!,
        cfg: cfg,
        range: _range(cfg),
        label: label);
    lastReason = d.reason;
    if (!d.changes) return null;
    if (_lastChange != null && now.difference(_lastChange!) < minGap) return null;

    if (d.down != null) await client.setPipeBandwidth(p.down.uuid, d.down!);
    if (d.up != null) await client.setPipeBandwidth(p.up.uuid, d.up!);
    await client.shaperReconfigure();
    _lastChange = now;
    currentDown = d.down ?? currentDown;
    currentUp = d.up ?? currentUp;
    _lastBytes = null; // counters restart after a reconfigure
    return d;
  }
}
