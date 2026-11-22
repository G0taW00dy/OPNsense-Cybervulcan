/// Traffic shaper models (v2.1 shaper card and auto-tune).
///
/// Shapes verified against OPNsense 26.7 on the house router:
/// * `POST /api/trafficshaper/settings/search_pipes` -> `{rows: [{uuid,
///   enabled, number, bandwidth, bandwidthMetric, description, ...}]}`.
/// * `GET /api/trafficshaper/service/statistics` -> `{status: ok, items: [
///   {type: pipe, pipe: "10002", rules: [...]}, {type: queue, sched_nr:
///   "10002", rules: [{bytes, pkts}]}, ...]}` - queues hang under the pipe
///   whose number equals their `sched_nr`.
library;

int? _int(Object? v) => v is num ? v.toInt() : int.tryParse('${v ?? ''}'.trim());

class ShaperPipe {
  const ShaperPipe({
    required this.uuid,
    required this.number,
    required this.description,
    required this.mbit,
    required this.enabled,
  });

  final String uuid;
  final int? number;
  final String description;

  /// Bandwidth in Mbit/s (converted from the pipe's metric).
  final double mbit;
  final bool enabled;

  factory ShaperPipe.fromJson(Map<String, dynamic> j) {
    final bw = double.tryParse('${j['bandwidth'] ?? ''}'.trim()) ?? 0;
    final metric = '${j['bandwidthMetric'] ?? 'Mbit'}'.toLowerCase();
    final mbit = switch (metric) {
      'bit' => bw / 1e6,
      'kbit' => bw / 1e3,
      'gbit' => bw * 1e3,
      _ => bw,
    };
    return ShaperPipe(
      uuid: '${j['uuid'] ?? ''}',
      number: _int(j['number']),
      description: '${j['description'] ?? ''}',
      mbit: mbit,
      enabled: j['enabled'] == '1' || j['enabled'] == 1 || j['enabled'] == true,
    );
  }

  bool get _vpn => description.toLowerCase().contains('vpn');
  bool get looksVpnDownload => _vpn && description.toLowerCase().contains('down');
  bool get looksVpnUpload => _vpn && description.toLowerCase().contains('up');

  bool get _clear => !_vpn && description.toLowerCase().contains('clear');
  bool get looksClearDownload => _clear && description.toLowerCase().contains('down');
  bool get looksClearUpload => _clear && description.toLowerCase().contains('up') && !description.toLowerCase().contains('down');
}

/// The CLEAR (direct internet) download / upload pipes, by description.
({ShaperPipe down, ShaperPipe up})? findClearPipes(List<ShaperPipe> pipes) {
  final d = pipes.where((p) => p.enabled && p.looksClearDownload).firstOrNull;
  final u = pipes.where((p) => p.enabled && p.looksClearUpload).firstOrNull;
  return d == null || u == null ? null : (down: d, up: u);
}

/// The VPN download / upload pipes, found by description ("VPN download",
/// "VPN upload"), or null when the router has no such pipes.
({ShaperPipe down, ShaperPipe up})? findVpnPipes(List<ShaperPipe> pipes) {
  final d = pipes.where((p) => p.enabled && p.looksVpnDownload).firstOrNull;
  final u = pipes.where((p) => p.enabled && p.looksVpnUpload).firstOrNull;
  return d == null || u == null ? null : (down: d, up: u);
}

Map<int, int> shaperBytesFromStatistics(Map<String, dynamic> json) {
  final out = <int, int>{};
  final items = json['items'];
  if (items is! List) return out;
  int sumRules(Object? rules) {
    var s = 0;
    if (rules is List) {
      for (final r in rules) {
        if (r is Map) s += _int(r['bytes']) ?? 0;
      }
    }
    return s;
  }

  for (final i in items) {
    if (i is! Map) continue;
    final n = i['type'] == 'pipe' ? _int(i['pipe']) : (i['type'] == 'queue' ? _int(i['sched_nr']) : null);
    if (n == null) continue;
    out[n] = (out[n] ?? 0) + sumRules(i['rules']);
  }
  return out;
}

/// Enabled pipes for display: VPN first, then the rest; download before upload.
List<ShaperPipe> shaperDisplayOrder(List<ShaperPipe> pipes) {
  int rank(ShaperPipe p) {
    final d = p.description.toLowerCase();
    return (d.contains('vpn') ? 0 : 2) + (d.contains('up') && !d.contains('down') ? 1 : 0);
  }

  final list = pipes.where((p) => p.enabled).toList();
  list.sort((a, b) {
    final r = rank(a).compareTo(rank(b));
    return r != 0 ? r : a.description.compareTo(b.description);
  });
  return list;
}

// ------------------------------------------------------------ v2.1.13
// Shaper by exit path (22 Nov): rules on the WireGuard tunnel interfaces use
// the VPN pipes ("Tunnel"), rules on WAN use the CLEAR pipes ("Direct line").
// A device switched to CLEAR stays on the VPN network but leaves via WAN, so
// it must be shaped by the line limit - rules by source network got that
// wrong (the PC on CLEAR was held to the VPN limit).

/// Any VPN download / upload pipes, switched on or off.
({ShaperPipe down, ShaperPipe up})? findVpnPipesAny(List<ShaperPipe> pipes) {
  final d = pipes.where((p) => p.looksVpnDownload).firstOrNull;
  final u = pipes.where((p) => p.looksVpnUpload).firstOrNull;
  return d == null || u == null ? null : (down: d, up: u);
}

/// Any CLEAR (direct line) download / upload pipes, switched on or off.
({ShaperPipe down, ShaperPipe up})? findClearPipesAny(List<ShaperPipe> pipes) {
  final d = pipes.where((p) => p.looksClearDownload).firstOrNull;
  final u = pipes.where((p) => p.looksClearUpload).firstOrNull;
  return d == null || u == null ? null : (down: d, up: u);
}

class ShaperQueue {
  const ShaperQueue({required this.uuid, required this.pipe, required this.description, required this.enabled});
  final String uuid;

  /// UUID of the pipe the queue feeds.
  final String pipe;
  final String description;
  final bool enabled;

  factory ShaperQueue.fromJson(Map<String, dynamic> j) => ShaperQueue(
        uuid: '${j['uuid'] ?? ''}',
        pipe: '${j['pipe'] ?? ''}',
        description: '${j['description'] ?? ''}',
        enabled: j['enabled'] == '1' || j['enabled'] == 1 || j['enabled'] == true,
      );
}

class ShaperRule {
  const ShaperRule({
    required this.uuid,
    required this.enabled,
    required this.interface,
    required this.direction,
    required this.target,
    required this.description,
    this.sequence,
  });
  final String uuid;
  final bool enabled;

  /// Interface key (wan, opt5, ...).
  final String interface;

  /// in / out / both ('' = both).
  final String direction;

  /// UUID of the queue or pipe the rule feeds.
  final String target;
  final String description;
  final int? sequence;

  factory ShaperRule.fromJson(Map<String, dynamic> j) => ShaperRule(
        uuid: '${j['uuid'] ?? ''}',
        enabled: j['enabled'] == '1' || j['enabled'] == 1 || j['enabled'] == true,
        interface: '${j['interface'] ?? ''}',
        direction: '${j['direction'] ?? ''}',
        target: '${j['target'] ?? ''}',
        description: '${j['description'] ?? ''}',
        sequence: _int(j['sequence']),
      );
}

enum ShaperLayout {
  /// Tunnel rules on the WireGuard interfaces and line rules on WAN.
  exitPath,

  /// Rules exist but not by exit path (e.g. by VPN / CLEAR network).
  other,

  /// No enabled rules feed the VPN / CLEAR pipes.
  none,
}

/// Which pipe (uuid) a rule ends up in: its target, or the pipe of its queue.
String _pipeOf(ShaperRule r, List<ShaperQueue> queues) =>
    queues.where((q) => q.uuid == r.target).firstOrNull?.pipe ?? r.target;

/// Classifies the router's shaper rules. [tunnelIfaces] are the interface
/// keys of the house WireGuard tunnels (main and backup), [wanIface] the WAN.
ShaperLayout classifyShaperLayout({
  required List<ShaperRule> rules,
  required List<ShaperQueue> queues,
  required List<ShaperPipe> pipes,
  required Set<String> tunnelIfaces,
  String wanIface = 'wan',
}) {
  final vpn = findVpnPipesAny(pipes);
  final line = findClearPipesAny(pipes);
  if (vpn == null || line == null) return ShaperLayout.none;
  final live = rules.where((r) => r.enabled).toList();
  bool has(String iface, String dir, String pipe) =>
      live.any((r) => r.interface == iface && r.direction == dir && _pipeOf(r, queues) == pipe);
  final used = {vpn.down.uuid, vpn.up.uuid, line.down.uuid, line.up.uuid};
  if (!live.any((r) => used.contains(_pipeOf(r, queues)))) return ShaperLayout.none;
  final tunnelOk = tunnelIfaces.isNotEmpty &&
      tunnelIfaces.every((i) => has(i, 'in', vpn.down.uuid) && has(i, 'out', vpn.up.uuid));
  final lineOk = has(wanIface, 'in', line.down.uuid) && has(wanIface, 'out', line.up.uuid);
  // Old rules by source network would shape a second time: not exit-path.
  final stray = live.any((r) =>
      used.contains(_pipeOf(r, queues)) && r.interface != wanIface && !tunnelIfaces.contains(r.interface));
  return tunnelOk && lineOk && !stray ? ShaperLayout.exitPath : ShaperLayout.other;
}

/// Recommended limits from a speed test with the shaper OFF, measured on the
/// house line on 22 Nov 2026: the tunnel stayed lag-free with its limit at
/// about the unshaped speed (410 for 413 measured: the limit counts traffic
/// inside the tunnel and the tunnel delivers ~82 % of it), the direct line
/// with ~98 % down / ~97 % up (540 / 52 for 549 / 53.5).
({int down, int up}) recommendedLimits({required bool tunnel, required double downMbps, required double upMbps}) {
  final fd = tunnel ? 1.0 : 0.98;
  final fu = tunnel ? 1.0 : 0.97;
  int r(double v) => v < 1 ? 1 : v.round();
  return (down: r(downMbps * fd), up: r(upMbps * fu));
}

/// Real speed to expect through a limit (for the hint under the fields).
int expectedRealMbps({required bool tunnel, required int limit}) => (limit * (tunnel ? 0.82 : 0.97)).round();
