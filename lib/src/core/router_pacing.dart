// v2.2.7: pacing for configuration writes to the router.
//
// 24 Nov: twice the router's web GUI and API stopped answering right after a
// long "Find best". The console showed a calm scan, then - as the scan ended
// and the app re-added the tested servers to the router's server list - the
// router's service-status calls started to hang and pile up until every web
// worker was stuck. Each list entry is a separate configuration save, so the
// app now waits for the router to settle, writes one entry at a time with a
// gap, and checks before every write that the router still answers a plain
// read quickly. When it does not, the app stops; the rest is written on the
// next sync instead of adding load to a router that is already struggling.

/// Sleeps for a duration (replaceable in tests).
typedef PaceSleep = Future<void> Function(Duration d);

class RouterWritePacer {
  RouterWritePacer({
    required this.probe,
    this.gap = defaultGap,
    this.slow = defaultSlow,
    PaceSleep? sleep,
    DateTime Function()? clock,
  })  : _sleep = sleep ?? Future<void>.delayed,
        _clock = clock ?? DateTime.now;

  /// Gap between two writes.
  static const defaultGap = Duration(seconds: 5);

  /// A read slower than this means the router is busy: stop writing.
  static const defaultSlow = Duration(seconds: 4);

  /// A cheap read of the router (the app uses the WireGuard peer list, which
  /// needs the same configuration lock the writes need).
  final Future<void> Function() probe;
  final Duration gap;
  final Duration slow;
  final PaceSleep _sleep;
  final DateTime Function() _clock;

  /// Call before write number [done] (counted from 0). Waits [gap] (not
  /// before the first write), then checks the router. Returns false when the
  /// router is slow or failing - the caller stops writing.
  Future<bool> beforeWrite(int done) async {
    if (done > 0 && gap > Duration.zero) await _sleep(gap);
    final t0 = _clock();
    try {
      await probe().timeout(slow * 2);
    } on Object {
      return false;
    }
    return _clock().difference(t0) <= slow;
  }
}

/// v2.2.7: how often to poll while the router answers slowly or not at all.
/// Each slow or failed poll doubles the interval (from [normal]) up to
/// [max]; one quick answer brings it straight back. Every device runs this,
/// so a jammed router is not hit by all of them every few seconds.
Duration backedOffPollInterval(Duration normal, int slowPollsInARow,
    {Duration max = const Duration(minutes: 5)}) {
  if (slowPollsInARow <= 0 || normal >= max) return normal;
  var d = normal;
  for (var i = 0; i < slowPollsInARow && d < max; i++) {
    d *= 2;
  }
  return d > max ? max : d;
}

/// A poll that took longer than this counts as slow for [backedOffPollInterval].
const slowPollThreshold = Duration(seconds: 8);

/// The router answered too slowly to keep writing (see [RouterWritePacer]).
class RouterBusyException implements Exception {
  RouterBusyException(this.message);
  final String message;
  @override
  String toString() => message;
}
