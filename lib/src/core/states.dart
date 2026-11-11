
import '../api/opnsense_client.dart';
import 'network_map.dart';

/// Builds the `kill_states` filter for an IP or subnet.
///
/// OPNsense strips `/` from the filter (SanitizeFilter "query"), so:
/// * a single host (`/32`) becomes a *network* clause, e.g. `10.10.40.50`,
///   which matches src/dst/nat/gateway addresses exactly;
/// * a subnet becomes a *text* clause on the octet boundary at or above its
///   prefix, e.g. `10.10.40.0/24` -> `10.10.40.`. That is a substring match,
///   so it can also hit e.g. `110.10.40.x`. Dropping a few unrelated states
///   only makes those connections re-establish, which is acceptable.
String stateKillFilter(String cidrOrIp) {
  final net = Ipv4Subnet.tryParse(cidrOrIp);
  if (net == null) throw ArgumentError.value(cidrOrIp, 'cidrOrIp', 'not IPv4');
  final ip = intToIpv4(net.network);
  if (net.prefix == 32) return ip;
  final octets = (net.prefix ~/ 8).clamp(1, 3);
  return '${ip.split('.').take(octets).join('.')}.';
}

class StateKillResult {
  const StateKillResult({this.dropped, this.warning});

  /// States dropped; null when the router's answer was lost.
  final int? dropped;

  /// Non-fatal problem worth showing to the user.
  final String? warning;

  String describe() {
    if (warning != null) return warning!;
    if (dropped == null) return 'old connections reset';
    return '$dropped old connection${dropped == 1 ? '' : 's'} reset';
  }
}

/// Drops existing pf states for [cidrOrIp] so connections re-open on the new
/// path (VPN <-> direct). Never throws: the mode change itself has already
/// succeeded, so failures here are reported as warnings.
///
/// The device running Cybervulcan is usually inside the affected range, so
/// the state of the kill request's own connection is dropped too and its
/// reply may never arrive. A timeout or reset is therefore treated as
/// "probably done". All API calls use fresh connections, so later calls are
/// unaffected.
Future<StateKillResult> killStatesFor(OpnsenseClient client, String cidrOrIp) async {
  try {
    final n = await client.killStates(stateKillFilter(cidrOrIp));
    return StateKillResult(dropped: n);
  } on OpnsenseException catch (e) {
    switch (e.kind) {
      case ApiErrorKind.network:
        return const StateKillResult();
      case ApiErrorKind.forbidden:
        return const StateKillResult(
            warning: 'Existing connections were not reset: the API user needs '
                '"Diagnostics: Show States".');
      default:
        return StateKillResult(warning: 'Existing connections were not reset: ${e.message}');
    }
  } on ArgumentError catch (e) {
    return StateKillResult(warning: 'Existing connections were not reset: ${e.message}');
  }
}
