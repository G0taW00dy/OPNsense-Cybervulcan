import '../api/models.dart';
import '../api/opnsense_client.dart';

/// Which Proton tunnel the house is currently leaving through.
enum ProtonExit { main, backup, none, unknown }

/// Overall indicator; maps 1:1 to the tray icon colours.
enum Health {
  /// green - main tunnel up, nothing unusual.
  ok,

  /// amber - failover active, latency/loss, or a change in progress.
  warning,

  /// red - router unreachable, API error, or kill switch tripped.
  problem,

  /// purple - whole-house VPN bypass is active.
  bypass,

  /// grey - not configured yet.
  notConfigured,
}

class KillSwitchState {
  const KillSwitchState({this.armed, required this.tripped, this.detail});

  /// true = block rule present and enabled; false = missing/disabled;
  /// null = could not be determined (privilege not granted).
  final bool? armed;

  /// Both Proton gateways down: the VPN network has no internet.
  final bool tripped;
  final String? detail;
}

class HouseSnapshot {
  const HouseSnapshot({
    required this.fetchedAt,
    this.configured = true,
    this.error,
    this.main,
    this.backup,
    this.bypassActive,
    this.bypassExpiresAt,
    this.pcIp,
    this.pcClear,
    this.killSwitchArmed,
    this.killSwitchDetail,
    this.busy = false,
  });

  final DateTime fetchedAt;
  final bool configured;

  /// Error that prevented the core (gateway) status from loading.
  final OpnsenseException? error;
  final GatewayStatus? main;
  final GatewayStatus? backup;

  /// null = unknown (privilege missing / not loaded).
  final bool? bypassActive;
  final DateTime? bypassExpiresAt;
  final String? pcIp;

  /// PC currently listed in the PC-mode (CLEAR) alias. null = unknown/not PC.
  final bool? pcClear;
  final bool? killSwitchArmed;
  final String? killSwitchDetail;

  /// A user-initiated change is in flight.
  final bool busy;

  static HouseSnapshot unconfigured(DateTime now) =>
      HouseSnapshot(fetchedAt: now, configured: false);

  bool get reachable => configured && error == null;

  ProtonExit get exit {
    if (!reachable || (main == null && backup == null)) return ProtonExit.unknown;
    if (main?.health.isUp ?? false) return ProtonExit.main;
    if (backup?.health.isUp ?? false) return ProtonExit.backup;
    return ProtonExit.none;
  }

  /// Main down and backup carrying the traffic.
  bool get failoverActive => exit == ProtonExit.backup;

  GatewayStatus? get activeGateway => switch (exit) {
        ProtonExit.main => main,
        ProtonExit.backup => backup,
        _ => null,
      };

  KillSwitchState get killSwitch => KillSwitchState(
        armed: killSwitchArmed,
        tripped: exit == ProtonExit.none,
        detail: killSwitchDetail,
      );

  Health get health {
    if (!configured) return Health.notConfigured;
    if (!reachable) return Health.problem;
    // While bypass is on the VPN network goes direct, so a tunnel outage does
    // not take it offline - bypass (purple) wins over "tripped".
    if (bypassActive ?? false) return Health.bypass;
    if (exit == ProtonExit.none || exit == ProtonExit.unknown) return Health.problem;
    if (killSwitchArmed == false) return Health.problem;
    if (busy) return Health.warning;
    if (failoverActive) return Health.warning;
    if (activeGateway?.health.isDegraded ?? false) return Health.warning;
    return Health.ok;
  }

  HouseSnapshot copyWith({
    bool? busy,
    bool? bypassActive,
    DateTime? bypassExpiresAt,
    bool clearBypassExpiry = false,
    bool? pcClear,
  }) =>
      HouseSnapshot(
        fetchedAt: fetchedAt,
        configured: configured,
        error: error,
        main: main,
        backup: backup,
        bypassActive: bypassActive ?? this.bypassActive,
        bypassExpiresAt: clearBypassExpiry ? null : (bypassExpiresAt ?? this.bypassExpiresAt),
        pcIp: pcIp,
        pcClear: pcClear ?? this.pcClear,
        killSwitchArmed: killSwitchArmed,
        killSwitchDetail: killSwitchDetail,
        busy: busy ?? this.busy,
      );
}

/// Finds the gateway named [name] (case-insensitive).
GatewayStatus? findGateway(List<GatewayStatus> all, String name) {
  final n = name.toLowerCase();
  for (final g in all) {
    if (g.name.toLowerCase() == n) return g;
  }
  return null;
}

/// Decides kill-switch "armed" from `search_rule` results: an enabled
/// block/reject rule whose "tagged" match equals [tag].
({bool armed, String detail}) evaluateKillSwitchRules(
    List<FirewallRule> rules, String tag) {
  final candidates = rules
      .where((r) => r.isBlocking && (r.tagged ?? '').trim().toUpperCase() == tag.toUpperCase())
      .toList();
  if (candidates.isEmpty) {
    return (armed: false, detail: 'No block rule matching tag $tag found');
  }
  final enabled = candidates.where((r) => r.enabled).toList();
  if (enabled.isEmpty) {
    return (armed: false, detail: 'Kill switch rule exists but is disabled');
  }
  final r = enabled.first;
  final hits = r.packets != null ? ', ${r.packets} packets blocked' : '';
  return (
    armed: true,
    detail: '${r.description?.isNotEmpty == true ? r.description : 'Block tagged $tag'}$hits',
  );
}
