/// Data models for the subset of the OPNsense API used by Cybervulcan.
///
/// Field names follow opnsense/core (verified against the 26.x source):
/// * `GET /api/routes/gateway/status` -> `{items: [...], status: "ok"}`
///   (src/opnsense/scripts/routes/gateway_status.php)
/// * `GET /api/firewall/alias_util/list/{alias}` -> searchRecordset
///   `{rows: [{ip: ...}], total, rowCount, current}` (older releases: `items`)
/// * `GET /api/dnsmasq/leases/search` -> `{rows: [{address, hwaddr, hostname,
///   expire, if_descr, ...}], interfaces: {...}}`
/// * `GET /api/firewall/filter/search_rule` -> `{rows: [{uuid, enabled,
///   action, tagged, description, ...}]}`
library;

/// Health as reported by dpinger for a single gateway.
enum GatewayHealth {
  /// `none` - online, no alarms.
  online,

  /// `delay` - latency above the low threshold.
  latency,

  /// `loss` - packet loss above the low threshold.
  loss,

  /// `delay+loss`.
  latencyAndLoss,

  /// `down` - offline.
  down,

  /// `force_down` - administratively marked down.
  forcedDown,

  /// Anything else (e.g. `pending` right after boot).
  unknown;

  bool get isUp =>
      this == online || this == latency || this == loss || this == latencyAndLoss;

  bool get isDegraded =>
      this == latency || this == loss || this == latencyAndLoss;

  static GatewayHealth parse(String? raw) {
    switch ((raw ?? '').trim().toLowerCase()) {
      case 'none':
      case 'online':
        return GatewayHealth.online;
      case 'delay':
        return GatewayHealth.latency;
      case 'loss':
        return GatewayHealth.loss;
      case 'delay+loss':
        return GatewayHealth.latencyAndLoss;
      case 'down':
        return GatewayHealth.down;
      case 'force_down':
        return GatewayHealth.forcedDown;
      default:
        return GatewayHealth.unknown;
    }
  }
}

/// Parses dpinger strings such as `"12.3 ms"`, `"0.0 %"` or `"~"`.
double? parseMetric(Object? raw) {
  if (raw == null) return null;
  if (raw is num) return raw.toDouble();
  final match = RegExp(r'-?\d+(?:\.\d+)?').firstMatch(raw.toString());
  return match == null ? null : double.tryParse(match.group(0)!);
}

class GatewayStatus {
  const GatewayStatus({
    required this.name,
    required this.health,
    this.address,
    this.monitor,
    this.delayMs,
    this.stddevMs,
    this.lossPercent,
    this.statusText,
  });

  final String name;
  final GatewayHealth health;
  final String? address;
  final String? monitor;
  final double? delayMs;
  final double? stddevMs;
  final double? lossPercent;
  final String? statusText;

  factory GatewayStatus.fromJson(Map<String, dynamic> json) {
    String? str(String key) {
      final v = json[key];
      if (v == null) return null;
      final s = v.toString();
      return s == '~' || s.isEmpty ? null : s;
    }

    return GatewayStatus(
      name: (json['name'] ?? '').toString(),
      health: GatewayHealth.parse(json['status']?.toString()),
      address: str('address'),
      monitor: str('monitor'),
      delayMs: parseMetric(str('delay')),
      stddevMs: parseMetric(str('stddev')),
      lossPercent: parseMetric(str('loss')),
      statusText: str('status_translated'),
    );
  }

  @override
  String toString() => 'GatewayStatus($name, $health, ${delayMs}ms, $lossPercent%)';
}

class DhcpLease {
  const DhcpLease({
    required this.address,
    required this.mac,
    this.hostname,
    this.interfaceDescription,
    this.expire,
    this.vendor,
    this.isStatic = false,
  });

  final String address;
  final String mac;
  final String? hostname;
  final String? interfaceDescription;
  final DateTime? expire;
  final String? vendor;
  final bool isStatic;

  factory DhcpLease.fromJson(Map<String, dynamic> json) {
    DateTime? expire;
    final rawExpire = json['expire'];
    if (rawExpire is num && rawExpire > 0) {
      expire = DateTime.fromMillisecondsSinceEpoch(rawExpire.toInt() * 1000);
    } else if (rawExpire is String) {
      final n = int.tryParse(rawExpire);
      expire = n != null && n > 0
          ? DateTime.fromMillisecondsSinceEpoch(n * 1000)
          : DateTime.tryParse(rawExpire);
    }
    String? opt(String key) {
      final v = json[key]?.toString().trim();
      return v == null || v.isEmpty || v == '*' ? null : v;
    }

    return DhcpLease(
      address: (json['address'] ?? '').toString(),
      mac: (json['hwaddr'] ?? '').toString().toLowerCase(),
      hostname: opt('hostname'),
      interfaceDescription: opt('if_descr'),
      expire: expire,
      vendor: opt('mac_info'),
      isStatic: json['lease_type'] == 'static',
    );
  }
}

/// A firewall rule as returned by `search_rule` (only the fields we use).
class FirewallRule {
  const FirewallRule({
    required this.uuid,
    required this.enabled,
    required this.action,
    this.tagged,
    this.description,
    this.evaluations,
    this.packets,
    this.states,
  });

  final String uuid;
  final bool enabled;
  final String action;
  final String? tagged;
  final String? description;
  final int? evaluations;
  final int? packets;
  final int? states;

  bool get isBlocking {
    final a = action.toLowerCase();
    return a == 'block' || a == 'reject';
  }

  factory FirewallRule.fromJson(Map<String, dynamic> json) {
    int? asInt(Object? v) => v is num ? v.toInt() : int.tryParse('${v ?? ''}');
    final enabled = json['enabled'];
    return FirewallRule(
      uuid: (json['uuid'] ?? '').toString(),
      enabled: enabled == true || enabled == 1 || enabled == '1',
      action: (json['action'] ?? '').toString(),
      tagged: json['tagged']?.toString(),
      description: json['description']?.toString(),
      evaluations: asInt(json['evaluations']),
      packets: asInt(json['packets']),
      states: asInt(json['states']),
    );
  }
}
