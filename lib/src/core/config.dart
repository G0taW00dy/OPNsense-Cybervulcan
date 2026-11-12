import 'dart:convert';

import 'network_map.dart';

/// Non-secret settings. Persisted as JSON in shared_preferences.
/// The API key/secret are *not* part of this object - see [SecretStore].
class AppConfig {
  const AppConfig({
    this.baseUrl = 'https://10.10.10.254',
    this.pinnedCertSha256,
    this.mainGateway = 'WG_MAIN_GW',
    this.backupGateway = 'WG_BACKUP_GW',
    this.mainLabel = 'San Jose',
    this.backupLabel = 'Los Angeles',
    this.pcModeAlias = 'PCMODE_CLEAR',
    this.bypassAlias = 'BYPASS_ALL',
    this.bypassNetwork = '10.10.40.0/24',
    this.bypassDuration = const Duration(hours: 2),
    this.pcIpOverride,
    this.killSwitchTag = 'NO_WAN_EGRESS',
    this.killSwitchRuleUuid,
    this.pollInterval = const Duration(seconds: 15),
    this.homeCountryCode = 'AU',
    this.vpnCountryCode = 'US',
    this.networks = defaultNetworks,
    this.notifyOnBypass = true,
    this.notifyOnFailover = true,
    this.useExpiryMarker = true,
    this.checkUpdates = true,
  });

  final String baseUrl;

  /// SHA-256 fingerprint of a trusted self-signed router certificate (TOFU).
  final String? pinnedCertSha256;
  final String mainGateway;
  final String backupGateway;
  final String mainLabel;
  final String backupLabel;
  final String pcModeAlias;
  final String bypassAlias;
  final String bypassNetwork;
  final Duration bypassDuration;

  /// Manually configured PC IP; null = auto-detect.
  final String? pcIpOverride;
  final String killSwitchTag;

  /// Optional: UUID of the kill switch rule, enables the low-privilege
  /// `rule_stats` check when `Firewall: Rules [new]` is not granted.
  final String? killSwitchRuleUuid;
  final Duration pollInterval;
  final String homeCountryCode;
  final String vpnCountryCode;
  final List<NamedNetwork> networks;
  final bool notifyOnBypass;
  final bool notifyOnFailover;

  /// Store the bypass expiry on the router as a reserved 240.0.0.0/4 marker
  /// entry in the bypass table, so every device enforces the same deadline.
  final bool useExpiryMarker;

  /// Check GitHub Releases automatically (start-up + every 12 h).
  final bool checkUpdates;

  Uri? get baseUri {
    final u = Uri.tryParse(baseUrl.trim());
    if (u == null || u.host.isEmpty || !(u.scheme == 'http' || u.scheme == 'https')) {
      return null;
    }
    return u;
  }

  AppConfig copyWith({
    String? baseUrl,
    String? pinnedCertSha256,
    bool clearPin = false,
    String? mainGateway,
    String? backupGateway,
    String? mainLabel,
    String? backupLabel,
    String? pcModeAlias,
    String? bypassAlias,
    String? bypassNetwork,
    Duration? bypassDuration,
    String? pcIpOverride,
    bool clearPcIpOverride = false,
    String? killSwitchTag,
    String? killSwitchRuleUuid,
    bool clearKillSwitchRuleUuid = false,
    Duration? pollInterval,
    String? homeCountryCode,
    String? vpnCountryCode,
    List<NamedNetwork>? networks,
    bool? notifyOnBypass,
    bool? notifyOnFailover,
    bool? useExpiryMarker,
    bool? checkUpdates,
  }) =>
      AppConfig(
        baseUrl: baseUrl ?? this.baseUrl,
        pinnedCertSha256: clearPin ? null : (pinnedCertSha256 ?? this.pinnedCertSha256),
        mainGateway: mainGateway ?? this.mainGateway,
        backupGateway: backupGateway ?? this.backupGateway,
        mainLabel: mainLabel ?? this.mainLabel,
        backupLabel: backupLabel ?? this.backupLabel,
        pcModeAlias: pcModeAlias ?? this.pcModeAlias,
        bypassAlias: bypassAlias ?? this.bypassAlias,
        bypassNetwork: bypassNetwork ?? this.bypassNetwork,
        bypassDuration: bypassDuration ?? this.bypassDuration,
        pcIpOverride: clearPcIpOverride ? null : (pcIpOverride ?? this.pcIpOverride),
        killSwitchTag: killSwitchTag ?? this.killSwitchTag,
        killSwitchRuleUuid: clearKillSwitchRuleUuid
            ? null
            : (killSwitchRuleUuid ?? this.killSwitchRuleUuid),
        pollInterval: pollInterval ?? this.pollInterval,
        homeCountryCode: homeCountryCode ?? this.homeCountryCode,
        vpnCountryCode: vpnCountryCode ?? this.vpnCountryCode,
        networks: networks ?? this.networks,
        notifyOnBypass: notifyOnBypass ?? this.notifyOnBypass,
        notifyOnFailover: notifyOnFailover ?? this.notifyOnFailover,
        useExpiryMarker: useExpiryMarker ?? this.useExpiryMarker,
        checkUpdates: checkUpdates ?? this.checkUpdates,
      );

  Map<String, dynamic> toJson() => {
        'baseUrl': baseUrl,
        'pinnedCertSha256': pinnedCertSha256,
        'mainGateway': mainGateway,
        'backupGateway': backupGateway,
        'mainLabel': mainLabel,
        'backupLabel': backupLabel,
        'pcModeAlias': pcModeAlias,
        'bypassAlias': bypassAlias,
        'bypassNetwork': bypassNetwork,
        'bypassMinutes': bypassDuration.inMinutes,
        'pcIpOverride': pcIpOverride,
        'killSwitchTag': killSwitchTag,
        'killSwitchRuleUuid': killSwitchRuleUuid,
        'pollSeconds': pollInterval.inSeconds,
        'homeCountryCode': homeCountryCode,
        'vpnCountryCode': vpnCountryCode,
        'networks': [
          for (final n in networks)
            {'name': n.name, 'cidr': n.cidr, 'description': n.description},
        ],
        'notifyOnBypass': notifyOnBypass,
        'notifyOnFailover': notifyOnFailover,
        'useExpiryMarker': useExpiryMarker,
        'checkUpdates': checkUpdates,
      };

  factory AppConfig.fromJson(Map<String, dynamic> j) {
    const d = AppConfig();
    String s(String k, String def) {
      final v = j[k];
      return v is String && v.trim().isNotEmpty ? v.trim() : def;
    }

    String? o(String k) {
      final v = j[k];
      return v is String && v.trim().isNotEmpty ? v.trim() : null;
    }

    int i(String k, int def, {int min = 1}) {
      final v = j[k];
      final n = v is num ? v.toInt() : int.tryParse('${v ?? ''}');
      return n == null || n < min ? def : n;
    }

    bool b(String k, bool def) => j[k] is bool ? j[k] as bool : def;

    final nets = <NamedNetwork>[];
    final rawNets = j['networks'];
    if (rawNets is List) {
      for (final n in rawNets) {
        if (n is Map && n['name'] is String && canonicalCidr('${n['cidr']}') != null) {
          nets.add(NamedNetwork(n['name'] as String, canonicalCidr('${n['cidr']}')!,
              description: '${n['description'] ?? ''}'));
        }
      }
    }

    return AppConfig(
      baseUrl: s('baseUrl', d.baseUrl),
      pinnedCertSha256: o('pinnedCertSha256'),
      mainGateway: s('mainGateway', d.mainGateway),
      backupGateway: s('backupGateway', d.backupGateway),
      mainLabel: s('mainLabel', d.mainLabel),
      backupLabel: s('backupLabel', d.backupLabel),
      pcModeAlias: s('pcModeAlias', d.pcModeAlias),
      bypassAlias: s('bypassAlias', d.bypassAlias),
      bypassNetwork: canonicalCidr(s('bypassNetwork', d.bypassNetwork)) ?? d.bypassNetwork,
      bypassDuration: Duration(minutes: i('bypassMinutes', d.bypassDuration.inMinutes)),
      pcIpOverride: o('pcIpOverride'),
      killSwitchTag: s('killSwitchTag', d.killSwitchTag),
      killSwitchRuleUuid: o('killSwitchRuleUuid'),
      pollInterval: Duration(seconds: i('pollSeconds', d.pollInterval.inSeconds, min: 5)),
      homeCountryCode: s('homeCountryCode', d.homeCountryCode).toUpperCase(),
      vpnCountryCode: s('vpnCountryCode', d.vpnCountryCode).toUpperCase(),
      networks: nets.isEmpty ? defaultNetworks : nets,
      notifyOnBypass: b('notifyOnBypass', d.notifyOnBypass),
      notifyOnFailover: b('notifyOnFailover', d.notifyOnFailover),
      useExpiryMarker: b('useExpiryMarker', d.useExpiryMarker),
      checkUpdates: b('checkUpdates', d.checkUpdates),
    );
  }

  String encode() => jsonEncode(toJson());

  static AppConfig decode(String? raw) {
    if (raw == null || raw.isEmpty) return const AppConfig();
    try {
      final j = jsonDecode(raw);
      return j is Map<String, dynamic> ? AppConfig.fromJson(j) : const AppConfig();
    } on FormatException {
      return const AppConfig();
    }
  }
}
