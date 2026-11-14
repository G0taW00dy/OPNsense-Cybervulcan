import 'dart:convert';

import 'network_map.dart';

/// Current settings format. 1 = v1.0.x (no `configVersion` key), 2 = v1.1.
const currentConfigVersion = 2;

/// Default certificate name the router's TLS certificate must carry.
const defaultCertName = 'router.cybervulcan.com';

/// Turns `10.10.10.254`, `10.10.10.254:8443` or `https://x/` into a base URL
/// (`https://` unless `http://` was typed). Returns the input when it cannot
/// be parsed, so the validator can complain about it.
String normaliseRouterAddress(String input) {
  var s = input.trim();
  if (s.isEmpty) return s;
  if (!s.contains('://')) s = 'https://$s';
  final u = Uri.tryParse(s);
  if (u == null || u.host.isEmpty) return input.trim();
  return Uri(scheme: u.scheme, host: u.host, port: u.hasPort ? u.port : null).toString();
}

/// Non-secret settings. Persisted as JSON in shared_preferences.
/// The API key/secret and the WireGuard private / pre-shared keys are *not*
/// part of this object - see [SecretStore].
class AppConfig {
  const AppConfig({
    this.baseUrl = 'https://10.10.10.254',
    this.certName = defaultCertName,
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
    this.vpnName = 'Proton',
    this.directLabel = 'Direct (NBN)',
    this.directNetworkName = 'CLEAR',
    this.remoteEnabled = false,
    this.wgEndpointHost = 'home.cybervulcan.com',
    this.wgEndpointPort = 51830,
    this.wgServerPublicKey,
    this.wgAddress = '',
    this.wgAllowedIps = '10.10.10.254/32',
    this.wgKeepalive = 25,
  });

  /// Router address: `https://10.10.10.254` (scheme + IP/host + optional port).
  /// The app always *connects* to this address.
  final String baseUrl;

  /// Name the router's TLS certificate must be valid for (e.g. a Let's
  /// Encrypt certificate for `router.cybervulcan.com` or `*.cybervulcan.com`).
  /// The certificate is checked against this name, not the IP. Empty = check
  /// it against the address itself (v1.0 behaviour).
  final String certName;

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

  /// Name of the VPN provider, used in texts ("back on Proton").
  final String vpnName;

  /// Big status line while the whole-house bypass is on.
  final String directLabel;

  /// Name (in [networks]) of the network that always goes direct.
  final String directNetworkName;

  // ---- Remote access (built-in WireGuard, app-only). Secrets live in
  // SecretStore; these are the public parts.

  /// Use the in-app WireGuard tunnel when the router is not reachable directly.
  final bool remoteEnabled;

  /// Public host name (or IP) of the home WireGuard endpoint.
  final String wgEndpointHost;
  final int wgEndpointPort;

  /// Public key of the router's road-warrior WireGuard instance (base64).
  final String? wgServerPublicKey;

  /// This device's tunnel address assigned by the router admin, e.g. 10.10.99.2/32.
  final String wgAddress;

  /// Comma-separated destinations routed into the tunnel (default: the router only).
  final String wgAllowedIps;

  /// Persistent keepalive in seconds (0 = off).
  final int wgKeepalive;

  Uri? get baseUri {
    final u = Uri.tryParse(normaliseRouterAddress(baseUrl));
    if (u == null || u.host.isEmpty || !(u.scheme == 'http' || u.scheme == 'https')) {
      return null;
    }
    return u;
  }

  /// True for a plain `http://` router address: the API key and everything
  /// else travel unencrypted and nothing proves it is your router.
  bool get isPlainHttp => baseUri?.scheme == 'http';

  /// Host (normally an IP) the app connects to.
  String? get routerHost => baseUri?.host;

  /// Port the app connects to (443 / 80 unless given).
  int? get routerPort {
    final u = baseUri;
    if (u == null) return null;
    return u.hasPort ? u.port : (u.scheme == 'http' ? 80 : 443);
  }

  /// The name the TLS certificate is checked against.
  String? get tlsName {
    final n = certName.trim();
    return n.isNotEmpty ? n : baseUri?.host;
  }

  /// The same settings with a plain `http://` router address moved to
  /// `https://` on the same host (default port 443) and, when no certificate
  /// name is set, the default one. Used to migrate v1.0.x `http://10.10.10.254`
  /// setups once the router serves HTTPS. Returns `this` when the address is
  /// not plain http.
  AppConfig switchedToHttps() {
    final u = baseUri;
    if (u == null || u.scheme != 'http') return this;
    return copyWith(
      baseUrl: Uri(scheme: 'https', host: u.host).toString(),
      certName: certName.trim().isEmpty ? defaultCertName : certName,
    );
  }

  List<String> get wgAllowedIpList => [
        for (final p in wgAllowedIps.split(RegExp(r'[,\s]+')))
          if (p.trim().isNotEmpty) p.trim(),
      ];

  AppConfig copyWith({
    String? baseUrl,
    String? certName,
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
    String? vpnName,
    String? directLabel,
    String? directNetworkName,
    bool? remoteEnabled,
    String? wgEndpointHost,
    int? wgEndpointPort,
    String? wgServerPublicKey,
    bool clearWgServerPublicKey = false,
    String? wgAddress,
    String? wgAllowedIps,
    int? wgKeepalive,
  }) =>
      AppConfig(
        baseUrl: baseUrl ?? this.baseUrl,
        certName: certName ?? this.certName,
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
        vpnName: vpnName ?? this.vpnName,
        directLabel: directLabel ?? this.directLabel,
        directNetworkName: directNetworkName ?? this.directNetworkName,
        remoteEnabled: remoteEnabled ?? this.remoteEnabled,
        wgEndpointHost: wgEndpointHost ?? this.wgEndpointHost,
        wgEndpointPort: wgEndpointPort ?? this.wgEndpointPort,
        wgServerPublicKey: clearWgServerPublicKey
            ? null
            : (wgServerPublicKey ?? this.wgServerPublicKey),
        wgAddress: wgAddress ?? this.wgAddress,
        wgAllowedIps: wgAllowedIps ?? this.wgAllowedIps,
        wgKeepalive: wgKeepalive ?? this.wgKeepalive,
      );

  Map<String, dynamic> toJson() => {
        'configVersion': currentConfigVersion,
        'baseUrl': baseUrl,
        'certName': certName,
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
        'vpnName': vpnName,
        'directLabel': directLabel,
        'directNetworkName': directNetworkName,
        'remoteEnabled': remoteEnabled,
        'wgEndpointHost': wgEndpointHost,
        'wgEndpointPort': wgEndpointPort,
        'wgServerPublicKey': wgServerPublicKey,
        'wgAddress': wgAddress,
        'wgAllowedIps': wgAllowedIps,
        'wgKeepalive': wgKeepalive,
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

    // v1.0.x settings have no version. They connected to the address and
    // checked the certificate against it (or a pin): keep exactly that, so an
    // existing http://10.10.10.254 or pinned https:// setup keeps working.
    final version = j['configVersion'] is num ? (j['configVersion'] as num).toInt() : 1;
    final String certName;
    if (j['certName'] is String) {
      certName = (j['certName'] as String).trim();
    } else {
      certName = version < 2 ? '' : d.certName;
    }
    final port = i('wgEndpointPort', d.wgEndpointPort);
    final keepalive = i('wgKeepalive', d.wgKeepalive, min: 0);

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
      baseUrl: normaliseRouterAddress(s('baseUrl', d.baseUrl)),
      certName: certName,
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
      vpnName: s('vpnName', d.vpnName),
      directLabel: s('directLabel', d.directLabel),
      directNetworkName: s('directNetworkName', d.directNetworkName),
      remoteEnabled: b('remoteEnabled', d.remoteEnabled),
      wgEndpointHost: s('wgEndpointHost', d.wgEndpointHost),
      wgEndpointPort: port > 65535 ? d.wgEndpointPort : port,
      wgServerPublicKey: o('wgServerPublicKey'),
      wgAddress: o('wgAddress') ?? '',
      wgAllowedIps: s('wgAllowedIps', d.wgAllowedIps),
      wgKeepalive: keepalive > 65535 ? d.wgKeepalive : keepalive,
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
