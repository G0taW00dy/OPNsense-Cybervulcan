import 'dart:convert';

import 'network_map.dart';

/// Current settings format. 1 = v1.0.x (no `configVersion` key), 2 = v1.1.
const currentConfigVersion = 2;

/// Example router name used in hints (never a real default).
const exampleRouterName = 'router.example.com';

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
    this.certName = '',
    this.pinnedCertSha256,
    this.mainGateway = 'WG_MAIN_GW',
    this.backupGateway = 'WG_BACKUP_GW',
    this.mainLabel = 'Main',
    this.backupLabel = 'Backup',
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
    this.directLabel = 'Direct',
    this.directNetworkName = 'CLEAR',
    this.remoteEnabled = false,
    this.wgEndpointHost = '',
    this.wgEndpointPort = 51830,
    this.wgServerPublicKey,
    this.wgAddress = '',
    this.wgAllowedIps = '10.10.10.254/32',
    this.wgKeepalive = 25,
    this.routerLanIp = '',
    this.tailscaleEnabled = false,
    this.tailscaleAddress = '',
    this.externalTests = true,
    this.appLock = false,
    this.alertNewDevices = false,
    this.schedBypassEnabled = false,
    this.schedDays = 0,
    this.schedStart = '19:00',
    this.schedMinutes = 180,
    this.backupReminderDays = 0,
    this.serverSwitcherEnabled = false,
    this.serverListOnRouter = false,
    this.namesFollowCity = true,
    this.mainWgInstance = 'Proton_VPN_Main',
    this.backupWgInstance = 'Proton_VPN_Failover',
    this.serverCities = '',
    this.autoBestNightly = false,
    this.lockAfterMinutes = 5,
    this.remoteTransport = 'wireguard',
    this.remoteMode = 'app',
    this.tailscaleBuiltIn = true,
    this.homeDevices = '',
    this.vpnProvider = '',
    this.mainKeyExpiry = '',
    this.backupKeyExpiry = '',
    this.shaperAutoTune = false,
    this.shaperMinDown = 20,
    this.shaperMaxDown = 80,
    this.shaperMinUp = 3,
    this.shaperMaxUp = 15,
    this.shaperClearAutoTune = false,
    this.shaperClearMinDown = 20,
    this.shaperClearMaxDown = 100,
    this.shaperClearMinUp = 3,
    this.shaperClearMaxUp = 20,
    this.wanGateway = '',
    this.protonReminder = false,
    this.routerSafetyNet = true,
  });

  /// Router address: `https://10.10.10.254` (scheme + IP/host + optional port).
  /// The app always *connects* to this address.
  final String baseUrl;

  /// Name the router's TLS certificate must be valid for (e.g. a Let's
  /// Encrypt certificate for `router.example.com` or `*.example.com`).
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

  // ---- v2.0

  /// Router's LAN IPv4, used as the tunnel target when the router address is a name.
  final String routerLanIp;

  /// Try the router over Tailscale when it is not reachable directly.
  final bool tailscaleEnabled;

  /// Router's Tailscale address (100.x.y.z or MagicDNS name). Empty = rely on a subnet route.
  final String tailscaleAddress;

  /// Allow the Tests page to use outside services (exit IP, DNS leak, IPv6).
  final bool externalTests;

  /// Ask for fingerprint / face / device PIN before bypass, CLEAR, server changes and saving settings.
  final bool appLock;

  /// Notify when a device the app has not seen before gets a DHCP lease.
  final bool alertNewDevices;

  /// Scheduled whole-house bypass.
  final bool schedBypassEnabled;

  /// Days for the scheduled bypass: bit 0 = Monday ... bit 6 = Sunday.
  final int schedDays;

  /// Local start time HH:MM of the scheduled bypass.
  final String schedStart;

  /// Length of the scheduled bypass in minutes.
  final int schedMinutes;

  /// Remind to save a router config backup every N days (0 = off).
  final int backupReminderDays;

  /// Show the Proton server switcher (needs the "VPN: WireGuard" privilege).
  final bool serverSwitcherEnabled;

  /// Keep the server list on the router (switched-off WireGuard peers named
  /// CVL_...), shared by every device with the owner's key.
  final bool serverListOnRouter;

  /// After a server switch, rename the tunnel to the new server's city
  /// (Status title, widget, tray, alerts). Off = keep your own names.
  final bool namesFollowCity;

  /// WireGuard instance behind the main gateway.
  final String mainWgInstance;

  /// WireGuard instance behind the backup gateway (used to test candidates).
  final String backupWgInstance;

  /// Comma-separated cities the server switcher may pick from.
  final String serverCities;

  /// Run "find best server" once a night (between 3 and 5 am) while the app runs.
  final bool autoBestNightly;

  /// App lock: lock again after this many minutes in the background.
  final int lockAfterMinutes;

  /// Remote access engine: `wireguard`, `tailscale` or `auto` (WireGuard first, Tailscale when WireGuard cannot get in).
  final String remoteTransport;

  /// What remote access carries: `app` (only the app talks to the router, no VPN slot), `home` (home devices such as the NAS, takes the VPN slot) or `everything` (all traffic exits via the house, takes the VPN slot).
  final String remoteMode;

  /// Use the Tailscale engine built into the app (true) or the separate Tailscale app on this device (false).
  final bool tailscaleBuiltIn;

  /// Home devices reachable in `home` mode: IPs or CIDRs, comma separated (e.g. the NAS).
  final String homeDevices;

  /// VPN provider profile for the server switcher: `proton`, `mullvad` or `other` (empty = guess from [vpnName]).
  final String vpnProvider;

  /// Date (yyyy-mm-dd) the main tunnel key/certificate expires at the provider; empty = unknown.
  final String mainKeyExpiry;

  /// Date (yyyy-mm-dd) the backup tunnel key/certificate expires at the provider; empty = unknown.
  final String backupKeyExpiry;

  /// Automatically tune the router shaper limits to the VPN tunnel (lower when latency rises, raise when clear).
  final bool shaperAutoTune;

  /// Auto-tune: lowest VPN download limit, Mbit/s.
  final int shaperMinDown;

  /// Auto-tune: highest VPN download limit, Mbit/s.
  final int shaperMaxDown;

  /// Auto-tune: lowest VPN upload limit, Mbit/s.
  final int shaperMinUp;

  /// Auto-tune: highest VPN upload limit, Mbit/s.
  final int shaperMaxUp;

  /// Also tune the CLEAR (direct internet) limits, against the WAN gateway's ping.
  final bool shaperClearAutoTune;
  final int shaperClearMinDown;
  final int shaperClearMaxDown;
  final int shaperClearMinUp;
  final int shaperClearMaxUp;

  /// Router gateway of the direct internet line, for CLEAR tuning. Empty = the
  /// first gateway with "WAN" in its name that is not a VPN gateway.
  final String wanGateway;

  /// Phone only: remind to turn the provider app off at home and on when away.
  final bool protonReminder;

  /// Back up the router config before the app changes it, and restore it if the change fails its check.
  final bool routerSafetyNet;

  /// Provider profile in effect: [vpnProvider], or a guess from [vpnName].
  String get providerId {
    final p = vpnProvider.trim().toLowerCase();
    if (const {'proton', 'mullvad', 'other'}.contains(p)) return p;
    final n = vpnName.toLowerCase();
    if (n.contains('proton')) return 'proton';
    if (n.contains('mullvad')) return 'mullvad';
    return 'other';
  }

  /// [remoteTransport], validated (`wireguard`, `tailscale` or `auto`).
  String get transport {
    final t = remoteTransport.trim().toLowerCase();
    return const {'wireguard', 'tailscale', 'auto'}.contains(t) ? t : 'wireguard';
  }

  /// [remoteMode], validated (`app`, `home` or `everything`).
  String get mode {
    final m = remoteMode.trim().toLowerCase();
    return const {'app', 'home', 'everything'}.contains(m) ? m : 'app';
  }

  /// [homeDevices] as canonical CIDRs (a bare IP becomes /32); invalid entries dropped.
  List<String> get homeDeviceCidrs => [
        for (final p in homeDevices.split(RegExp(r'[,\s]+')))
          if (p.isNotEmpty && canonicalCidr(p.contains('/') ? p : '$p/32') != null)
            canonicalCidr(p.contains('/') ? p : '$p/32')!,
      ];

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
  /// `https://` on the same host (default port 443), keeping any certificate
  /// name. Used to migrate v1.0.x `http://10.10.10.254`
  /// setups once the router serves HTTPS. Returns `this` when the address is
  /// not plain http.
  AppConfig switchedToHttps() {
    final u = baseUri;
    if (u == null || u.scheme != 'http') return this;
    return copyWith(
      baseUrl: Uri(scheme: 'https', host: u.host).toString(),
    );
  }

  /// IPv4 address remote access must reach: the router address when it is
  /// an IP, otherwise [routerLanIp] (router address given as a name such as
  /// https://router.example.com). Null when neither is a valid IPv4.
  String? get routerTunnelIp {
    final h = routerHost;
    if (h != null && ipv4ToInt(h) != null) return h;
    final lan = routerLanIp.trim();
    return ipv4ToInt(lan) != null ? lan : null;
  }

  /// True when the router address is a host name rather than an IP.
  bool get routerAddressIsName {
    final h = routerHost;
    return h != null && ipv4ToInt(h) == null && !h.contains(':');
  }

  /// Cities the server switcher may choose from (trimmed, non-empty).
  List<String> get serverCityList => [
        for (final c in serverCities.split(','))
          if (c.trim().isNotEmpty) c.trim(),
      ];

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
    String? routerLanIp,
    bool? tailscaleEnabled,
    String? tailscaleAddress,
    bool? externalTests,
    bool? appLock,
    bool? alertNewDevices,
    bool? schedBypassEnabled,
    int? schedDays,
    String? schedStart,
    int? schedMinutes,
    int? backupReminderDays,
    bool? serverSwitcherEnabled,
    bool? serverListOnRouter,
    bool? namesFollowCity,
    String? mainWgInstance,
    String? backupWgInstance,
    String? serverCities,
    bool? autoBestNightly,
    int? lockAfterMinutes,
    String? remoteTransport,
    String? remoteMode,
    bool? tailscaleBuiltIn,
    String? homeDevices,
    String? vpnProvider,
    String? mainKeyExpiry,
    String? backupKeyExpiry,
    bool? shaperAutoTune,
    int? shaperMinDown,
    int? shaperMaxDown,
    int? shaperMinUp,
    int? shaperMaxUp,
    bool? shaperClearAutoTune,
    int? shaperClearMinDown,
    int? shaperClearMaxDown,
    int? shaperClearMinUp,
    int? shaperClearMaxUp,
    String? wanGateway,
    bool? protonReminder,
    bool? routerSafetyNet,
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
        routerLanIp: routerLanIp ?? this.routerLanIp,
        tailscaleEnabled: tailscaleEnabled ?? this.tailscaleEnabled,
        tailscaleAddress: tailscaleAddress ?? this.tailscaleAddress,
        externalTests: externalTests ?? this.externalTests,
        appLock: appLock ?? this.appLock,
        alertNewDevices: alertNewDevices ?? this.alertNewDevices,
        schedBypassEnabled: schedBypassEnabled ?? this.schedBypassEnabled,
        schedDays: schedDays ?? this.schedDays,
        schedStart: schedStart ?? this.schedStart,
        schedMinutes: schedMinutes ?? this.schedMinutes,
        backupReminderDays: backupReminderDays ?? this.backupReminderDays,
        serverSwitcherEnabled: serverSwitcherEnabled ?? this.serverSwitcherEnabled,
        serverListOnRouter: serverListOnRouter ?? this.serverListOnRouter,
        namesFollowCity: namesFollowCity ?? this.namesFollowCity,
        mainWgInstance: mainWgInstance ?? this.mainWgInstance,
        backupWgInstance: backupWgInstance ?? this.backupWgInstance,
        serverCities: serverCities ?? this.serverCities,
        autoBestNightly: autoBestNightly ?? this.autoBestNightly,
        lockAfterMinutes: lockAfterMinutes ?? this.lockAfterMinutes,
        remoteTransport: remoteTransport ?? this.remoteTransport,
        remoteMode: remoteMode ?? this.remoteMode,
        tailscaleBuiltIn: tailscaleBuiltIn ?? this.tailscaleBuiltIn,
        homeDevices: homeDevices ?? this.homeDevices,
        vpnProvider: vpnProvider ?? this.vpnProvider,
        mainKeyExpiry: mainKeyExpiry ?? this.mainKeyExpiry,
        backupKeyExpiry: backupKeyExpiry ?? this.backupKeyExpiry,
        shaperAutoTune: shaperAutoTune ?? this.shaperAutoTune,
        shaperMinDown: shaperMinDown ?? this.shaperMinDown,
        shaperMaxDown: shaperMaxDown ?? this.shaperMaxDown,
        shaperMinUp: shaperMinUp ?? this.shaperMinUp,
        shaperMaxUp: shaperMaxUp ?? this.shaperMaxUp,
        shaperClearAutoTune: shaperClearAutoTune ?? this.shaperClearAutoTune,
        shaperClearMinDown: shaperClearMinDown ?? this.shaperClearMinDown,
        shaperClearMaxDown: shaperClearMaxDown ?? this.shaperClearMaxDown,
        shaperClearMinUp: shaperClearMinUp ?? this.shaperClearMinUp,
        shaperClearMaxUp: shaperClearMaxUp ?? this.shaperClearMaxUp,
        wanGateway: wanGateway ?? this.wanGateway,
        protonReminder: protonReminder ?? this.protonReminder,
        routerSafetyNet: routerSafetyNet ?? this.routerSafetyNet,
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
        'routerLanIp': routerLanIp,
        'tailscaleEnabled': tailscaleEnabled,
        'tailscaleAddress': tailscaleAddress,
        'externalTests': externalTests,
        'appLock': appLock,
        'alertNewDevices': alertNewDevices,
        'schedBypassEnabled': schedBypassEnabled,
        'schedDays': schedDays,
        'schedStart': schedStart,
        'schedMinutes': schedMinutes,
        'backupReminderDays': backupReminderDays,
        'serverSwitcherEnabled': serverSwitcherEnabled,
        'serverListOnRouter': serverListOnRouter,
        'namesFollowCity': namesFollowCity,
        'mainWgInstance': mainWgInstance,
        'backupWgInstance': backupWgInstance,
        'serverCities': serverCities,
        'autoBestNightly': autoBestNightly,
        'lockAfterMinutes': lockAfterMinutes,
        'remoteTransport': remoteTransport,
        'remoteMode': remoteMode,
        'tailscaleBuiltIn': tailscaleBuiltIn,
        'homeDevices': homeDevices,
        'vpnProvider': vpnProvider,
        'mainKeyExpiry': mainKeyExpiry,
        'backupKeyExpiry': backupKeyExpiry,
        'shaperAutoTune': shaperAutoTune,
        'shaperMinDown': shaperMinDown,
        'shaperMaxDown': shaperMaxDown,
        'shaperMinUp': shaperMinUp,
        'shaperMaxUp': shaperMaxUp,
        'shaperClearAutoTune': shaperClearAutoTune,
        'shaperClearMinDown': shaperClearMinDown,
        'shaperClearMaxDown': shaperClearMaxDown,
        'shaperClearMinUp': shaperClearMinUp,
        'shaperClearMaxUp': shaperClearMaxUp,
        'wanGateway': wanGateway,
        'protonReminder': protonReminder,
        'routerSafetyNet': routerSafetyNet,
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
      // v2.1 (tailscale agent): remoteEnabled is now the master switch; a v2.0
      // "Tailscale" choice (its own switch) turns it on.
      remoteEnabled: b('remoteEnabled', d.remoteEnabled) ||
          (!j.containsKey('remoteTransport') && b('tailscaleEnabled', false)),
      wgEndpointHost: s('wgEndpointHost', d.wgEndpointHost),
      wgEndpointPort: port > 65535 ? d.wgEndpointPort : port,
      wgServerPublicKey: o('wgServerPublicKey'),
      wgAddress: o('wgAddress') ?? '',
      wgAllowedIps: s('wgAllowedIps', d.wgAllowedIps),
      wgKeepalive: keepalive > 65535 ? d.wgKeepalive : keepalive,
      routerLanIp: s('routerLanIp', d.routerLanIp),
      tailscaleEnabled: b('tailscaleEnabled', d.tailscaleEnabled),
      tailscaleAddress: o('tailscaleAddress') ?? '',
      externalTests: b('externalTests', d.externalTests),
      appLock: b('appLock', d.appLock),
      alertNewDevices: b('alertNewDevices', d.alertNewDevices),
      schedBypassEnabled: b('schedBypassEnabled', d.schedBypassEnabled),
      schedDays: i('schedDays', d.schedDays, min: 0),
      schedStart: s('schedStart', d.schedStart),
      schedMinutes: i('schedMinutes', d.schedMinutes),
      backupReminderDays: i('backupReminderDays', d.backupReminderDays, min: 0),
      serverSwitcherEnabled: b('serverSwitcherEnabled', d.serverSwitcherEnabled),
      serverListOnRouter: b('serverListOnRouter', d.serverListOnRouter),
      namesFollowCity: b('namesFollowCity', d.namesFollowCity),
      mainWgInstance: s('mainWgInstance', d.mainWgInstance),
      backupWgInstance: s('backupWgInstance', d.backupWgInstance),
      serverCities: s('serverCities', d.serverCities),
      autoBestNightly: b('autoBestNightly', d.autoBestNightly),
      lockAfterMinutes: i('lockAfterMinutes', d.lockAfterMinutes),
      // v2.0 stored Tailscale as its own switch; carry that choice over.
      // (v2.0 with both WireGuard and Tailscale on: Auto. v2.0 Tailscale meant
      // the device's Tailscale app, so built-in stays off for those users.)
      remoteTransport: j.containsKey('remoteTransport')
          ? s('remoteTransport', d.remoteTransport)
          : (b('tailscaleEnabled', false)
              ? (b('remoteEnabled', false) ? 'auto' : 'tailscale')
              : d.remoteTransport),
      remoteMode: s('remoteMode', d.remoteMode),
      tailscaleBuiltIn: j.containsKey('tailscaleBuiltIn')
          ? b('tailscaleBuiltIn', d.tailscaleBuiltIn)
          : !(b('tailscaleEnabled', false) && !j.containsKey('remoteTransport')) && d.tailscaleBuiltIn,
      homeDevices: s('homeDevices', d.homeDevices),
      vpnProvider: s('vpnProvider', d.vpnProvider),
      mainKeyExpiry: s('mainKeyExpiry', d.mainKeyExpiry),
      backupKeyExpiry: s('backupKeyExpiry', d.backupKeyExpiry),
      shaperAutoTune: b('shaperAutoTune', d.shaperAutoTune),
      shaperMinDown: i('shaperMinDown', d.shaperMinDown, min: 0),
      shaperMaxDown: i('shaperMaxDown', d.shaperMaxDown, min: 0),
      shaperMinUp: i('shaperMinUp', d.shaperMinUp, min: 0),
      shaperMaxUp: i('shaperMaxUp', d.shaperMaxUp, min: 0),
      shaperClearAutoTune: b('shaperClearAutoTune', d.shaperClearAutoTune),
      shaperClearMinDown: i('shaperClearMinDown', d.shaperClearMinDown, min: 0),
      shaperClearMaxDown: i('shaperClearMaxDown', d.shaperClearMaxDown, min: 0),
      shaperClearMinUp: i('shaperClearMinUp', d.shaperClearMinUp, min: 0),
      shaperClearMaxUp: i('shaperClearMaxUp', d.shaperClearMaxUp, min: 0),
      wanGateway: s('wanGateway', d.wanGateway),
      protonReminder: b('protonReminder', d.protonReminder),
      routerSafetyNet: b('routerSafetyNet', d.routerSafetyNet),
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
