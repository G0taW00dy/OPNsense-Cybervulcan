import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:http/http.dart' as http;

import '../api/models.dart';
import '../api/opnsense_client.dart';
import '../api/shaper_models.dart';
import '../api/wireguard_models.dart' show DotServer;
import '../net/router_link.dart';
import 'config.dart';
import 'house_state.dart';
import 'line_speed.dart';
import 'network_map.dart' show NamedNetwork, networkNameFor;
import 'quick_tests.dart';

/// Pro security tests (v2.0 Tests page).
///
/// Two kinds of check:
/// * router side - asks the router itself (kill switch, tunnels, encrypted
///   DNS, certificate). No third parties involved.
/// * outside - only a server on the internet can see where this device's
///   traffic and DNS queries really come from (exit IP, DNS leak, IPv6).
///   HTTPS only, two independent providers where possible, and they can be
///   switched off in Settings. While on the VPN these services only ever see
///   the VPN exit, never the home IP.

enum TestStatus { pass, warn, fail, skip, info }

enum TestGroup {
  leaks('Leak protection'),
  router('Router security'),
  performance('Performance');

  const TestGroup(this.label);
  final String label;
}

class SecurityTestResult {
  const SecurityTestResult({
    required this.id,
    required this.title,
    required this.group,
    required this.status,
    required this.summary,
    this.details = const [],
    this.external = false,
  });

  final String id;
  final String title;
  final TestGroup group;
  final TestStatus status;
  final String summary;
  final List<String> details;

  /// Used an outside service.
  final bool external;

  Map<String, dynamic> toJson() => {'id': id, 'title': title, 'status': status.name, 'summary': summary};

  static SecurityTestResult? fromJson(Object? j, TestGroup Function(String id) groupOf) {
    if (j is! Map) return null;
    final st = TestStatus.values.where((s) => s.name == j['status']);
    if (st.isEmpty) return null;
    final id = '${j['id'] ?? ''}';
    return SecurityTestResult(
        id: id, title: '${j['title'] ?? id}', group: groupOf(id), status: st.first, summary: '${j['summary'] ?? ''}');
  }
}

/// What the tests can use. Everything is optional except config and web.
/// v2.2.8: bufferbloat advice when the app is not talking to the router
/// directly. On one of the house networks that can't reach the router (24 Nov:
/// the laptop on IoT Wi-Fi) it is NOT away from home - the lag is on that
/// Wi-Fi link or that network's own limit.
String notDirectlyHomeNote(String? deviceIp, List<NamedNetwork> networks) {
  final net = deviceIp == null ? null : networkNameFor(deviceIp, networks);
  if (net != null) {
    return 'This device is at home on the $net network: the lag is on that Wi-Fi link or that network\'s own '
        'speed limit, not the house line.';
  }
  return 'This device is away from home: the lag is on the network it uses now (e.g. mobile data), not the house '
      'line - the router\'s shaper can\'t help here.';
}

class TestEnv {
  TestEnv({
    required this.config,
    required this.web,
    this.client,
    this.snapshot,
    this.deviceIp,
    this.expected = ExpectedPath.unknown,
    this.target,
    this.route,
    this.atHome = false,
    this.vpnCountries = const {},
    this.otherConnections = const [],
  });

  /// Countries of the servers the tunnels use now (see [vpnCountriesFor]).
  final Set<String> vpnCountries;

  /// This device's other network connections that are not the house
  /// networks (e.g. a second Wi-Fi): the internet may go that way instead.
  final List<String> otherConnections;

  Set<String> get vpnSet => {config.vpnCountryCode.toUpperCase(), ...vpnCountries};

  final AppConfig config;

  /// HTTP client for the outside checks.
  final http.Client web;
  final OpnsenseClient? client;
  final HouseSnapshot? snapshot;
  final String? deviceIp;
  final ExpectedPath expected;
  final RouterTarget? target;
  final RouterRoute? route;

  /// The router was reached directly (not via a tunnel / Tailscale).
  final bool atHome;

  QuickTests get quick => QuickTests(web);
}

typedef TestRunner = Future<SecurityTestResult> Function(TestEnv env);

class SecurityTest {
  const SecurityTest(this.id, this.title, this.group, this.run, {this.external = false, this.weight = 1});

  final String id;
  final String title;
  final TestGroup group;
  final TestRunner run;
  final bool external;
  final int weight;
}

SecurityTestResult _r(SecurityTest t, TestStatus s, String summary, [List<String> details = const []]) =>
    SecurityTestResult(
        id: t.id, title: t.title, group: t.group, status: s, summary: summary, details: details, external: t.external);

String _expectWord(ExpectedPath p) => switch (p) {
      ExpectedPath.vpn => 'VPN',
      ExpectedPath.direct => 'direct (CLEAR / bypass)',
      ExpectedPath.unknown => 'unknown',
    };

/// Classifies one DNS resolver against what this device should be using.
TestStatus classifyResolver(
    {required String? countryCode,
    required String? org,
    required ExpectedPath expected,
    required AppConfig cfg,
    Set<String>? vpnCountries,
    bool routerDotToQuad9 = false}) {
  final cc = countryCode?.toUpperCase();
  final o = (org ?? '').toLowerCase();
  final quad9 = isQuad9Org(o);
  final vpn = vpnCountries ?? {cfg.vpnCountryCode.toUpperCase()};
  switch (expected) {
    case ExpectedPath.vpn:
      if (cc == null) return TestStatus.info;
      if (quad9) return TestStatus.pass;
      // Home-country resolver that isn't a VPN network: a leak, even when a
      // tunnel server is in the same country (review 22 Nov).
      if (cc == cfg.homeCountryCode.toUpperCase() && !looksLikeVpnNetwork(org)) return TestStatus.fail;
      if (vpn.contains(cc)) return TestStatus.pass;
      // A VPN provider's resolver elsewhere: this device's own VPN app.
      if (looksLikeVpnNetwork(org)) return TestStatus.warn;
      if (cc == cfg.homeCountryCode.toUpperCase()) return TestStatus.fail;
      return TestStatus.warn;
    case ExpectedPath.direct:
      if (quad9) return TestStatus.pass;
      // v2.2.5: Quad9's Australian nodes are hosted by local ISPs (Swoop,
      // which also owns a home ISP), so their network name can't tell them from
      // ISP DNS. When the router's encrypted DNS to Quad9 is confirmed, a
      // home-country resolver is that path.
      if (cc == cfg.homeCountryCode.toUpperCase()) {
        return routerDotToQuad9 ? TestStatus.pass : TestStatus.warn; // else ISP DNS, not the router's DoT
      }
      return TestStatus.info;
    case ExpectedPath.unknown:
      return TestStatus.info;
  }
}

/// True when every enabled upstream DNS server of the router is Quad9 over
/// TLS with name verification (v2.2.5).
bool routerUsesQuad9Dot(List<DotServer> servers) {
  const quad9 = {'9.9.9.9', '149.112.112.112', '9.9.9.10', '149.112.112.10', '9.9.9.11', '149.112.112.11',
    '2620:fe::fe', '2620:fe::9', '2620:fe::10', '2620:fe::11'};
  final on = servers.where((s) => s.enabled).toList();
  return on.isNotEmpty &&
      on.every((s) => s.isTls && quad9.contains(s.server.trim().toLowerCase()) && (s.verify ?? '').toLowerCase().contains('quad9'));
}

/// Quad9's resolvers show up under several network names depending on the
/// site (seen in Australia: "Streamline Network Solutions" and "Anycast
/// Holdings"); all of them are Quad9, i.e. the router's encrypted DNS.
bool isQuad9Org(String? org) {
  final o = (org ?? '').toLowerCase();
  return const ['quad9', 'woodynet', 'streamline network', 'anycast holdings', 'packet clearing house']
      .any(o.contains);
}

/// The test id from bash.ws/id: a plain number, possibly wrapped in JSON or
/// whitespace. Throws with what came back so the report says why.
String bashWsId(int status, String body) {
  if (status != 200) throw Exception('bash.ws answered HTTP $status');
  final t = body.trim();
  final m = RegExp(r'^"?([0-9A-Za-z]{4,40})"?$').firstMatch(t) ??
      RegExp(r'"id"\s*:\s*"?([0-9A-Za-z]{4,40})').firstMatch(t);
  if (m == null) {
    final peek = t.length > 40 ? '${t.substring(0, 40)}...' : t;
    throw Exception('unexpected answer "${peek.replaceAll(RegExp(r'\s+'), ' ')}"');
  }
  return m.group(1)!;
}

TestStatus worst(Iterable<TestStatus> s) {
  if (s.contains(TestStatus.fail)) return TestStatus.fail;
  if (s.contains(TestStatus.warn)) return TestStatus.warn;
  if (s.contains(TestStatus.pass)) return TestStatus.pass;
  if (s.contains(TestStatus.info)) return TestStatus.info;
  return TestStatus.skip;
}

/// 0-100 from pass / warn / fail (skips and info don't count).
int? securityScore(List<SecurityTestResult> results, Map<String, int> weights) {
  var total = 0.0;
  var got = 0.0;
  for (final r in results) {
    final w = (weights[r.id] ?? 1).toDouble();
    switch (r.status) {
      case TestStatus.pass:
        total += w;
        got += w;
      case TestStatus.warn:
        total += w;
        got += w / 2;
      case TestStatus.fail:
        total += w;
      case TestStatus.skip:
      case TestStatus.info:
        break;
    }
  }
  return total == 0 ? null : (got / total * 100).round();
}

String scoreGrade(int score) => score >= 95
    ? 'A+'
    : score >= 85
        ? 'A'
        : score >= 70
            ? 'B'
            : score >= 50
                ? 'C'
                : 'D';

// ------------------------------------------------------------------ tests

final List<SecurityTest> allSecurityTests = [
  SecurityTest('exit', 'Exit IP', TestGroup.leaks, _exitTest, external: true, weight: 3),
  SecurityTest('exit_consistency', 'Exit consistency', TestGroup.leaks, _exitConsistency, external: true),
  SecurityTest('dns_leak', 'DNS leak (extended)', TestGroup.leaks, _dnsLeak, external: true, weight: 3),
  SecurityTest('ipv6', 'IPv6 leak', TestGroup.leaks, _ipv6, external: true, weight: 2),
  SecurityTest('kill_switch', 'Kill switch', TestGroup.router, _killSwitch, weight: 3),
  SecurityTest('tunnels', 'VPN tunnels & failover', TestGroup.router, _tunnels, weight: 2),
  SecurityTest('dot', 'Encrypted DNS (DNS-over-TLS)', TestGroup.router, _dot, weight: 2),
  SecurityTest('cert', 'Router certificate', TestGroup.router, _cert, weight: 2),
  SecurityTest('latency', 'Tunnel latency & jitter', TestGroup.performance, _latency),
  SecurityTest('bufferbloat', 'Bufferbloat & speed', TestGroup.performance, _bufferbloat, external: true, weight: 2),
];

Map<String, int> get securityTestWeights => {for (final t in allSecurityTests) t.id: t.weight};

TestGroup groupOfTest(String id) =>
    allSecurityTests.firstWhere((t) => t.id == id, orElse: () => allSecurityTests.first).group;

SecurityTest _t(String id) => allSecurityTests.firstWhere((t) => t.id == id);

/// Runs one test, turning crashes into a FAIL/skip result and honouring the
/// "outside services" setting.
Future<SecurityTestResult> runSecurityTest(SecurityTest t, TestEnv env) async {
  if (t.external && !env.config.externalTests) {
    return _r(t, TestStatus.skip, 'Outside services are switched off (Settings > Tests & privacy).');
  }
  try {
    return await t.run(env).timeout(Duration(seconds: t.id == 'bufferbloat' ? 90 : 60));
  } on TimeoutException {
    return _r(t, TestStatus.warn, 'Timed out.');
  } on OpnsenseException catch (e) {
    if (e.kind == ApiErrorKind.forbidden) {
      return _r(t, TestStatus.skip, 'The API user lacks the privilege for this check.', [e.message]);
    }
    return _r(t, TestStatus.warn, 'Router check failed: ${e.message}');
  } on Object catch (e) {
    return _r(t, TestStatus.warn, 'Could not run: $e');
  }
}

Future<SecurityTestResult> _exitTest(TestEnv env) async {
  final t = _t('exit');
  final info = await env.quick.exitInfo();
  final r = evaluateExit(info, env.expected, env.config, vpnCountries: env.vpnSet);
  final st = switch (r.verdict) {
    Verdict.ok => TestStatus.pass,
    Verdict.mismatch => TestStatus.fail,
    Verdict.warn => TestStatus.warn,
    Verdict.inconclusive => TestStatus.info,
  };
  return _r(t, st, r.explanation, [
    'Exit ${info.ip} - ${[info.city, info.country].whereType<String>().join(', ')}${info.org != null ? ' (${info.org})' : ''}',
    'This device: ${env.deviceIp ?? 'not on a house network'} - expected ${_expectWord(env.expected)}',
    if (env.otherConnections.isNotEmpty)
      'This device also has ${env.otherConnections.join(', ')} - its internet may go that way instead of the router.',
    if (awayEverythingNote(env) case final n?) n,
  ]);
}

/// v2.2.1: away with "Everything via home" on, this app's own checks still go
/// out directly (the app stays outside its own VPN so its tunnel can't loop
/// into itself) - say so, and how to check the real path (23 Nov: Sam's
/// phone showed ExampleTel here while her browser exited in Singapore).
String? awayEverythingNote(TestEnv env) =>
    !env.atHome && env.config.remoteEnabled && env.config.mode == 'everything' && env.expected != ExpectedPath.vpn
        ? 'Everything via home is on, but this app\'s own checks always go direct. To see where other apps exit, '
            'open ipleak.net in a browser - it should show the house VPN\'s country.'
        : null;

Future<SecurityTestResult> _exitConsistency(TestEnv env) async {
  final t = _t('exit_consistency');
  final q = env.quick;
  final ips = <String>[];
  final errors = <String>[];
  for (var i = 0; i < 4; i++) {
    try {
      ips.add(await q.publicIp(alternate: i.isOdd));
    } on Object catch (e) {
      errors.add('$e');
    }
    if (i < 3) await Future<void>.delayed(const Duration(milliseconds: 600));
  }
  if (ips.length < 2) return _r(t, TestStatus.warn, 'Not enough answers to compare.', errors);
  final distinct = ips.toSet();
  if (distinct.length == 1) {
    return _r(t, TestStatus.pass, 'Same exit ${ips.first} from ${ips.length} lookups via two providers.');
  }
  if (!env.atHome && env.expected == ExpectedPath.unknown) {
    // v2.2.1: mobile networks hand out addresses from a pool (ExampleTel
    // 203.0.113.76 / .21, 23 Nov) - not a house tunnel flapping.
    return _r(t, TestStatus.info,
        'Exit changed between lookups (${distinct.join(', ')}) - normal on mobile and other networks away from home.');
  }
  return _r(t, TestStatus.warn,
      'Exit changed between lookups (${distinct.join(', ')}) - flapping between tunnels, or split routing.',
      ['A failover during the test also causes this - run it again.']);
}

/// bash.ws: unique names are resolved, then bash.ws lists every resolver
/// that asked for them. Akamai's whoami name is the second, DNS-only check.
Future<SecurityTestResult> _dnsLeak(TestEnv env) async {
  final t = _t('dns_leak');
  final q = env.quick;
  final seen = <String, ExitInfo?>{};
  final notes = <String>[];

  try {
    final idRes = await env.web.get(Uri.parse('https://bash.ws/id')).timeout(const Duration(seconds: 8));
    final id = bashWsId(idRes.statusCode, idRes.body);
    for (var i = 1; i <= 8; i++) {
      try {
        await InternetAddress.lookup('$i.$id.bash.ws').timeout(const Duration(seconds: 3));
      } on Object {
        // NXDOMAIN is expected - the lookup itself is what counts.
      }
    }
    final rows = await q.getAny(Uri.parse('https://bash.ws/dnsleak/test/$id?json'));
    if (rows is List) {
      for (final r in rows) {
        if (r is Map && r['type'] == 'dns' && r['ip'] != null) seen['${r['ip']}'] = null;
      }
    }
    notes.add('bash.ws: ${seen.length} resolver(s) seen from 8 unique lookups.');
  } on Object catch (e) {
    notes.add('bash.ws unavailable: $e');
  }

  try {
    final before = seen.length;
    for (var i = 0; i < 3; i++) {
      final a = await InternetAddress.lookup('whoami.akamai.net').timeout(const Duration(seconds: 4));
      for (final x in a) {
        if (x.type == InternetAddressType.IPv4) seen.putIfAbsent(x.address, () => null);
      }
    }
    notes.add('Akamai whoami: ${seen.length - before} more resolver(s).');
  } on Object catch (e) {
    notes.add('Akamai whoami unavailable: $e');
  }

  if (seen.isEmpty) return _r(t, TestStatus.warn, 'Neither leak-test service answered.', notes);

  // v2.2.5: in direct mode, check the router really sends DNS to Quad9 over
  // TLS (needs the Unbound settings privilege; without it the old rule stays).
  var dotQuad9 = false;
  final client = env.client;
  if (env.expected == ExpectedPath.direct && client != null) {
    try {
      dotQuad9 = routerUsesQuad9Dot(await client.dotServers());
      if (dotQuad9) notes.add('Router DNS-over-TLS to Quad9 confirmed.');
    } on Object {
      notes.add('Router DNS settings not readable with this API key - Quad9 nodes hosted by local ISPs may show as a warning.');
    }
  }

  final verdicts = <TestStatus>[];
  final lines = <String>[];
  for (final ip in seen.keys.take(8)) {
    ExitInfo? g;
    try {
      g = await q.geo(ip);
    } on Object {
      g = null;
    }
    final v = classifyResolver(
        countryCode: g?.countryCode,
        org: g?.org,
        expected: env.expected,
        cfg: env.config,
        vpnCountries: env.vpnSet,
        routerDotToQuad9: dotQuad9);
    verdicts.add(v);
    lines.add('${v.name.toUpperCase().padRight(4)} $ip - ${g?.country ?? '?'}${g?.org != null ? ' (${g!.org})' : ''}');
  }
  final st = worst(verdicts);
  final summary = switch (st) {
    TestStatus.fail => 'DNS LEAK: a resolver in ${env.config.homeCountryCode} answered while this device should be on the VPN.',
    TestStatus.warn => env.expected == ExpectedPath.direct
        ? 'Direct mode is using a resolver other than the router\'s encrypted DNS.'
        : verdicts.isNotEmpty && seen.isNotEmpty
            ? 'Some resolvers are not where the house tunnels are (${env.vpnSet.join(' / ')}) - if they belong to a '
                'VPN provider, this device\'s own VPN app is probably on.'
            : 'Some resolvers are in an unexpected place - check the details.',
    TestStatus.pass => 'No leak: all ${seen.length} resolver(s) match the expected path (${_expectWord(env.expected)}).',
    _ => 'Resolvers listed - this device is not on a house network the app can judge.',
  };
  return _r(t, st, summary, [...lines, ...notes]);
}

Future<SecurityTestResult> _ipv6(TestEnv env) async {
  final t = _t('ipv6');
  final String v6;
  try {
    v6 = await env.quick.publicIpv6();
  } on Object {
    return _r(t, TestStatus.pass, 'No IPv6 path out of this device - nothing can leak over IPv6.');
  }
  ExitInfo? g;
  try {
    g = await env.quick.geo(v6);
  } on Object {
    g = null;
  }
  final cc = g?.countryCode?.toUpperCase();
  final where = '$v6 - ${g?.country ?? 'unknown country'}${g?.org != null ? ' (${g!.org})' : ''}';
  if (env.expected == ExpectedPath.vpn) {
    if (cc == env.config.homeCountryCode.toUpperCase() && !looksLikeVpnNetwork(g?.org)) {
      return _r(t, TestStatus.fail, 'IPv6 LEAK: IPv6 traffic leaves via your ISP, around the VPN.', [where]);
    }
    if (env.vpnSet.contains(cc)) {
      return _r(t, TestStatus.pass, 'IPv6 goes through the VPN too.', [where]);
    }
    return _r(t, TestStatus.warn, 'IPv6 works and exits somewhere unexpected.', [where]);
  }
  return _r(t, TestStatus.info, 'IPv6 works on this device.', [where]);
}

Future<SecurityTestResult> _killSwitch(TestEnv env) async {
  final t = _t('kill_switch');
  final s = env.snapshot;
  if (s == null || !s.reachable) return _r(t, TestStatus.skip, 'Router not reachable.');
  final k = s.killSwitch;
  if (k.tripped) {
    return _r(t, TestStatus.warn, 'Tripped right now: both tunnels are down, so the VPN network is blocked (as designed).',
        [k.detail ?? '']);
  }
  return switch (k.armed) {
    true => _r(t, TestStatus.pass, 'Armed: VPN-tagged traffic can never leave via the WAN.', [k.detail ?? '']),
    false => _r(t, TestStatus.fail, 'NOT ARMED: if both tunnels drop, VPN devices could go out unprotected.',
        [k.detail ?? '']),
    null => _r(t, TestStatus.skip, 'Unknown - the API user can\'t read the firewall rules.', [k.detail ?? '']),
  };
}

Future<SecurityTestResult> _tunnels(TestEnv env) async {
  final t = _t('tunnels');
  final c = env.client;
  if (c == null) return _r(t, TestStatus.skip, 'Router not configured.');
  final gws = await c.gatewayStatus();
  final cfg = env.config;
  final main = gws.where((g) => g.name == cfg.mainGateway).firstOrNull;
  final backup = gws.where((g) => g.name == cfg.backupGateway).firstOrNull;
  final lines = <String>[
    '${cfg.mainLabel} (main): ${main == null ? 'not found' : '${main.health.name}, ${main.delayMs?.toStringAsFixed(0) ?? '?'} ms'}',
    '${cfg.backupLabel} (backup): ${backup == null ? 'not found' : '${backup.health.name}, ${backup.delayMs?.toStringAsFixed(0) ?? '?'} ms'}',
  ];
  try {
    final peers = (await c.wgShow()).where((p) => p.isPeer);
    for (final p in peers) {
      final age = p.handshakeAgeSeconds;
      lines.add('Peer ${p.name}: ${p.online ? 'online' : 'offline'}'
          '${age != null ? ', last handshake ${age}s ago' : ''}');
    }
  } on OpnsenseException {
    lines.add('(Handshake details need the "VPN: WireGuard" privilege.)');
  }
  final mainUp = main?.health.isUp ?? false;
  final backupUp = backup?.health.isUp ?? false;
  if (mainUp && backupUp) return _r(t, TestStatus.pass, 'Both tunnels up - failover is ready.', lines);
  if (mainUp || backupUp) {
    return _r(t, TestStatus.warn, 'Only one tunnel is up - no failover left if it drops.', lines);
  }
  return _r(t, TestStatus.fail, 'Both tunnels are down.', lines);
}

Future<SecurityTestResult> _dot(TestEnv env) async {
  final t = _t('dot');
  final c = env.client;
  if (c == null) return _r(t, TestStatus.skip, 'Router not configured.');
  final servers = await c.dotServers();
  final tls = servers.where((s) => s.enabled && s.isTls).toList();
  final lines = [
    for (final s in tls) '${s.server}:${s.port ?? 853}${s.verify != null ? ' (verifies ${s.verify})' : ' (NO name verification)'}',
  ];
  bool? dnssec;
  try {
    dnssec = await c.unboundDnssec();
  } on OpnsenseException {
    dnssec = null;
  }
  if (dnssec != null) {
    lines.add(dnssec
        ? 'DNSSEC validated on the router.'
        : 'DNSSEC not validated on the router (Quad9 validates upstream, so this is fine).');
  }
  if (tls.isEmpty) {
    return _r(t, TestStatus.warn, 'The router sends DNS upstream unencrypted (no DNS-over-TLS servers).', lines);
  }
  if (tls.any((s) => s.verify == null)) {
    return _r(t, TestStatus.warn, 'DNS-over-TLS is on, but some servers have no name to verify.', lines);
  }
  return _r(t, TestStatus.pass, 'Router DNS is encrypted to ${tls.length} DNS-over-TLS server(s).', lines);
}

Future<SecurityTestResult> _cert(TestEnv env) async {
  final t = _t('cert');
  final target = env.target;
  final route = env.route;
  if (target == null || route == null) return _r(t, TestStatus.skip, 'Router not configured.');
  if (!target.secure) {
    return _r(t, TestStatus.fail, 'Plain http:// - no certificate, the API key travels unencrypted.');
  }
  final Socket s;
  try {
    s = await openRouterSocket(target, route, const Duration(seconds: 6));
  } on WrongCertificateException catch (e) {
    return _r(t, TestStatus.fail, 'Certificate rejected - this may not be your router.', [e.detail]);
  }
  final cert = s is SecureSocket ? s.peerCertificate : null;
  s.destroy();
  if (cert == null) return _r(t, TestStatus.warn, 'Connected, but no certificate details were available.');
  final days = cert.endValidity.difference(DateTime.now()).inDays;
  final lines = [
    'Valid for ${target.tlsName}${target.pinned ? ' (pinned)' : ''}',
    'Issuer: ${cert.issuer}',
    'Expires: ${cert.endValidity.toLocal().toString().substring(0, 16)} ($days days)',
  ];
  if (days < 3) return _r(t, TestStatus.fail, 'Certificate expires in $days days - renewal is failing.', lines);
  if (days < 21) {
    return _r(t, TestStatus.warn, 'Certificate expires in $days days - check the ACME renewal.', lines);
  }
  return _r(t, TestStatus.pass, 'Valid for ${target.tlsName}, $days days left.', lines);
}

Future<SecurityTestResult> _latency(TestEnv env) async {
  final t = _t('latency');
  final c = env.client;
  if (c == null) return _r(t, TestStatus.skip, 'Router not configured.');
  final gws = await c.gatewayStatus();
  final cfg = env.config;
  final lines = <String>[];
  final statuses = <TestStatus>[];
  for (final (name, label) in [(cfg.mainGateway, cfg.mainLabel), (cfg.backupGateway, cfg.backupLabel)]) {
    final g = gws.where((x) => x.name == name).firstOrNull;
    if (g == null || g.delayMs == null) {
      lines.add('$label: no data');
      continue;
    }
    final d = g.delayMs!;
    final j = g.stddevMs ?? 0;
    final l = g.lossPercent ?? 0;
    final st = l >= 2 || d > 350 || j > 60
        ? TestStatus.fail
        : (l > 0 || d > 250 || j > 30)
            ? TestStatus.warn
            : TestStatus.pass;
    statuses.add(st);
    lines.add('$label: ${d.toStringAsFixed(0)} ms, jitter ${j.toStringAsFixed(1)} ms, loss ${l.toStringAsFixed(1)} %');
  }
  final st = worst(statuses);
  final both = [
    for (final n in [cfg.mainGateway, cfg.backupGateway]) gws.where((x) => x.name == n).firstOrNull,
  ];
  final congestion = st != TestStatus.pass && lineCongestion(both[0], both[1]);
  return _r(t, st, switch (st) {
    _ when congestion =>
      'Both tunnels are slow by about the same amount - that points to the home line being busy or congested, '
          'not the VPN servers. Changing server won\'t help much; the shaper and a quieter line will.',
    TestStatus.pass => 'Tunnels are steady.',
    TestStatus.warn => 'Some latency / jitter - fine for browsing, noticeable in games.',
    TestStatus.fail => 'Poor tunnel quality - try "Find best server".',
    _ => 'No tunnel measurements available.',
  }, [...lines, 'Measured by the router to each tunnel\'s monitor IP. Far-away servers add distance delay - that alone is not a fault.']);
}

/// Both tunnels degraded alike (delay within 15 % and both jittery or both
/// lossy): the shared home line is the likely cause, not either server.
bool lineCongestion(GatewayStatus? a, GatewayStatus? b) {
  if (a?.delayMs == null || b?.delayMs == null) return false;
  final da = a!.delayMs!, db = b!.delayMs!;
  final close = (da - db).abs() <= 0.15 * max(da, db);
  final jittery = (a.stddevMs ?? 0) > 30 && (b.stddevMs ?? 0) > 30;
  final lossy = (a.lossPercent ?? 0) > 0 && (b.lossPercent ?? 0) > 0;
  return close && (jittery || lossy);
}

/// Bufferbloat: round trip to an internet server (Cloudflare 1.1.1.1:443,
/// TCP handshake) idle, then while downloading and while uploading. This
/// crosses the real bottleneck (e.g. a 5G / NBN line), which a round trip to
/// the router does not. Grades on the worst added delay, like Waveform.
Future<SecurityTestResult> _bufferbloat(TestEnv env) async {
  final t = _t('bufferbloat');

  Future<double?> rtt() async {
    final sw = Stopwatch()..start();
    try {
      final s = await Socket.connect('1.1.1.1', 443, timeout: const Duration(seconds: 4));
      sw.stop();
      s.destroy();
      return sw.elapsedMicroseconds / 1000;
    } on Object {
      return null;
    }
  }

  // Warm up (Wi-Fi power save, radio wake-up), then measure idle.
  for (var i = 0; i < 3; i++) {
    await rtt();
  }
  final idle = <double>[];
  for (var i = 0; i < 8; i++) {
    final r = await rtt();
    if (r != null) idle.add(r);
    await Future<void>.delayed(const Duration(milliseconds: 200));
  }
  if (idle.length < 3) return _r(t, TestStatus.skip, 'Could not reach 1.1.1.1 to measure.');

  // Second opinion from the router: its gateway monitor pings through the
  // VPN tunnel, and the whole tunnel is ONE flow on the line - so it feels
  // the line's queue even when this device's own new connections are
  // served quickly by the router's shaper.
  final c = env.client;
  final gwName = env.expected == ExpectedPath.vpn ? env.config.mainGateway : null;
  Future<double?> routerDelay() async {
    if (c == null || gwName == null) return null;
    try {
      return (await c.gatewayStatus()).where((g) => g.name == gwName).firstOrNull?.delayMs;
    } on Object {
      return null;
    }
  }

  final routerIdle = await routerDelay();
  final routerLoaded = <double>[];

  Future<(List<double>, int, double)> loaded(Future<void> Function(void Function(int) count, bool Function() stop) load) async {
    final samples = <double>[];
    var bytes = 0;
    final sw = Stopwatch()..start();
    var done = false;
    bool stop() => done || sw.elapsed > const Duration(seconds: 12);
    final job = load((n) => bytes += n, stop);
    final sampler = () async {
      // Let the streams ramp up and the queue fill before sampling.
      await Future<void>.delayed(const Duration(milliseconds: 2500));
      while (!stop()) {
        final r = await rtt();
        if (r != null) samples.add(r);
        await Future<void>.delayed(const Duration(milliseconds: 200));
      }
    }();
    final routerSampler = () async {
      await Future<void>.delayed(const Duration(milliseconds: 5000));
      while (!stop()) {
        final d = await routerDelay();
        if (d != null) routerLoaded.add(d);
        await Future<void>.delayed(const Duration(seconds: 2));
      }
    }();
    try {
      await job.timeout(const Duration(seconds: 15));
    } on Object {
      // A partial transfer still loads the line and gives a speed figure.
    }
    done = true;
    await sampler;
    await routerSampler;
    sw.stop();
    return (samples, bytes, max(sw.elapsedMilliseconds / 1000, 0.5));
  }

  // Eight parallel streams each way (like Speedtest): fewer TCP connections
  // over a long VPN path leave the line part-empty, so no queue builds and
  // the lag people feel never shows (v2.0.3 used 3 and graded A while
  // Speedtest saw +1.4 s). 25 MB requests (Cloudflare refuses
  // very large single downloads), repeated until the time is up.
  final errors = <String>[];
  Future<void> streams(Future<void> Function() one) =>
      Future.wait([for (var i = 0; i < bufferbloatStreams; i++) one().catchError((Object e) => errors.add('$e'))]);
  final down = await loaded((count, stop) => streams(() async {
        while (!stop()) {
          final resp = await openSpeedDownload(env.web);
          await for (final chunk in resp.stream) {
            count(chunk.length);
            if (stop()) break;
          }
        }
      }));
  // 256 KB pieces: each POST only counts once it is finished, and 1 MB pieces
  // over a slow, far-away upload rarely finished in time (21 Nov: 0.6 Mbit/s
  // measured on a 10 Mbit/s limit).
  final piece = List<int>.filled(256 << 10, 0x61);
  final up = await loaded((count, stop) => streams(() async {
        while (!stop()) {
          final r = await env.web
              .post(Uri.parse('https://speed.cloudflare.com/__up'), body: piece)
              .timeout(const Duration(seconds: 20));
          if (r.statusCode >= 400) throw Exception('upload HTTP ${r.statusCode}');
          count(piece.length);
        }
      }));

  final base = median(idle);
  double addedFor(List<double> s) => s.isEmpty ? 0 : max(0.0, iqm(s) - base);
  final addDown = addedFor(down.$1);
  final addUp = addedFor(up.$1);
  // The router's monitor averages over a minute, so it can only under-read
  // a 12 s burst - taking the larger of the two never overstates the lag.
  final addRouter = routerIdle == null || routerLoaded.isEmpty ? 0.0 : max(0.0, routerLoaded.reduce(max) - routerIdle);
  final worstAdd = max(max(addDown, addUp), addRouter);
  String mbps((List<double>, int, double) x) => (x.$2 * 8 / x.$3 / 1e6).toStringAsFixed(1);
  final lines = [
    'Idle ${base.toStringAsFixed(0)} ms to 1.1.1.1',
    'Downloading: ${down.$1.isEmpty ? 'no samples' : '${iqm(down.$1).toStringAsFixed(0)} ms (+${addDown.toStringAsFixed(0)})'} - ~${mbps(down)} Mbit/s',
    'Uploading: ${up.$1.isEmpty ? 'no samples' : '${iqm(up.$1).toStringAsFixed(0)} ms (+${addUp.toStringAsFixed(0)})'} - ~${mbps(up)} Mbit/s',
    if (routerIdle != null && routerLoaded.isNotEmpty)
      'Router tunnel monitor: ${routerIdle.toStringAsFixed(0)} ms idle, up to ${routerLoaded.reduce(max).toStringAsFixed(0)} ms '
          'under load (+${addRouter.toStringAsFixed(0)})',
    'Path: ${_expectWord(env.expected)}. Added delay under load is what makes games lag when someone else downloads.',
    if (speedTestUsedFallback)
      'Cloudflare\'s speed test was busy for this VPN exit (HTTP 429) - downloads came from a public Vultr test file.',
  ];
  // No real load = no valid result (the old version graded an idle line A+).
  final downMbps = down.$2 * 8 / down.$3 / 1e6;
  final upMbps = up.$2 * 8 / up.$3 / 1e6;
  if (downMbps < 1 || upMbps < 0.2 || down.$1.length < 3) {
    return _r(t, TestStatus.warn, 'Could not load the line enough to measure (download ${downMbps.toStringAsFixed(1)}, '
        'upload ${upMbps.toStringAsFixed(1)} Mbit/s) - result not valid, run it again.', [
      ...lines,
      if (errors.isNotEmpty) 'Errors: ${errors.toSet().take(3).join('; ')}',
    ]);
  }
  final grade = bufferbloatGrade(worstAdd);
  // v2.1.2: if the router already has a shaper, say which limit is too high
  // instead of "set up a shaper".
  List<ShaperPipe>? pipes;
  if (c != null) {
    try {
      pipes = await c.shaperPipes();
    } on Object {
      pipes = null; // no privilege / no shaper: generic advice
    }
  }
  // v2.2.1: away from home the lag is on the network in use (e.g. mobile) -
  // the router's shaper can't help (23 Nov: Sam's phone on ExampleTel 4G).
  final fix = !env.atHome && env.expected == ExpectedPath.unknown
      ? notDirectlyHomeNote(env.deviceIp, env.config.networks)
      : shaperAdvice(pipes, env.expected, downMbps: downMbps, upMbps: upMbps, lagDown: addDown > addUp);
  final st = switch (grade) {
    'A+' || 'A' => TestStatus.pass,
    'B' || 'C' => TestStatus.warn,
    _ => TestStatus.fail,
  };
  return _r(t, st, switch (st) {
    TestStatus.pass => 'Grade $grade: +${worstAdd.toStringAsFixed(0)} ms under load - good for gaming.',
    TestStatus.warn => 'Grade $grade: +${worstAdd.toStringAsFixed(0)} ms under load - lag spikes when the line is busy. $fix',
    _ => 'Grade $grade: +${worstAdd.toStringAsFixed(0)} ms under load - heavy lag when the line is busy. $fix',
  }, lines);
}

/// What to do about bufferbloat, given the router's shaper pipes (null =
/// unknown). With a shaper in place the usual cause is a limit above what
/// the line delivers right now, so the queue still builds at the provider.
String shaperAdvice(List<ShaperPipe>? pipes, ExpectedPath path,
    {required double downMbps, required double upMbps, required bool lagDown}) {
  final active = pipes?.where((p) => p.enabled).toList() ?? const <ShaperPipe>[];
  if (pipes == null) return 'An FQ-CoDel shaper on the router fixes this (Settings > VPN tunnels > Shaper).';
  if (active.isEmpty) return 'Set up the FQ-CoDel shaper on the router (Firewall > Shaper).';
  if (path == ExpectedPath.unknown) {
    // 21 Nov: the PC on MGMT was told to lower the VPN/CLEAR limits, which
    // don't apply to it at all.
    return 'This device is not on the VPN or CLEAR network, and the shaper only covers those - move it to one of '
        'them (or add a shaper rule for its network).';
  }
  bool isVpn(ShaperPipe p) => p.description.toLowerCase().contains('vpn');
  bool isDown(ShaperPipe p) => p.description.toLowerCase().contains('down');
  final candidates = active.where((p) => switch (path) {
        ExpectedPath.vpn => isVpn(p),
        ExpectedPath.direct => !isVpn(p),
        ExpectedPath.unknown => true,
      });
  final measured = lagDown ? downMbps : upMbps;
  final inDir = candidates.where((p) => isDown(p) == lagDown).toList();
  // Only limits that are actually above what the line gave (21 Nov: a 10
  // Mbit/s limit was listed as "above" 17.2 Mbit/s).
  final dir = inDir.where((p) => p.mbit > measured).toList();
  if (inDir.isNotEmpty && dir.isEmpty) {
    return 'The ${lagDown ? 'download' : 'upload'} limit is already below what the line gave - the lag may come '
        'from another device or the line itself at that moment. Run the test again.';
  }
  final suggest = (measured * 0.85).floor().clamp(1, 100000);
  if (dir.isEmpty) {
    return 'The shaper is on, but no ${lagDown ? 'download' : 'upload'} limit covers this path.';
  }
  final names = dir.map((p) => '"${p.description}" (${p.mbit.round()} Mbit/s)').join(' or ');
  return 'The shaper is on, but the ${lagDown ? 'download' : 'upload'} limit $names is above what the line gave just now '
      '(~${measured.toStringAsFixed(1)} Mbit/s), so the queue still builds at the provider. Try about $suggest Mbit/s, '
      'or let auto-tune adjust the VPN limits.';
}

double median(List<double> v) {
  if (v.isEmpty) return double.nan;
  final s = [...v]..sort();
  return s[s.length ~/ 2];
}

/// Parallel transfer streams per direction for the bufferbloat test.
const bufferbloatStreams = 8;

/// Interquartile mean (Speedtest's loaded-latency figure): the average of
/// the middle half, so a few outliers don't decide the result.
double iqm(List<double> v) {
  if (v.isEmpty) return double.nan;
  if (v.length < 4) return median(v);
  final s = [...v]..sort();
  final mid = s.sublist(s.length ~/ 4, s.length - s.length ~/ 4);
  return mid.reduce((a, b) => a + b) / mid.length;
}

/// Waveform-style grade for the added latency under load (ms).
String bufferbloatGrade(double addedMs) => addedMs < 5
    ? 'A+'
    : addedMs < 30
        ? 'A'
        : addedMs < 60
            ? 'B'
            : addedMs < 200
                ? 'C'
                : addedMs < 400
                    ? 'D'
                    : 'F';

// ---------------------------------------------------------------- history

class TestRun {
  const TestRun(this.at, this.score, this.results);

  final DateTime at;
  final int? score;
  final List<SecurityTestResult> results;

  Map<String, dynamic> toJson() =>
      {'at': at.toUtc().toIso8601String(), 'score': score, 'results': [for (final r in results) r.toJson()]};

  static TestRun? fromJson(Object? j) {
    if (j is! Map) return null;
    final at = DateTime.tryParse('${j['at']}');
    if (at == null) return null;
    final rs = j['results'];
    return TestRun(at, j['score'] is num ? (j['score'] as num).toInt() : null, [
      if (rs is List)
        for (final r in rs) ?SecurityTestResult.fromJson(r, groupOfTest),
    ]);
  }
}

const testHistoryKey = 'security_test_history_v1';
const testHistoryMax = 20;

List<TestRun> decodeHistory(String? raw) {
  if (raw == null || raw.isEmpty) return [];
  try {
    final j = jsonDecode(raw);
    return [
      if (j is List)
        for (final r in j) ?TestRun.fromJson(r),
    ];
  } on FormatException {
    return [];
  }
}

String encodeHistory(List<TestRun> runs) =>
    jsonEncode([for (final r in runs.take(testHistoryMax)) r.toJson()]);

/// Plain-text report for copying into a chat or support request. Contains no
/// secrets (no keys, no full router config).
String testReport(TestRun run, {String? device}) {
  final b = StringBuffer()
    ..writeln('Cybervulcan security test - ${run.at.toLocal().toString().substring(0, 16)}')
    ..writeln('Device: ${device ?? '?'}  Score: ${run.score ?? '-'}${run.score != null ? ' (${scoreGrade(run.score!)})' : ''}')
    ..writeln();
  for (final g in TestGroup.values) {
    final rs = run.results.where((r) => r.group == g).toList();
    if (rs.isEmpty) continue;
    b.writeln('[${g.label}]');
    for (final r in rs) {
      b.writeln('${r.status.name.toUpperCase().padRight(5)} ${r.title}: ${r.summary}');
      for (final d in r.details) {
        if (d.isNotEmpty) b.writeln('        $d');
      }
    }
    b.writeln();
  }
  return b.toString().trimRight();
}
