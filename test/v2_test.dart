import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:opnsense_cybervulcan/src/api/models.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/quick_tests.dart';
import 'package:opnsense_cybervulcan/src/core/schedule.dart';
import 'package:opnsense_cybervulcan/src/core/security_tests.dart';
import 'package:opnsense_cybervulcan/src/core/server_switcher.dart';
import 'package:opnsense_cybervulcan/src/core/settings_transfer.dart';
import 'package:opnsense_cybervulcan/src/core/storage.dart';
import 'package:opnsense_cybervulcan/src/net/router_link.dart';
import 'package:opnsense_cybervulcan/src/ui/settings_page.dart' show summariseReport;

import 'connection_test.dart' show FakeTunnel;
import 'fake_router.dart';

const _k1 = 'Q3liZXJ2dWxjYW4gdGVzdCBrZXkgbnVtYmVyIG9uZSE=';

String key(String c) => '${c * 43}=';

void main() {
  group('v2 config', () {
    test('new fields round-trip and default sensibly', () {
      const d = AppConfig();
      expect(d.baseUrl, 'https://10.10.10.254');
      expect(d.routerTunnelIp, '10.10.10.254');
      expect(d.externalTests, isTrue);
      expect(d.appLock, isFalse);
      expect(d.serverCityList, isEmpty);
      final c = d.copyWith(
        tailscaleEnabled: true,
        tailscaleAddress: '100.101.102.103',
        appLock: true,
        alertNewDevices: true,
        schedBypassEnabled: true,
        schedDays: 0x60,
        schedStart: '18:30',
        schedMinutes: 90,
        backupReminderDays: 14,
        serverSwitcherEnabled: true,
        serverCities: ' Los Angeles ,, Seattle ',
        autoBestNightly: true,
        externalTests: false,
      );
      final back = AppConfig.decode(c.encode());
      expect(back.tailscaleEnabled, isTrue);
      expect(back.tailscaleAddress, '100.101.102.103');
      expect(back.schedDays, 0x60);
      expect(back.schedStart, '18:30');
      expect(back.schedMinutes, 90);
      expect(back.backupReminderDays, 14);
      expect(back.serverCityList, ['Los Angeles', 'Seattle']);
      expect(back.autoBestNightly, isTrue);
      expect(back.externalTests, isFalse);
    });

    test('router address as a name: tunnel goes to the LAN IP; IP address: to itself', () {
      expect(const AppConfig(baseUrl: 'https://10.10.10.1').routerTunnelIp, '10.10.10.1');
      expect(const AppConfig(baseUrl: 'https://router.example', routerLanIp: 'nope').routerTunnelIp, isNull);
      expect(const AppConfig().routerAddressIsName, isFalse);
      expect(const AppConfig(baseUrl: 'https://router.example.com').routerAddressIsName, isTrue);
    });

    test('personal v2 preferences are not exported to other people', () {
      final c = const AppConfig().copyWith(appLock: true, serverSwitcherEnabled: true, schedBypassEnabled: true);
      final j = jsonDecode(exportSettings(c)) as Map;
      final settings = j['settings'] as Map;
      for (final k in ['appLock', 'serverSwitcherEnabled', 'schedBypassEnabled', 'autoBestNightly', 'alertNewDevices']) {
        expect(settings.containsKey(k), isFalse, reason: k);
      }
      expect(settings['tailscaleAddress'], isNotNull);
      expect(settings.containsKey('routerLanIp'), isTrue);
    });
  });

  group('schedule', () {
    final cfg = const AppConfig().copyWith(
        schedBypassEnabled: true, schedDays: weekdayBit(DateTime.friday), schedStart: '19:00', schedMinutes: 180);
    final friday = DateTime(2026, 11, 20); // a Friday

    test('fires inside the window once, with the rest of the window', () {
      final at = friday.add(const Duration(hours: 20, minutes: 15));
      expect(scheduledBypassDue(cfg, at, null), const Duration(minutes: 105));
      expect(scheduledBypassDue(cfg, at, dayKey(at)), isNull); // already fired today
    });

    test('not before, not after, not on other days, not when off', () {
      expect(scheduledBypassDue(cfg, friday.add(const Duration(hours: 18, minutes: 59)), null), isNull);
      expect(scheduledBypassDue(cfg, friday.add(const Duration(hours: 22)), null), isNull);
      expect(scheduledBypassDue(cfg, friday.add(const Duration(days: 1, hours: 20)), null), isNull);
      expect(scheduledBypassDue(cfg.copyWith(schedBypassEnabled: false), friday.add(const Duration(hours: 20)), null),
          isNull);
    });

    test('clock parsing and description', () {
      expect(parseClock('7:05'), 425);
      expect(parseClock('24:00'), isNull);
      expect(parseClock('19-00'), isNull);
      expect(describeSchedule(cfg), 'Fri 19:00 for 3 h');
      expect(describeSchedule(cfg.copyWith(schedDays: 0x1f, schedMinutes: 90)), 'Weekdays 19:00 for 1 h 30 min');
      expect(describeSchedule(cfg.copyWith(schedBypassEnabled: false)), 'Off');
    });

    test('backup reminder and nightly window', () {
      final c = const AppConfig().copyWith(backupReminderDays: 7);
      final now = DateTime(2026, 11, 20, 12);
      expect(backupReminderDue(c, now, now.subtract(const Duration(days: 8)), null), isTrue);
      expect(backupReminderDue(c, now, now.subtract(const Duration(days: 3)), null), isFalse);
      expect(backupReminderDue(c, now, now.subtract(const Duration(days: 8)), now.subtract(const Duration(hours: 2))),
          isFalse);
      final n = const AppConfig().copyWith(autoBestNightly: true, serverSwitcherEnabled: true);
      expect(nightlyBestDue(n, DateTime(2026, 11, 20, 3, 30), null), isTrue);
      expect(nightlyBestDue(n, DateTime(2026, 11, 20, 13), null), isFalse);
      expect(nightlyBestDue(n, DateTime(2026, 11, 20, 4), DateTime(2026, 11, 20, 3, 10)), isFalse);
    });

    test('new devices: first run only learns', () {
      expect(newMacs(['aa:bb'], {}), isEmpty);
      expect(newMacs(['AA:BB', 'cc:dd'], {'aa:bb'}), ['cc:dd']);
    });
  });

  group('server switcher', () {
    final logicals = {
      'LogicalServers': [
        {
          'Name': 'US-CA#1', 'City': 'San Jose', 'ExitCountry': 'US', 'Status': 1, 'Tier': 2, 'Features': 0, 'Load': 40,
          'Servers': [
            {'EntryIP': '203.0.113.1', 'X25519PublicKey': key('a'), 'Status': 1},
            {'EntryIP': '203.0.113.2', 'X25519PublicKey': key('b'), 'Status': 1},
          ],
        },
        {
          'Name': 'US-CA#2', 'City': 'Los Angeles', 'ExitCountry': 'US', 'Status': 1, 'Tier': 2, 'Features': 0, 'Load': 10,
          'Servers': [
            {'EntryIP': '203.0.113.3', 'X25519PublicKey': key('c'), 'Status': 1},
          ],
        },
        {'Name': 'CH-US#1', 'City': 'San Jose', 'ExitCountry': 'US', 'Status': 1, 'Tier': 2, 'Features': 1, 'Servers': []},
        {'Name': 'US-FREE#1', 'City': 'San Jose', 'ExitCountry': 'US', 'Status': 1, 'Tier': 0, 'Servers': []},
        {
          'Name': 'AU#1', 'City': 'Sydney', 'ExitCountry': 'AU', 'Status': 1, 'Tier': 2, 'Features': 0,
          'Servers': [
            {'EntryIP': '203.0.113.9', 'X25519PublicKey': key('d'), 'Status': 1},
          ],
        },
        {
          'Name': 'US-CA#3', 'City': 'San Jose', 'ExitCountry': 'US', 'Status': 0, 'Tier': 2,
          'Servers': [
            {'EntryIP': '203.0.113.4', 'X25519PublicKey': key('e'), 'Status': 1},
          ],
        },
      ],
    };

    test('parses Proton logicals: online, paid, no Secure Core, one server each', () {
      final us = parseProtonLogicals(logicals, country: 'US');
      expect(us.map((s) => s.name), ['US-CA#1', 'US-CA#2']);
      expect(us.first.entryIp, '203.0.113.1');
      expect(us.first.load, 40);
      expect(parseProtonLogicals(logicals).length, 3);
    });

    test('a .conf gives only the public parts (private key ignored)', () {
      const conf = '''
[Interface]
# Key for laptop
PrivateKey = SUPERSECRETSUPERSECRETSUPERSECRETSUPERSECRE=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
# US-CA#455
PublicKey = $_k1
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.7:51820
''';
      final s = serverFromWireGuardConf(conf)!;
      expect(s.name, 'US-CA#455');
      expect(s.entryIp, '198.51.100.7');
      expect(s.publicKey, _k1);
      expect(jsonEncode(s.toJson()), isNot(contains('SUPERSECRET')));
      expect(serverFromWireGuardConf('[Interface]\nPrivateKey = x'), isNull);
    });

    test('candidates spread over cities, least loaded first', () {
      final all = parseProtonLogicals(logicals, country: 'US');
      final c = pickCandidates(all, ['San Jose', 'Los Angeles'], max: 2);
      expect(c.map((s) => s.city).toSet(), {'San Jose', 'Los Angeles'});
      expect(pickCandidates(all, ['Seattle']), isEmpty);
    });

    test('plan keeps the current main unless clearly better', () {
      var ip = 10;
      ServerMeasurement m(String n, double d, {String city = 'San Jose'}) => ServerMeasurement(
          ProtonServer(name: n, entryIp: '203.0.113.${ip++}', publicKey: key('z'), city: city),
          delayMs: d,
          jitterMs: 2,
          lossPercent: 0);
      final current = m('cur', 200);
      var plan = planBest(current, [m('a', 195), m('b', 210, city: 'Los Angeles')])!;
      expect(plan.changeMain, isFalse);
      plan = planBest(current, [m('a', 150), m('bb', 170, city: 'Los Angeles'), m('ccc', 160)])!;
      expect(plan.changeMain, isTrue);
      expect(plan.newMain.server.name, 'a');
      expect(plan.newBackup!.server.city, 'Los Angeles'); // prefers another city
      expect(planBest(current, [const ServerMeasurement(ProtonServer(name: 'x', entryIp: '1.1.1.1', publicKey: ''), error: 'down')]),
          isNull);
    });

    test('find best on the fake router: tests on backup, then moves winner to main', () async {
      final r = FakeRouter()..delayByServer = {'149.36.48.154': 200, '203.0.113.1': 150, '203.0.113.3': 180};
      final sw = ServerSwitcher(
        client: r.client(),
        config: const AppConfig(),
        sleep: (_) async {},
      );
      final log = <String>[];
      final cands = pickCandidates(parseProtonLogicals(logicals, country: 'US'), ['San Jose', 'Los Angeles']);
      final plan = (await sw.findBest(cands, log.add))!;
      expect(plan.changeMain, isTrue);
      expect(plan.newMain.server.entryIp, '203.0.113.1');
      expect(r.wgClients[0]['serveraddress'], '203.0.113.1'); // main moved
      expect(r.wgClients[1]['serveraddress'], '203.0.113.3'); // backup = runner-up, other city
      expect(r.wgReconfigures, greaterThanOrEqualTo(3));
      // Only public fields were ever sent.
      final sent = r.requests.where((q) => q.url.path.contains('set_client')).map((q) => q.body).join();
      expect(sent, isNot(contains('PRIVATE')));
      expect(sent, isNot(contains('privkey')));
    });

    test('find best restores the original backup when nothing works', () async {
      final r = FakeRouter();
      r.gateways = [FakeRouter.gw('WG_MAIN_GW', 'none', '200 ms', '0.0 %'), FakeRouter.gw('WG_BACKUP_GW', 'down', '~', '100 %')];
      final sw = ServerSwitcher(client: r.client(), config: const AppConfig(), sleep: (_) async {});
      final plan = await sw.findBest(
          [ProtonServer(name: 'x', entryIp: '203.0.113.50', publicKey: key('x'))], (_) {});
      expect(plan, isNull);
      expect(r.wgClients[1]['serveraddress'], '149.34.251.130');
      expect(r.wgClients[0]['serveraddress'], '149.36.48.154');
    });

    test('switching a server keeps the peer linked to its tunnel and refreshes the monitor', () async {
      final r = FakeRouter();
      final sw = ServerSwitcher(client: r.client(), config: const AppConfig(), sleep: (_) async {});
      final (_, backup) = await sw.peers();
      await sw.apply(backup, ProtonServer(name: 'US-CA#742', entryIp: '149.102.228.1', publicKey: key('n')), main: false);
      expect(r.wgClients[1]['serveraddress'], '149.102.228.1');
      expect(r.wgClients[1]['%servers'], 'Proton_VPN_Failover'); // link kept (20 Nov bug)
      expect(r.routeReconfigures, 1);
      expect(r.monitorRestarts, ['WG_BACKUP_GW']);
      expect(sw.monitorWarning, isNull);
      final sent = r.requests.where((q) => q.url.path.contains('set_client')).map((q) => q.body).join();
      expect(sent, contains('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'));
      expect(sent, isNot(contains('PRIVATE')));
    });

    test('a lost instance link is restored from the instance name', () async {
      final r = FakeRouter();
      r.wgClients[1]['%servers'] = '';
      final sw = ServerSwitcher(client: r.client(), config: const AppConfig(), sleep: (_) async {});
      final peer = (await r.client().wgPeers())[1];
      await sw.apply(peer, ProtonServer(name: 'x', entryIp: '149.102.228.1', publicKey: key('n')), main: false);
      expect(r.wgClients[1]['%servers'], 'Proton_VPN_Failover');
    });

    test('a server that never answers is reported and the old one restored', () async {
      final r = FakeRouter()..deadServers = {'203.0.113.99'};
      final sw = ServerSwitcher(client: r.client(), config: const AppConfig(), sleep: (_) async {}, verifyAttempts: 3);
      final (_, backup) = await sw.peers();
      await expectLater(sw.apply(backup, ProtonServer(name: 'dead', entryIp: '203.0.113.99', publicKey: key('d')), main: false),
          throwsA(isA<ServerSwitchException>()));
      final r2 = FakeRouter()..deadServers = {'203.0.113.99'};
      final sw2 = ServerSwitcher(client: r2.client(), config: const AppConfig(), sleep: (_) async {}, verifyAttempts: 3);
      final log = <String>[];
      final plan = await sw2.findBest([ProtonServer(name: 'dead', entryIp: '203.0.113.99', publicKey: key('d'))], log.add);
      expect(plan, isNull);
      expect(r2.wgClients[1]['serveraddress'], '149.34.251.130');
      expect(log.join('\n'), contains('did not answer'));
    });

    test('missing monitor privileges give a warning, not a failure', () async {
      final r = FakeRouter()..forbidden.addAll(['/api/routes/routes/', '/api/core/service/']);
      final sw = ServerSwitcher(client: r.client(), config: const AppConfig(), sleep: (_) async {});
      final (_, backup) = await sw.peers();
      await sw.apply(backup, ProtonServer(name: 'x', entryIp: '149.102.228.1', publicKey: key('n')), main: false);
      expect(sw.monitorWarning, contains('Static Routes'));
    });

    test('endpoint matching', () {
      expect(endpointMatches('149.102.228.1:51820', '149.102.228.1', 51820), isTrue);
      expect(endpointMatches('149.102.228.1:51821', '149.102.228.1', 51820), isFalse);
      expect(endpointMatches('[2a02:6ea0::10]:51820', '2a02:6ea0::10', 51820), isTrue);
      expect(endpointMatches(null, '1.1.1.1', 1), isFalse);
    });

    test('peer model never keeps private data', () async {
      final peers = await FakeRouter().client().wgPeers();
      expect(peers.first.belongsTo('proton_vpn_main'), isTrue);
      expect(peers.first.publicKey, FakeRouter.keyA);
    });

    test('summarise ignores down samples', () {
      final s = const ProtonServer(name: 'x', entryIp: '1.1.1.1', publicKey: '');
      final g = GatewayStatus.fromJson(FakeRouter.gw('WG_BACKUP_GW', 'none', '100 ms', '0.0 %'));
      final down = GatewayStatus.fromJson(FakeRouter.gw('WG_BACKUP_GW', 'down', '~', '100 %'));
      expect(summarise(s, [g, down, g]).delayMs, 100);
      expect(summarise(s, [down]).ok, isFalse);
    });
  });

  group('security tests', () {
    const cfg = AppConfig();

    test('resolver classification', () {
      expect(classifyResolver(countryCode: 'AU', org: 'ExampleTel', expected: ExpectedPath.vpn, cfg: cfg), TestStatus.fail);
      expect(classifyResolver(countryCode: 'US', org: 'Datacamp', expected: ExpectedPath.vpn, cfg: cfg), TestStatus.pass);
      expect(classifyResolver(countryCode: 'AU', org: 'Quad9', expected: ExpectedPath.vpn, cfg: cfg), TestStatus.pass);
      expect(classifyResolver(countryCode: 'AU', org: 'Quad9', expected: ExpectedPath.direct, cfg: cfg), TestStatus.pass);
      expect(classifyResolver(countryCode: 'AU', org: 'ExampleTel', expected: ExpectedPath.direct, cfg: cfg), TestStatus.warn);
      expect(classifyResolver(countryCode: 'DE', org: 'x', expected: ExpectedPath.unknown, cfg: cfg), TestStatus.info);
    });

    SecurityTestResult res(String id, TestStatus s) =>
        SecurityTestResult(id: id, title: id, group: groupOfTest(id), status: s, summary: 's', details: const ['d']);

    test('score ignores skipped / info and weights important checks', () {
      final w = securityTestWeights;
      expect(securityScore([res('exit', TestStatus.pass), res('dns_leak', TestStatus.skip)], w), 100);
      expect(securityScore([res('exit', TestStatus.fail), res('latency', TestStatus.pass)], w), 25);
      expect(securityScore([res('ipv6', TestStatus.info)], w), isNull);
      expect(scoreGrade(100), 'A+');
      expect(scoreGrade(72), 'B');
    });

    test('history survives a round trip; report has no secrets', () {
      final run = TestRun(DateTime.utc(2026, 11, 20), 88, [res('exit', TestStatus.pass), res('kill_switch', TestStatus.warn)]);
      final back = decodeHistory(encodeHistory([run]));
      expect(back.single.score, 88);
      expect(back.single.results.map((r) => r.status), [TestStatus.pass, TestStatus.warn]);
      expect(back.single.results.last.group, TestGroup.router);
      final text = testReport(run, device: 'PC');
      expect(text, contains('[Router security]'));
      expect(text.toLowerCase(), isNot(contains('secret')));
      expect(decodeHistory('{bad'), isEmpty);
    });

    test('bash.ws id parsing and bufferbloat grades', () {
      expect(bashWsId(200, ' 1234567\n'), '1234567');
      expect(bashWsId(200, '{"id": "98765"}'), '98765');
      expect(bashWsId(200, '4a383d141b61b555'), '4a383d141b61b555'); // seen live, Nov 2026
      expect(() => bashWsId(200, '<html>Just a moment...</html>'), throwsA(isA<Exception>()));
      expect(() => bashWsId(503, ''), throwsA(isA<Exception>()));
      expect(bufferbloatGrade(3), 'A+');
      expect(bufferbloatGrade(45), 'B');
      expect(bufferbloatGrade(1400), 'F'); // the 5G line under load
      expect(median([5, 1, 3]), 3);
      expect(iqm([100, 300, 310, 320, 330, 5000]), closeTo(315, 0.1)); // outliers ignored
    });

    test('connection report folds to a summary line', () {
      const r = 'OK    Certificate valid\nOK    Gateway status\nOK    Bypass alias\n'
          'SKIP  WireGuard peers: not granted (optional)\nSKIP  Unbound: not granted (optional)';
      expect(summariseReport(r), '3 OK - 2 skipped (optional)');
      expect(summariseReport('Saved. Connected to the router.'), isNull);
    });

    test('outside checks are skipped when switched off', () async {
      final env = TestEnv(config: cfg.copyWith(externalTests: false), web: noHttp());
      final r = await runSecurityTest(allSecurityTests.firstWhere((t) => t.id == 'exit'), env);
      expect(r.status, TestStatus.skip);
    });

    test('router checks against the fake router', () async {
      final r = FakeRouter()
        ..dotRows = [
          {'enabled': '1', 'type': 'dot', 'server': '9.9.9.9', 'port': '853', 'verify': 'dns.quad9.net'},
        ];
      final env = TestEnv(config: cfg, web: noHttp(), client: r.client());
      final tunnels = await runSecurityTest(allSecurityTests.firstWhere((t) => t.id == 'tunnels'), env);
      expect(tunnels.status, TestStatus.pass);
      final dot = await runSecurityTest(allSecurityTests.firstWhere((t) => t.id == 'dot'), env);
      expect(dot.status, TestStatus.pass);
      r.forbidden.add('/api/unbound');
      final dot2 = await runSecurityTest(allSecurityTests.firstWhere((t) => t.id == 'dot'), env);
      expect(dot2.status, TestStatus.skip);
    });
  });

  group('Tailscale route', () {
    test('away: router reached at its tailnet address, certificate still checked', () async {
      final probed = <String>[];
      final link = RouterLink(
        tunnel: FakeTunnel(),
        probe: (t, route, timeout) async {
          probed.add(route.host);
          expect(t.tlsName, 'router.example.com');
          return ProbeResult(route.host == '100.101.102.103' ? ProbeKind.ok : ProbeKind.unreachable);
        },
      );
      final cfg = const AppConfig(baseUrl: 'https://router.example.com')
          .copyWith(tailscaleEnabled: true, tailscaleAddress: '100.101.102.103');
      final s = await link.check(cfg, const WireGuardSecrets());
      expect(s.state, LinkState.connected);
      expect(s.viaTailscale, isTrue);
      expect(s.remote, isTrue);
      expect(probed, ['router.example.com', '100.101.102.103']);
      expect(link.routeFor(RouterTarget.fromConfig(cfg)!).host, '100.101.102.103');
      expect(s.describe(cfg), 'Connected via Tailscale');
    });

    test('away, Tailscale not connected: clear message', () async {
      final link = RouterLink(
          tunnel: FakeTunnel(), probe: (t, route, timeout) async => const ProbeResult(ProbeKind.unreachable));
      final cfg = const AppConfig().copyWith(tailscaleEnabled: true, tailscaleAddress: '100.101.102.103');
      final s = await link.check(cfg, const WireGuardSecrets());
      expect(s.state, LinkState.notHome);
      expect(s.describe(cfg), contains('Tailscale'));
    });
  });
}

/// Any outside call fails - the tests here must not touch the internet.
http.Client noHttp() => MockClient((r) async => http.Response('offline in tests', 503));
