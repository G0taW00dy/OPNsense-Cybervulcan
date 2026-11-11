import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:opnsense_cybervulcan/src/api/models.dart';
import 'package:opnsense_cybervulcan/src/api/opnsense_client.dart';

import 'fake_router.dart';

void main() {
  group('OpnsenseClient', () {
    test('parses gateway status with dpinger string metrics', () async {
      final router = FakeRouter()
        ..gateways = [
          FakeRouter.gw('WG_MAIN_GW', 'down', '0.0 ms', '100.0 %'),
          FakeRouter.gw('WG_BACKUP_GW', 'delay', '187.4 ms', '2.5 %'),
          {'name': 'WG_IDLE', 'address': '~', 'status': 'none', 'loss': '~', 'delay': '~', 'stddev': '~', 'monitor': '~'},
        ];
      final gws = await router.client().gatewayStatus();
      expect(gws, hasLength(3));
      expect(gws[0].health, GatewayHealth.down);
      expect(gws[0].lossPercent, 100.0);
      expect(gws[1].health, GatewayHealth.latency);
      expect(gws[1].health.isUp, isTrue);
      expect(gws[1].health.isDegraded, isTrue);
      expect(gws[1].delayMs, closeTo(187.4, 0.001));
      expect(gws[1].monitor, '8.8.4.4');
      expect(gws[2].delayMs, isNull);
      expect(gws[2].address, isNull);
    });

    test('sends HTTP Basic auth with key:secret', () async {
      final router = FakeRouter(apiKey: 'KEY', apiSecret: 'SECRET');
      await router.client().gatewayStatus();
      expect(router.requests.single.headers['Authorization'],
          'Basic ${base64Encode(utf8.encode('KEY:SECRET'))}');
      expect(router.requests.single.url.toString(), 'https://10.10.10.254/api/routes/gateway/status');
    });

    test('maps 401 and 403 to typed errors without leaking secrets', () async {
      final client = OpnsenseClient(
        baseUrl: Uri.parse('https://10.10.10.254'),
        apiKey: 'k',
        apiSecret: 'wrong-secret',
        httpClient: MockClient((_) async => http.Response('', 401)),
      );
      await expectLater(
        client.gatewayStatus(),
        throwsA(isA<OpnsenseException>()
            .having((e) => e.kind, 'kind', ApiErrorKind.unauthorized)
            .having((e) => e.toString(), 'toString', isNot(contains('wrong-secret')))),
      );

      final router = FakeRouter()..forbidden.add('/api/dnsmasq/');
      await expectLater(
        router.client().dnsmasqLeases(),
        throwsA(isA<OpnsenseException>().having((e) => e.kind, 'kind', ApiErrorKind.forbidden)),
      );
    });

    test('alias add/list/delete/flush round-trip with JSON bodies', () async {
      final router = FakeRouter();
      final c = router.client();
      await c.aliasAdd('PCMODE_CLEAR', '10.10.40.50');
      expect(await c.aliasList('PCMODE_CLEAR'), ['10.10.40.50']);
      final add = router.requests.firstWhere((r) => r.url.path.contains('/add/'));
      expect(add.method, 'POST');
      expect(add.headers['Content-Type'], startsWith('application/json'));
      expect(jsonDecode(add.body), {'address': '10.10.40.50'});

      await c.aliasDelete('PCMODE_CLEAR', '10.10.40.50');
      expect(await c.aliasList('PCMODE_CLEAR'), isEmpty);

      await c.aliasAdd('BYPASS_ALL', '10.10.40.0/24');
      await c.aliasFlush('BYPASS_ALL');
      expect(router.tables['BYPASS_ALL'], isEmpty);
    });

    test('alias list accepts legacy "items" shape and plain strings', () async {
      final c = OpnsenseClient(
        baseUrl: Uri.parse('http://router'),
        apiKey: 'k',
        apiSecret: 's',
        httpClient: MockClient((_) async => http.Response(
            jsonEncode({'items': [{'ip': '10.0.0.1'}, '10.0.0.2']}), 200)),
      );
      expect(await c.aliasList('X'), ['10.0.0.1', '10.0.0.2']);
    });

    test('API-level failure status throws', () async {
      final c = FakeRouter().client();
      await expectLater(c.aliasAdd('NOPE', '10.0.0.1'),
          throwsA(isA<OpnsenseException>().having((e) => e.message, 'msg', contains('nonexistent'))));
    });

    test('rejects unsafe alias names and addresses before sending', () async {
      final router = FakeRouter();
      final c = router.client();
      await expectLater(c.aliasList('../core/firmware'), throwsArgumentError);
      await expectLater(c.aliasAdd('BYPASS_ALL', '10.0.0.1; rm'), throwsArgumentError);
      expect(router.requests, isEmpty);
    });

    test('non-JSON answer (wrong URL / login page) is a badResponse', () async {
      final c = OpnsenseClient(
        baseUrl: Uri.parse('http://router'),
        apiKey: 'k',
        apiSecret: 's',
        httpClient: MockClient((_) async => http.Response('<html>login</html>', 200)),
      );
      await expectLater(c.gatewayStatus(),
          throwsA(isA<OpnsenseException>().having((e) => e.kind, 'kind', ApiErrorKind.badResponse)));
    });

    test('parses dnsmasq leases', () async {
      final router = FakeRouter()
        ..leases = [
          {
            'address': '10.10.40.50',
            'hwaddr': 'AA:BB:CC:00:11:22',
            'hostname': 'TIM-PC',
            'expire': 1893456000,
            'if_descr': 'VPN',
            'mac_info': 'ASUSTek',
            'lease_type': 'static',
          },
          {'address': '10.10.50.9', 'hwaddr': 'de:ad:be:ef:00:01', 'hostname': '*', 'expire': 0},
        ];
      final leases = await router.client().dnsmasqLeases();
      expect(leases.first.hostname, 'TIM-PC');
      expect(leases.first.mac, 'aa:bb:cc:00:11:22');
      expect(leases.first.isStatic, isTrue);
      expect(leases.first.expire, DateTime.fromMillisecondsSinceEpoch(1893456000 * 1000));
      expect(leases.last.hostname, isNull);
      expect(leases.last.expire, isNull);
    });

    test('searchRules posts the phrase with show_all=1', () async {
      final router = FakeRouter()
        ..rules = [
          {'uuid': 'u1', 'enabled': '1', 'action': 'block', 'tagged': 'NO_WAN_EGRESS', 'description': 'Kill switch'},
        ];
      final rules = await router.client().searchRules('NO_WAN_EGRESS');
      expect(rules.single.isBlocking, isTrue);
      expect(rules.single.enabled, isTrue);
      final req = router.requests.single;
      expect(req.url.queryParameters['show_all'], '1');
      expect(jsonDecode(req.body)['searchPhrase'], 'NO_WAN_EGRESS');
    });

    test('ruleStats returns uuid-keyed stats', () async {
      final router = FakeRouter()
        ..rules = [
          {'uuid': 'u1', 'enabled': '1', 'action': 'block', 'tagged': 'NO_WAN_EGRESS'},
        ];
      final stats = await router.client().ruleStats();
      expect(stats['u1']?['packets'], 42);
    });
  });

  test('parseMetric', () {
    expect(parseMetric('12.3 ms'), 12.3);
    expect(parseMetric('0.0 %'), 0.0);
    expect(parseMetric('~'), isNull);
    expect(parseMetric(null), isNull);
    expect(parseMetric(5), 5.0);
  });
}
