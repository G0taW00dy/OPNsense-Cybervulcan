import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/core/bypass.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/network_map.dart';
import 'package:opnsense_cybervulcan/src/core/settings_transfer.dart';
import 'package:opnsense_cybervulcan/src/core/wg_conf.dart';
import 'package:opnsense_cybervulcan/src/core/wg_keys.dart';
import 'package:opnsense_cybervulcan/src/ui/settings_page.dart';

import 'fake_router.dart';

Uint8List hex(String h) =>
    Uint8List.fromList([for (var i = 0; i < h.length; i += 2) int.parse(h.substring(i, i + 2), radix: 16)]);
String toHex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('X25519 / WireGuard keys', () {
    test('RFC 7748 section 5.2 vector', () {
      expect(
        toHex(x25519(hex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'),
            hex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'))),
        'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
      );
    });

    test('RFC 7748 section 6.1 public key and shared secret', () {
      final alice = hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
      final bobPriv = hex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
      final alicePub = base64.decode(wireGuardPublicKey(base64.encode(alice)));
      expect(toHex(alicePub), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
      expect(toHex(x25519(bobPriv, alicePub)),
          '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');
    });

    test('matches an independent implementation (Python cryptography)', () {
      final priv = base64.encode(List<int>.generate(32, (i) => i));
      expect(wireGuardPublicKey(priv), 'j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8=');
    });

    test('generated keys are clamped, valid and random', () {
      final a = generateWireGuardPrivateKey();
      final b = generateWireGuardPrivateKey();
      expect(a, isNot(b));
      final raw = base64.decode(a);
      expect(raw[0] & 7, 0);
      expect(raw[31] & 0xC0, 0x40);
      expect(isWireGuardKey(wireGuardPublicKey(a)), isTrue);
      expect(generateWireGuardPrivateKey(Random(1)), generateWireGuardPrivateKey(Random(1)));
      expect(isWireGuardKey('short'), isFalse);
      expect(isWireGuardKey(null), isFalse);
    });
  });

  group('wg-quick import', () {
    final priv = generateWireGuardPrivateKey();
    final psk = generateWireGuardPrivateKey();
    final server = wireGuardPublicKey(generateWireGuardPrivateKey());
    final conf = '''
[Interface]
PrivateKey = $priv
Address = 10.10.99.3/32, fd00::3/128
DNS = 10.10.10.254

[Peer]
PublicKey = $server
PresharedKey = $psk
Endpoint = home.cybervulcan.com:51830
AllowedIPs = 10.10.10.254/32
PersistentKeepalive = 25
''';

    test('reads every field', () {
      final r = parseWgQuick(conf);
      expect(r.privateKey, priv);
      expect(r.presharedKey, psk);
      expect(r.address, '10.10.99.3/32');
      expect(r.serverPublicKey, server);
      expect(r.endpointHost, 'home.cybervulcan.com');
      expect(r.endpointPort, 51830);
      expect(r.allowedIps, '10.10.10.254/32');
      expect(r.keepalive, 25);
      expect(r.warnings.join(), contains('DNS'));
    });

    test('rejects text that is not a config; flags bad keys and full tunnels', () {
      expect(() => parseWgQuick('hello'), throwsFormatException);
      final r = parseWgQuick('[Interface]\nPrivateKey = nope\n[Peer]\nAllowedIPs = 0.0.0.0/0\n'
          'Endpoint = [2001:db8::1]:51830');
      expect(r.privateKey, isNull);
      expect(r.endpointHost, '2001:db8::1');
      expect(r.endpointPort, 51830);
      expect(r.warnings.join(' '), allOf(contains('PrivateKey'), contains('full tunnel')));
    });
  });

  group('config migration from 1.0.1', () {
    test('http://10.10.10.254 from 1.0.1 stays valid (with the http warning)', () {
      final old = jsonEncode({
        'baseUrl': 'http://10.10.10.254',
        'pinnedCertSha256': null,
        'mainGateway': 'WG_MAIN_GW',
        'bypassAlias': 'BYPASS_ALL',
        'bypassNetwork': '10.10.40.0/24',
        'bypassMinutes': 120,
        'pollSeconds': 15,
        'useExpiryMarker': false,
        'checkUpdates': true,
      });
      final c = AppConfig.decode(old);
      expect(c.baseUrl, 'http://10.10.10.254');
      expect(c.isPlainHttp, isTrue);
      expect(c.routerHost, '10.10.10.254');
      expect(c.routerPort, 80);
      expect(c.useExpiryMarker, isFalse);
      expect(c.remoteEnabled, isFalse);
      // Re-saved, it carries the new version and keeps its meaning.
      final again = AppConfig.decode(c.encode());
      expect(again.toJson(), c.toJson());
      expect(again.toJson()['configVersion'], currentConfigVersion);
    });

    test('pinned https from 1.0.1 keeps checking against the address + pin', () {
      final c = AppConfig.decode(jsonEncode({'baseUrl': 'https://10.10.10.254', 'pinnedCertSha256': 'AB:CD'}));
      expect(c.certName, '');
      expect(c.tlsName, '10.10.10.254');
      expect(c.pinnedCertSha256, 'AB:CD');
    });

    test('new installs default to the certificate name and new fields', () {
      const c = AppConfig();
      expect(c.certName, 'router.cybervulcan.com');
      expect(c.tlsName, 'router.cybervulcan.com');
      expect(c.wgEndpointHost, 'home.cybervulcan.com');
      expect(c.wgEndpointPort, 51830);
      expect(c.wgAllowedIpList, ['10.10.10.254/32']);
      expect(c.wgKeepalive, 25);
      expect(AppConfig.decode(null).certName, 'router.cybervulcan.com');
    });

    test('a bare IP is accepted as https', () {
      expect(normaliseRouterAddress('10.10.10.254'), 'https://10.10.10.254');
      expect(normaliseRouterAddress(' https://10.10.10.254/ '), 'https://10.10.10.254');
      expect(normaliseRouterAddress('http://10.10.10.254:8080'), 'http://10.10.10.254:8080');
    });
  });

  group('settings export / import', () {
    final full = const AppConfig().copyWith(
      certName: 'router.example.net',
      bypassAlias: 'MY_BYPASS',
      mainLabel: 'Sydney',
      pcIpOverride: '10.10.40.50',
      remoteEnabled: true,
      wgServerPublicKey: wireGuardPublicKey(generateWireGuardPrivateKey()),
      wgAddress: '10.10.99.3/32',
      networks: const [NamedNetwork('HOME', '192.168.1.0/24')],
    );

    test('export has the router setup but no secrets and no device-only values', () {
      final text = exportSettings(full);
      final lower = text.toLowerCase();
      for (final bad in ['secret"', 'apikey', 'privatekey', 'presharedkey', 'password', 'token']) {
        expect(lower, isNot(contains(bad)), reason: bad);
      }
      final settings = (jsonDecode(text) as Map)['settings'] as Map;
      expect(settings['bypassAlias'], 'MY_BYPASS');
      expect(settings['certName'], 'router.example.net');
      expect(settings['wgAddress'], '10.10.99.3/32');
      expect(settings.containsKey('pcIpOverride'), isFalse);
      expect(settings.containsKey('notifyOnBypass'), isFalse);
    });

    test('round trip onto a fresh device', () {
      final r = importSettings(exportSettings(full), const AppConfig());
      expect(r.config.bypassAlias, 'MY_BYPASS');
      expect(r.config.mainLabel, 'Sydney');
      expect(r.config.wgServerPublicKey, full.wgServerPublicKey);
      expect(r.config.networks.single.cidr, '192.168.1.0/24');
      expect(r.config.pcIpOverride, isNull);
      expect(r.warnings, isEmpty);
    });

    test('secret-looking keys in a hand-edited file are ignored', () {
      final text = jsonEncode({
        'kind': settingsExportKind,
        'settings': {
          'baseUrl': 'https://192.168.1.1',
          'apiSecret': 'leak',
          'wgPrivateKey': 'leak',
          'presharedKey': 'leak',
          'unknownThing': 1,
        },
      });
      final r = importSettings(text, const AppConfig());
      expect(r.config.baseUrl, 'https://192.168.1.1');
      expect(r.ignored, containsAll(['apiSecret', 'wgPrivateKey', 'presharedKey', 'unknownThing']));
      expect(r.config.encode(), isNot(contains('leak')));
      expect(r.warnings, hasLength(3));
    });

    test('garbage is rejected', () {
      expect(() => importSettings('not json', const AppConfig()), throwsFormatException);
      expect(() => importSettings('{"x":1}', const AppConfig()), throwsFormatException);
    });

    test('networks text editor round trip', () {
      final text = networksToText(defaultNetworks);
      expect(networksFromText(text)!.map((n) => n.cidr), defaultNetworks.map((n) => n.cidr));
      expect(networksFromText('VPN 10.10.40.0/24 Everything')!.single.description, 'Everything');
      expect(networksFromText('VPN nope'), isNull);
    });
  });

  group('bypass deadline on the router', () {
    late FakeRouter router;
    late MemoryStore store;
    var now = DateTime.utc(2026, 11, 12, 10);
    BypassManager m(AppConfig c) =>
        BypassManager(client: router.client(), config: c, store: store, clock: () => now);

    setUp(() {
      router = FakeRouter();
      store = MemoryStore();
      now = DateTime.utc(2026, 11, 12, 10);
    });

    test('bypass turned on with the setting off has no router deadline (12 Nov case)', () async {
      final off = const AppConfig().copyWith(useExpiryMarker: false);
      final s = await m(off).turnOn();
      expect(s.markers, isEmpty);
      expect(bypassLacksRouterDeadline(s), isTrue);
      final (action, after) = await m(off).enforce(await m(off).read());
      expect(action, EnforceAction.none);
      expect(bypassLacksRouterDeadline(after), isTrue);
    });

    test('"Add deadline" stores it even with the setting off', () async {
      final off = const AppConfig().copyWith(useExpiryMarker: false);
      await m(off).turnOn();
      final s = await m(off).addRouterDeadline();
      expect(s.markers, hasLength(1));
      expect(s.expiresAt, DateTime.utc(2026, 11, 12, 12));
      expect(bypassLacksRouterDeadline(s), isFalse);
    });

    test('with the setting on, a missing marker is restored automatically', () async {
      final off = const AppConfig().copyWith(useExpiryMarker: false);
      await m(off).turnOn();
      const on = AppConfig();
      final (action, s) = await m(on).enforce(await m(on).read());
      expect(action, EnforceAction.restoredRouterDeadline);
      expect(decodeExpiryMarker(s.markers.single), DateTime.utc(2026, 11, 12, 12));
      expect(router.tables['BYPASS_ALL']!.where((e) => decodeExpiryMarker(e) != null), hasLength(1));
    });

    test('no-time-limit bypass does not warn', () async {
      final off = const AppConfig().copyWith(useExpiryMarker: false);
      final s = await m(off).turnOn(duration: bypassNoLimit);
      expect(bypassLacksRouterDeadline(s), isFalse);
    });
  });
}
