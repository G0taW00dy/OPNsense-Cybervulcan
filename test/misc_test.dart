import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/api/tls.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/network_map.dart';
import 'package:opnsense_cybervulcan/src/core/quick_tests.dart';

void main() {
  group('network map', () {
    test('subnet membership and names', () {
      expect(networkNameFor('10.10.40.50', defaultNetworks), 'VPN');
      expect(networkNameFor('10.10.20.9', defaultNetworks), 'CLEAR');
      expect(networkNameFor('10.10.50.200', defaultNetworks), 'IOT');
      expect(networkNameFor('10.10.10.254', defaultNetworks), 'MGMT');
      expect(networkNameFor('192.168.1.2', defaultNetworks), isNull);
    });

    test('canonical CIDR and pf entry matching', () {
      expect(canonicalCidr('10.10.40.7/24'), '10.10.40.0/24');
      expect(canonicalCidr('nope'), isNull);
      expect(tableEntryMatches('10.10.40.0/24', '10.10.40.0/24'), isTrue);
      expect(tableEntryMatches('10.10.40.50', '10.10.40.50/32'), isTrue);
      expect(tableEntryMatches('10.10.40.0/24', '10.10.40.50'), isFalse);
    });
  });

  group('config', () {
    test('JSON round-trip keeps every field', () {
      final c = const AppConfig().copyWith(
        baseUrl: 'https://10.10.10.254',
        pinnedCertSha256: 'AB:CD',
        bypassDuration: const Duration(minutes: 45),
        pcIpOverride: '10.10.40.50',
        killSwitchRuleUuid: 'abc',
        useExpiryMarker: false,
      );
      final back = AppConfig.decode(c.encode());
      expect(back.toJson(), c.toJson());
    });

    test('garbage input falls back to defaults', () {
      expect(AppConfig.decode('{not json').baseUrl, const AppConfig().baseUrl);
      expect(AppConfig.decode('{"pollSeconds": 1}').pollInterval, const Duration(seconds: 15));
    });

    test('never serialises credentials', () {
      expect(const AppConfig().encode().toLowerCase(), isNot(contains('secret')));
    });
  });

  group('TLS fingerprint helpers', () {
    test('format and compare', () {
      expect(formatFingerprint([0, 15, 255]), '00:0F:FF');
      expect(fingerprintsMatch('00:0f:ff', '000FFF'), isTrue);
      expect(fingerprintsMatch('', ''), isFalse);
      expect(fingerprintsMatch('00:0F:FE', '00:0F:FF'), isFalse);
    });
  });

  group('quick test evaluation', () {
    const cfg = AppConfig();
    const au = ExitInfo(ip: '1.2.3.4', countryCode: 'AU');
    const us = ExitInfo(ip: '5.6.7.8', countryCode: 'US');

    test('expected path from device network and router state', () {
      expect(expectedPathFor(deviceIp: '10.10.40.50', cfg: cfg, bypassActive: false, pcClear: false),
          ExpectedPath.vpn);
      expect(expectedPathFor(deviceIp: '10.10.40.50', cfg: cfg, bypassActive: false, pcClear: true),
          ExpectedPath.direct);
      expect(expectedPathFor(deviceIp: '10.10.40.8', cfg: cfg, bypassActive: true, pcClear: null),
          ExpectedPath.direct);
      expect(expectedPathFor(deviceIp: '10.10.20.3', cfg: cfg, bypassActive: false, pcClear: null),
          ExpectedPath.direct);
      expect(expectedPathFor(deviceIp: '100.64.1.1', cfg: cfg, bypassActive: false, pcClear: null),
          ExpectedPath.unknown);
    });

    test('verdicts', () {
      expect(evaluateExit(us, ExpectedPath.vpn, cfg).verdict, Verdict.ok);
      expect(evaluateExit(au, ExpectedPath.vpn, cfg).verdict, Verdict.mismatch);
      expect(evaluateExit(au, ExpectedPath.direct, cfg).verdict, Verdict.ok);
      expect(evaluateExit(us, ExpectedPath.direct, cfg).verdict, Verdict.mismatch);
      expect(evaluateExit(const ExitInfo(ip: 'x'), ExpectedPath.vpn, cfg).verdict, Verdict.inconclusive);
    });
  });
}
