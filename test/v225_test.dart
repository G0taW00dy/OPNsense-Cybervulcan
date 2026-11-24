import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:opnsense_cybervulcan/src/api/wireguard_models.dart';
import 'package:opnsense_cybervulcan/src/core/controller.dart';
import 'package:opnsense_cybervulcan/src/core/security_tests.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/quick_tests.dart' show ExpectedPath;
import 'package:opnsense_cybervulcan/src/core/settings_transfer.dart';
import 'package:opnsense_cybervulcan/src/core/updater.dart';
import 'package:opnsense_cybervulcan/src/core/wg_conf.dart';
import 'package:opnsense_cybervulcan/src/core/storage.dart';
import 'package:opnsense_cybervulcan/src/net/router_link.dart';
import 'package:opnsense_cybervulcan/src/platform/android_widget.dart' show widgetShouldGoStale, widgetStaleAfter;
import 'package:opnsense_cybervulcan/src/platform/app_lock.dart';
import 'package:opnsense_cybervulcan/src/ui/help_page.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'connection_test.dart' show FakeTunnel;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('Polling (v2.2.5)', () {
    test('on-screen rate in the foreground, at least 5 min in the background', () async {
      SharedPreferences.setMockInitialValues({});
      final c = CybervulcanController(
        prefs: await PrefsStore.open(),
        secrets: SecretStore(),
        supportsPcMode: false,
        link: RouterLink(tunnel: FakeTunnel()),
      );
      c.backgroundGrace = Duration.zero;
      expect(c.currentPollInterval, const Duration(seconds: 15));

      c.setForeground(false);
      await Future<void>.delayed(const Duration(milliseconds: 5));
      expect(c.currentPollInterval, CybervulcanController.backgroundPollInterval);
      expect(CybervulcanController.backgroundPollInterval, const Duration(minutes: 5));

      c.setForeground(true);
      expect(c.currentPollInterval, const Duration(seconds: 15));

      // A user setting slower than 5 min is kept in the background too.
      c.config = c.config.copyWith(pollInterval: const Duration(minutes: 10));
      c.setForeground(false);
      await Future<void>.delayed(const Duration(milliseconds: 5));
      expect(c.currentPollInterval, const Duration(minutes: 10));
    });
  });

  group('Signed updates (v2.2.5)', () {
    const base = 'https://github.com/owner/repo/releases/download/v9.9.9';
    final payload = utf8.encode('installer bytes');
    final digest = sha256.convert(payload).toString();

    Map<String, dynamic> rel({bool signed = true}) => {
          'tag_name': 'v9.9.9',
          'html_url': 'https://github.com/owner/repo/releases/tag/v9.9.9',
          'draft': false,
          'prerelease': false,
          'assets': [
            {'name': 'Cybervulcan-Setup-9.9.9.exe', 'browser_download_url': '$base/Cybervulcan-Setup-9.9.9.exe', 'digest': 'sha256:$digest'},
            if (signed) {'name': 'Cybervulcan-Setup-9.9.9.exe.minisig', 'browser_download_url': '$base/Cybervulcan-Setup-9.9.9.exe.minisig'},
            // A signature hosted elsewhere is ignored.
            {'name': 'Cybervulcan-9.9.9.apk.minisig', 'browser_download_url': 'https://evil.example/x.minisig'},
          ],
        };

    MockClient client() => MockClient((req) async {
          if (req.url.path.endsWith('.minisig')) return http.Response('untrusted comment: sig\nSIG\n', 200);
          return http.Response.bytes(payload, 200);
        });

    test('the .minisig asset is found next to the installer', () {
      final r = ReleaseInfo.fromGitHub(rel(), UpdateTarget.windows)!;
      expect(r.asset!.signatureUrl.toString(), '$base/Cybervulcan-Setup-9.9.9.exe.minisig');
      expect(ReleaseInfo.fromGitHub(rel(), UpdateTarget.android)?.asset, isNull);
      expect(ReleaseInfo.fromGitHub(rel(signed: false), UpdateTarget.windows)!.asset!.signatureUrl, isNull);
    });

    test('unsigned releases and missing verifiers are refused', () async {
      final unsigned = ReleaseInfo.fromGitHub(rel(signed: false), UpdateTarget.windows)!;
      final s = UpdateService(target: UpdateTarget.windows, client: client(), verifier: (_, __) => null);
      await expectLater(s.downloadInstaller(unsigned), throwsA(isA<UpdateException>()));
      final noVerifier = UpdateService(target: UpdateTarget.windows, client: client());
      await expectLater(noVerifier.downloadInstaller(ReleaseInfo.fromGitHub(rel(), UpdateTarget.windows)!),
          throwsA(isA<UpdateException>()));
    });

    test('a bad signature deletes the download; a good one keeps it', () async {
      final r = ReleaseInfo.fromGitHub(rel(), UpdateTarget.windows)!;
      String? seenSig;
      final bad = UpdateService(target: UpdateTarget.windows, client: client(), verifier: (path, sig) {
        seenSig = sig;
        return 'signature does not match the file';
      });
      final dir = await Directory.systemTemp.createTemp('cv-upd-');
      await expectLater(bad.downloadInstaller(r, into: dir), throwsA(isA<UpdateException>()));
      expect(seenSig, contains('untrusted comment'));
      expect(dir.listSync(), isEmpty);

      final good = UpdateService(target: UpdateTarget.windows, client: client(), verifier: (_, __) => null);
      final f = await good.downloadInstaller(r, into: dir);
      expect(await f.readAsBytes(), payload);
      await dir.delete(recursive: true);
    });

    test('the release public key is compiled in', () {
      expect(updatePublicKey, startsWith('RWQ'));
      expect(updatePublicKey.length, 56);
    });
  });

  group('Plain http router (v2.2.5, audit H1)', () {
    test('direct plain-http connections are refused before connecting', () async {
      final t = RouterTarget.fromConfig(const AppConfig(baseUrl: 'http://10.10.10.254'))!;
      await expectLater(
        openRouterSocket(t, RouterRoute.direct(t.host, t.port), const Duration(seconds: 1)),
        throwsA(isA<SocketException>().having((e) => e.message, 'message', contains('blocked'))),
      );
    });
  });

  group('Settings import (v2.2.5, audit L1)', () {
    test('a certificate pin is never imported or exported', () {
      final pinned = AppConfig(baseUrl: 'https://router.example.net', pinnedCertSha256: 'aa' * 32);
      expect(exportSettings(pinned), isNot(contains('pinnedCertSha256')));
      final text = jsonEncode({
        'kind': settingsExportKind,
        'settings': {'baseUrl': 'https://router.example.net', 'pinnedCertSha256': 'bb' * 32},
      });
      final r = importSettings(text, const AppConfig());
      expect(r.config.pinnedCertSha256, isNull);
      expect(r.ignored, contains('pinnedCertSha256'));
    });

    test('changing the router address or certificate name is called out', () {
      const current = AppConfig(baseUrl: 'https://router.example.net', certName: 'router.example.net');
      final text = jsonEncode({
        'kind': settingsExportKind,
        'settings': {'baseUrl': 'https://203.0.113.9', 'certName': 'other.example.org'},
      });
      final r = importSettings(text, current);
      expect(r.warnings.where((w) => w.contains('router address changes')), hasLength(1));
      expect(r.warnings.where((w) => w.contains('certificate name changes')), hasLength(1));
      // Same values: no warning.
      expect(importSettings(exportSettings(current), current).warnings, isEmpty);
    });
  });

  group('App PIN (v2.2.5, audit L2)', () {
    test('PBKDF2-HMAC-SHA256 matches known test vectors', () {
      String hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
      expect(hex(pbkdf2Sha256(utf8.encode('password'), utf8.encode('salt'), 1, 32)),
          '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');
      expect(hex(pbkdf2Sha256(utf8.encode('password'), utf8.encode('salt'), 2, 32)),
          'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43');
      expect(
          hex(pbkdf2Sha256(utf8.encode('passwordPASSWORDpassword'),
              utf8.encode('saltSALTsaltSALTsaltSALTsaltSALTsalt'), 4096, 40)),
          '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9');
    });

    test('new PINs use PBKDF2; old salted-SHA-256 PINs still unlock', () {
      final h = hashPin('2468');
      expect(h, startsWith('p2-$pinIterations-'));
      expect(isLegacyPinHash(h), isFalse);
      expect(verifyPin('2468', h), isTrue);
      expect(verifyPin('2469', h), isFalse);
      const salt = 'c2FsdHNhbHQ=';
      final legacy = '$salt:${sha256.convert(utf8.encode('$salt:1357'))}';
      expect(isLegacyPinHash(legacy), isTrue);
      expect(verifyPin('1357', legacy), isTrue);
      expect(verifyPin('1358', legacy), isFalse);
      expect(verifyPin('1357', 'p2-0-x:00'), isFalse);
    });

    test('lock-out after 5 wrong PINs, doubling, at most an hour', () {
      final now = DateTime(2026, 11, 24, 9);
      expect(pinLockUntil(4, now), isNull);
      expect(pinLockUntil(5, now), now.add(const Duration(minutes: 1)));
      expect(pinLockUntil(6, now), now.add(const Duration(minutes: 2)));
      expect(pinLockUntil(30, now), now.add(const Duration(minutes: 60)));
    });
  });

  group('WireGuard config import limits (v2.2.5, audit L5)', () {
    test('oversized text is refused; bad endpoint parts are dropped', () {
      expect(() => parseWgQuick('[Interface]\n${'#' * (wgQuickMaxLength + 1)}'), throwsFormatException);
      final r = parseWgQuick('[Interface]\nAddress = 10.10.99.9/32\n[Peer]\nEndpoint = home.example.com:70000\n'
          'PersistentKeepalive = 99999\n');
      expect(r.endpointHost, 'home.example.com');
      expect(r.endpointPort, isNull);
      expect(r.keepalive, isNull);
      final bad = parseWgQuick('[Interface]\nAddress = 10.10.99.9/32\n[Peer]\nEndpoint = a b;c:51820\n');
      expect(bad.endpointHost, isNull);
      expect(bad.warnings.join(), contains('not valid'));
      final ok = parseWgQuick('[Interface]\nAddress = 10.10.99.9/32\n[Peer]\nEndpoint = 203.0.113.7:51830\n');
      expect(ok.endpointHost, '203.0.113.7');
      expect(ok.endpointPort, 51830);
    });
  });

  group('Router install line (v2.2.5, audit L7)', () {
    test('uses the release tag and checks the bundled SHA-256', () async {
      final sha = await routerInstallSha256();
      expect(sha, matches(RegExp(r'^[0-9a-f]{64}$')));
      expect(sha, sha256.convert(lfOnly(File('router/install.sh').readAsBytesSync())).toString());
      final cmd = routerInstallCommand('owner/repo', '9.9.9', sha);
      expect(cmd, contains('/owner/repo/v9.9.9/router/install.sh'));
      expect(cmd, isNot(contains('/main/')));
      // v2.2.8: csh-safe (the router's root shell) - no \$( ).
      expect(cmd, contains('sha256 -q -c $sha /tmp/cvinstall.sh && sh /tmp/cvinstall.sh'));
      expect(cmd, isNot(contains(r'$(')));
    });
  });

  group('Router install line hash (v2.2.8)', () {
    test('CRLF and LF copies of the script give the same hash', () {
      final lf = 'a\nb\n'.codeUnits;
      final crlf = 'a\r\nb\r\n'.codeUnits;
      expect(lfOnly(crlf), lf);
      expect(lfOnly(lf), lf);
      expect(lfOnly('x\ry'.codeUnits), 'x\ry'.codeUnits);
    });
  });

  group('DNS leak test in direct mode (v2.2.5)', () {
    const cfg = AppConfig(homeCountryCode: 'AU');
    test('a home-country resolver passes only when router DoT to Quad9 is confirmed', () {
      expect(classifyResolver(countryCode: 'AU', org: 'Swoop Telecommunications', expected: ExpectedPath.direct, cfg: cfg),
          TestStatus.warn);
      expect(
          classifyResolver(
              countryCode: 'AU', org: 'Swoop Telecommunications', expected: ExpectedPath.direct, cfg: cfg, routerDotToQuad9: true),
          TestStatus.pass);
      // Never relaxes the VPN case.
      expect(
          classifyResolver(countryCode: 'AU', org: 'ExampleTel', expected: ExpectedPath.vpn, cfg: cfg, routerDotToQuad9: true),
          TestStatus.fail);
    });

    test('router DoT counts as Quad9 only when every enabled server is Quad9 over TLS with verification', () {
      const q1 = DotServer(enabled: true, type: 'dot', server: '9.9.9.9', port: 853, verify: 'dns.quad9.net');
      const q2 = DotServer(enabled: true, type: 'dot', server: '149.112.112.112', port: 853, verify: 'dns.quad9.net');
      expect(routerUsesQuad9Dot([q1, q2]), isTrue);
      expect(routerUsesQuad9Dot([q1, const DotServer(enabled: true, type: 'dot', server: '1.1.1.1', verify: 'one.one.one.one')]),
          isFalse);
      expect(routerUsesQuad9Dot([const DotServer(enabled: true, type: 'dot', server: '9.9.9.9')]), isFalse);
      expect(routerUsesQuad9Dot([q1, const DotServer(enabled: false, type: 'dns', server: '8.8.8.8')]), isTrue);
      expect(routerUsesQuad9Dot(const []), isFalse);
    });
  });

  group('Widget out of reach (v2.2.5)', () {
    test('a single missed check while the phone sleeps keeps the last status', () {
      final now = DateTime(2026, 11, 24, 6, 52);
      expect(widgetShouldGoStale(null, now), isTrue);
      expect(widgetShouldGoStale(now.subtract(const Duration(minutes: 5)), now), isFalse);
      expect(widgetShouldGoStale(now.subtract(widgetStaleAfter), now), isTrue);
    });
  });
}
