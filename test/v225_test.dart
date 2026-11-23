import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:opnsense_cybervulcan/src/core/controller.dart';
import 'package:opnsense_cybervulcan/src/core/updater.dart';
import 'package:opnsense_cybervulcan/src/core/storage.dart';
import 'package:opnsense_cybervulcan/src/net/router_link.dart';
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
}
