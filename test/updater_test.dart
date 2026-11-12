import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:opnsense_cybervulcan/src/core/updater.dart';

Map<String, dynamic> release({
  String tag = 'v1.2.0',
  bool prerelease = false,
  String host = 'github.com',
}) =>
    {
      'tag_name': tag,
      'html_url': 'https://github.com/G0taW00dy/OPNsense-Cybervulcan/releases/tag/$tag',
      'draft': false,
      'prerelease': prerelease,
      'body': 'notes',
      'assets': [
        {
          'name': 'Cybervulcan-1.2.0.apk',
          'browser_download_url': 'https://$host/G0taW00dy/OPNsense-Cybervulcan/releases/download/$tag/Cybervulcan-1.2.0.apk',
        },
        {
          'name': 'Cybervulcan-Setup-1.2.0.exe',
          'browser_download_url': 'https://$host/G0taW00dy/OPNsense-Cybervulcan/releases/download/$tag/Cybervulcan-Setup-1.2.0.exe',
          'digest': 'sha256:ABCDEF',
        },
      ],
    };

void main() {
  group('compareVersions', () {
    test('numeric, not string, order', () {
      expect(compareVersions('1.10.0', '1.9.2'), 1);
      expect(compareVersions('1.0.0', '1.0.1'), -1);
      expect(compareVersions('v1.2', '1.2.0'), 0);
      expect(compareVersions('1.2.0+7', '1.2.0'), 0);
      expect(compareVersions('2.0.0-beta', '1.9.9'), 1);
    });
  });

  group('ReleaseInfo.fromGitHub', () {
    test('picks the installer on Windows and the APK on Android', () {
      final w = ReleaseInfo.fromGitHub(release(), UpdateTarget.windows)!;
      expect(w.version, '1.2.0');
      expect(w.asset!.name, 'Cybervulcan-Setup-1.2.0.exe');
      expect(w.asset!.sha256, 'abcdef');
      final a = ReleaseInfo.fromGitHub(release(), UpdateTarget.android)!;
      expect(a.asset!.name, 'Cybervulcan-1.2.0.apk');
      expect(a.asset!.sha256, isNull);
    });

    test('skips pre-releases', () {
      expect(ReleaseInfo.fromGitHub(release(prerelease: true), UpdateTarget.windows), isNull);
    });

    test('ignores downloads that are not on GitHub', () {
      final r = ReleaseInfo.fromGitHub(release(host: 'evil.example'), UpdateTarget.windows)!;
      expect(r.asset, isNull);
    });
  });

  group('UpdateService.check', () {
    UpdateService svc(http.Client c, {String current = '1.0.0'}) =>
        UpdateService(target: UpdateTarget.windows, client: c, currentVersion: current);

    test('finds a newer release and announces it once', () async {
      final s = svc(MockClient((req) async {
        expect(req.url.path, '/repos/G0taW00dy/OPNsense-Cybervulcan/releases/latest');
        return http.Response(jsonEncode(release()), 200);
      }));
      final seen = <String>[];
      s.found.listen((r) => seen.add(r.version));
      await s.check();
      await s.check();
      await Future<void>.delayed(Duration.zero);
      expect(s.available?.version, '1.2.0');
      expect(seen, ['1.2.0']);
      expect(s.error, isNull);
    });

    test('same or older version is not an update', () async {
      final s = svc(MockClient((_) async => http.Response(jsonEncode(release()), 200)), current: '1.2.0');
      await s.check();
      expect(s.available, isNull);
    });

    test('404 (no release yet / private repo) is quiet', () async {
      final s = svc(MockClient((_) async => http.Response('{}', 404)));
      await s.check();
      expect(s.available, isNull);
      expect(s.error, isNull);
    });

    test('other errors are reported', () async {
      final s = svc(MockClient((_) async => http.Response('', 500)));
      await s.check();
      expect(s.error, contains('500'));
    });
  });
}
