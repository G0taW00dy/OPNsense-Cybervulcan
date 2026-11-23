import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/quick_tests.dart';
import 'package:opnsense_cybervulcan/src/core/remote_modes.dart';
import 'package:opnsense_cybervulcan/src/core/updater.dart';
import 'package:opnsense_cybervulcan/src/ui/remote_modes_editor.dart' show modeUnavailable;

void main() {
  group('Update channel (v2.2.2)', updateChannelTests);
  AppConfig everything({String dns = ''}) => const AppConfig().copyWith(
        remoteEnabled: true,
        remoteMode: 'everything',
        routerLanIp: '10.10.10.254',
        everythingDns: dns,
      );

  group('DNS for Everything via home (v2.2.1)', () {
    test('empty = the router', () {
      expect(systemVpnDns(everything()), '10.10.10.254');
    });

    test('Proton DNS when set', () {
      expect(systemVpnDns(everything(dns: '10.2.0.1')), '10.2.0.1');
      expect(systemVpnDns(everything(dns: ' 10.2.0.1 ')), '10.2.0.1');
    });

    test('an invalid entry falls back to the router', () {
      expect(systemVpnDns(everything(dns: 'dns.example')), '10.10.10.254');
      expect(everythingDnsError('dns.example'), isNotNull);
      expect(everythingDnsError('10.2.0.256'), isNotNull);
      expect(everythingDnsError(''), isNull);
      expect(everythingDnsError('10.2.0.1'), isNull);
    });

    test('home mode announces no DNS', () {
      expect(systemVpnDns(everything(dns: '10.2.0.1').copyWith(remoteMode: 'home')), isNull);
    });

    test('kept in saved settings', () {
      final c = everything(dns: '10.2.0.1');
      expect(AppConfig.fromJson(c.toJson()).everythingDns, '10.2.0.1');
    });
  });

  test('Everything via home is offered on Windows (v2.2.1)', () {
    expect(modeUnavailable(everything(), 'everything', windows: true), isNull);
  });

  test('tunnel countries from live peer names (read-only API user, v2.2.1)', () {
    final names = tunnelServerNamesFromLive(['CVT_SG.82_Singapore', 'CVT_SG.145_Singapore', 'Alex_Phone', 'Sam_Phone']);
    expect(names, ['SG#82', 'SG#145']);
    expect(vpnCountriesFor(const AppConfig().copyWith(vpnCountryCode: 'US'), names), containsAll(['SG', 'US']));
  });
}

// v2.2.2: test-build update channel.
Map<String, dynamic> _rel(String tag, {bool pre = false, bool draft = false, bool exe = true}) => {
      'tag_name': tag,
      'html_url': 'https://github.com/o/r/releases/tag/$tag',
      'prerelease': pre,
      'draft': draft,
      'assets': [
        if (exe) {'name': 'Cybervulcan-Setup-${tag.substring(1)}.exe', 'browser_download_url': 'https://github.com/o/r/releases/download/$tag/x.exe'},
        {'name': 'Cybervulcan-${tag.substring(1)}.apk', 'browser_download_url': 'https://github.com/o/r/releases/download/$tag/x.apk'},
      ],
    };

void updateChannelTests() {
  final list = [_rel('v2.2.0'), _rel('v2.2.2', pre: true), _rel('v2.2.1', pre: true), _rel('v2.3.0', draft: true)];
  test('stable channel ignores pre-releases', () {
    expect(newestRelease(list, UpdateTarget.windows, allowPrerelease: false)?.version, '2.2.0');
  });
  test('test channel takes the newest pre-release', () {
    expect(newestRelease(list, UpdateTarget.windows, allowPrerelease: true)?.version, '2.2.2');
  });
  test('drafts and releases without this platform\'s file are skipped', () {
    final l = [_rel('v2.2.0'), _rel('v2.2.5', pre: true, exe: false)];
    expect(newestRelease(l, UpdateTarget.windows, allowPrerelease: true)?.version, '2.2.0');
    expect(newestRelease(l, UpdateTarget.android, allowPrerelease: true)?.version, '2.2.5');
  });
  test('test builds setting is saved', () {
    expect(AppConfig.fromJson(const AppConfig(testBuilds: true).toJson()).testBuilds, isTrue);
    expect(const AppConfig().testBuilds, isFalse);
  });
}
