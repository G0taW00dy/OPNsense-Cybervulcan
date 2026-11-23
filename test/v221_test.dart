import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/quick_tests.dart';
import 'package:opnsense_cybervulcan/src/core/remote_modes.dart';
import 'package:opnsense_cybervulcan/src/ui/remote_modes_editor.dart' show modeUnavailable;

void main() {
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
