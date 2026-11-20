import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/providers.dart';
import 'package:opnsense_cybervulcan/src/core/schedule.dart';
import 'package:opnsense_cybervulcan/src/core/server_switcher.dart';

void main() {
  String key(String c) => '${List.filled(43, c).join()}=';

  group('provider profiles', () {
    test('profile from settings, guessed from the provider name when unset', () {
      expect(const AppConfig(vpnName: 'Proton').providerId, 'proton');
      expect(const AppConfig(vpnName: 'Mullvad VPN').providerId, 'mullvad');
      expect(const AppConfig(vpnName: 'Acme VPN').providerId, 'other');
      expect(const AppConfig(vpnName: 'Proton', vpnProvider: 'other').providerId, 'other');
      expect(ProviderProfile.byId('mullvad').hasServerList, isTrue);
      expect(ProviderProfile.byId('proton').hasServerList, isFalse);
      expect(ProviderProfile.byId('nonsense').id, 'other');
    });

    test('Mullvad flat relay list', () {
      final json = [
        {'hostname': 'us-lax-wg-101', 'country_code': 'us', 'city_name': 'Los Angeles', 'ipv4_addr_in': '198.51.100.1',
         'pubkey': key('a'), 'active': true, 'type': 'wireguard'},
        {'hostname': 'us-lax-wg-102', 'country_code': 'us', 'city_name': 'Los Angeles', 'ipv4_addr_in': '198.51.100.2',
         'pubkey': key('b'), 'active': false, 'type': 'wireguard'},
        {'hostname': 'au-syd-wg-001', 'country_code': 'au', 'city_name': 'Sydney', 'ipv4_addr_in': '198.51.100.3',
         'pubkey': key('c'), 'active': true, 'type': 'wireguard'},
        {'hostname': 'us-bad', 'country_code': 'us', 'ipv4_addr_in': 'not-an-ip', 'pubkey': key('d'), 'active': true},
        {'hostname': 'us-badkey', 'country_code': 'us', 'ipv4_addr_in': '198.51.100.5', 'pubkey': 'short', 'active': true},
      ];
      final us = parseMullvadRelays(json, country: 'US');
      expect(us.map((s) => s.name), ['us-lax-wg-101']);
      expect(us.single.city, 'Los Angeles');
      expect(us.single.port, 51820);
      expect(parseMullvadRelays(json).length, 2);
    });

    test('Mullvad nested v1 format', () {
      final json = {
        'countries': [
          {
            'code': 'us',
            'cities': [
              {
                'name': 'Seattle',
                'relays': [
                  {'hostname': 'us-sea-wg-001', 'ipv4_addr_in': '198.51.100.9', 'public_key': key('e')},
                ],
              },
            ],
          },
        ],
      };
      final s = parseMullvadRelays(json, country: 'us');
      expect(s.single.city, 'Seattle');
      expect(s.single.country, 'US');
    });

    test('garbage in, nothing out', () {
      expect(parseMullvadRelays(null), isEmpty);
      expect(parseMullvadRelays({'x': 1}), isEmpty);
    });

    test('a pasted [Peer] block is enough to add a server', () {
      final s = serverFromWireGuardConf('[Peer]\n# US-CA#742\nPublicKey = ${key('k')}\nAllowedIPs = 0.0.0.0/0, ::/0\n'
          'Endpoint = 149.102.228.1:51820\n# Endpoint = [2a02:6ea0:c803:5949::10]:51820\nPersistentKeepalive = 25\n')!;
      expect(s.name, 'US-CA#742');
      expect(s.entryIp, '149.102.228.1');
    });
  });

  group('key expiry', () {
    test('dates', () {
      expect(parseIsoDate('2027-11-11'), DateTime(2027, 11, 11));
      expect(parseIsoDate('2027-02-31'), isNull);
      expect(parseIsoDate('11/11/2027'), isNull);
      expect(parseIsoDate(''), isNull);
    });

    test('warns at 30, 7, 1 days and on expiry - each stage once', () {
      final exp = DateTime(2027, 11, 11);
      expect(keyExpiryStage(exp, DateTime(2027, 9, 1), null), isNull);
      expect(keyExpiryStage(exp, DateTime(2027, 10, 20), null), 30);
      expect(keyExpiryStage(exp, DateTime(2027, 10, 21), 30), isNull);
      expect(keyExpiryStage(exp, DateTime(2027, 11, 5), 30), 7);
      expect(keyExpiryStage(exp, DateTime(2027, 11, 10, 9), 7), 1);
      expect(keyExpiryStage(exp, DateTime(2027, 11, 11, 8), 1), 0);
      expect(keyExpiryStage(exp, DateTime(2027, 11, 12), 0), isNull);
      // Installed late: jumps straight to the right stage.
      expect(keyExpiryStage(exp, DateTime(2027, 11, 9), null), 7);
    });
  });
}
