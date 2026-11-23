import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/api/models.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/network_map.dart';
import 'package:opnsense_cybervulcan/src/core/wg_keys.dart';
import 'package:opnsense_cybervulcan/src/net/router_link.dart';

void main() {
  group('Auto transport stays off Tailscale for home devices (v2.1.22)', () {
    final now = DateTime(2026, 11, 23, 15);
    AppConfig cfg(String mode) => const AppConfig().copyWith(remoteMode: mode, remoteTransport: 'auto');

    test('App only: Tailscale first while it is in use and WireGuard was tried recently', () {
      expect(
          preferTailscaleFirst(cfg('app'),
              tailscaleInUse: true,
              hasBuiltInStep: true,
              lastWireGuardTry: now.subtract(const Duration(minutes: 1)),
              now: now),
          isTrue);
    });

    test('App only: WireGuard gets a fresh try after the retry interval', () {
      expect(
          preferTailscaleFirst(cfg('app'),
              tailscaleInUse: true,
              hasBuiltInStep: true,
              lastWireGuardTry: now.subtract(wireGuardRetry + const Duration(seconds: 1)),
              now: now),
          isFalse);
    });

    test('Home devices: always WireGuard first', () {
      for (final m in ['home', 'everything']) {
        expect(
            preferTailscaleFirst(cfg(m),
                tailscaleInUse: true,
                hasBuiltInStep: true,
                lastWireGuardTry: now.subtract(const Duration(seconds: 5)),
                now: now),
            isFalse,
            reason: m);
      }
    });

    test('Not in use / no built-in step / never tried: no preference', () {
      expect(preferTailscaleFirst(cfg('app'), tailscaleInUse: false, hasBuiltInStep: true, lastWireGuardTry: now, now: now),
          isFalse);
      expect(preferTailscaleFirst(cfg('app'), tailscaleInUse: true, hasBuiltInStep: false, lastWireGuardTry: now, now: now),
          isFalse);
      expect(preferTailscaleFirst(cfg('app'), tailscaleInUse: true, hasBuiltInStep: true, lastWireGuardTry: null, now: now),
          isFalse);
    });
  });

  group('Router networks (v2.1.22)', () {
    final rows = <Object?>[
      {'identifier': 'wan', 'description': 'WAN', 'device': 'igc0', 'ipv4': [{'ipaddr': '203.0.113.7/23'}]},
      {'identifier': 'lan', 'description': 'MGMT', 'device': 'igc1', 'ipv4': [{'ipaddr': '10.10.10.254/24'}]},
      {'identifier': 'opt2', 'description': 'CAMS', 'device': 'vlan051', 'ipv4': [{'ipaddr': '10.10.60.254/24'}]},
      {'identifier': 'opt5', 'description': 'WG_MAIN', 'device': 'wg0', 'ipv4': [{'ipaddr': '10.2.0.2/32'}]},
      {'identifier': 'opt7', 'description': 'RW', 'device': 'wg2', 'ipv4': [{'ipaddr': '10.10.99.1/24'}]},
      {'identifier': 'opt8', 'description': 'TAILSCALE', 'device': 'tailscale0', 'ipv4': [{'ipaddr': '100.64.1.2/32'}]},
      {'identifier': 'lo0', 'description': 'Loopback', 'device': 'lo0', 'ipv4': [{'ipaddr': '127.0.0.1/8'}]},
      {'identifier': '', 'description': 'Unassigned Interface', 'device': 'igc2', 'ipv4': []},
    ];

    test('keeps real house networks, skips WAN, tunnels and loopback', () {
      final n = networksFromInterfaceRows(rows);
      expect(n.map((x) => '${x.name} ${x.cidr}'), ['MGMT 10.10.10.0/24', 'CAMS 10.10.60.0/24']);
    });

    test('missing = router networks whose subnet is not listed', () {
      final listed = [const NamedNetwork('MGMT', '10.10.10.0/24'), const NamedNetwork('VPN', '10.10.40.0/24')];
      final m = missingNetworks(networksFromInterfaceRows(rows), listed);
      expect(m.map((x) => x.name), ['CAMS']);
    });
  });

  group('Wake on LAN (v2.1.22)', () {
    test('host from the router and match by MAC in any case or separator', () {
      final h = WolHost.fromJson({
        'uuid': 'cba68e41-0d3c-41bf-b00f-ffddab0e09a9',
        'mac': '00:11:22:33:44:55',
        'interface': 'opt3',
        'descr': 'Main PC',
      });
      expect(h.mac, '00:11:22:33:44:55');
      expect(wolHostFor('00-11-22-33-44-55', [h])?.description, 'Main PC');
      expect(wolHostFor('00:11:22:33:44:55', [h]), isNull);
      expect(wolHostFor('', [h]), isNull);
    });
  });

  group('Replaced tunnel keys (v2.1.22)', () {
    test('only a known key that changed counts', () {
      final seen = {'Main': 'keyA', 'Backup': 'keyB'};
      expect(replacedInstanceKeys(seen, {'Main': 'keyA', 'Backup': 'keyB'}), isEmpty);
      expect(replacedInstanceKeys(seen, {'Main': 'keyC', 'Backup': 'keyB'}), ['Main']);
      expect(replacedInstanceKeys(const {}, {'Main': 'keyA'}), isEmpty, reason: 'first look is not a change');
      expect(replacedInstanceKeys(seen, {'Main': 'keyA', 'Backup': 'keyB', 'RW': 'keyR'}), isEmpty);
    });

    test('expiry is a year after the key was made', () {
      expect(keyExpiryFrom(DateTime(2026, 11, 23)), '2027-11-23');
      expect(keyExpiryFrom(DateTime(2028, 2, 29)), '2029-03-01');
    });
  });
}
