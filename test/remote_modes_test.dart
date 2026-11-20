import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/remote_modes.dart';
import 'package:opnsense_cybervulcan/src/core/storage.dart';
import 'package:opnsense_cybervulcan/src/core/wg_keys.dart';
import 'package:opnsense_cybervulcan/src/net/router_link.dart';
import 'package:opnsense_cybervulcan/src/net/tunnel.dart';
import 'package:opnsense_cybervulcan/src/platform/vpn_modes.dart';

final _serverPub = wireGuardPublicKey(generateWireGuardPrivateKey());
final _secrets = WireGuardSecrets(privateKey: generateWireGuardPrivateKey());

AppConfig cfgFor(String mode, {String devices = '', bool remote = true}) => const AppConfig().copyWith(
      baseUrl: 'https://10.10.10.254',
      remoteEnabled: remote,
      wgEndpointHost: 'home.example.com',
      wgServerPublicKey: _serverPub,
      wgAddress: '10.10.99.2/32',
      remoteMode: mode,
      homeDevices: devices,
    );

const away = LinkStatus(LinkState.connected, viaTunnel: true);
const home = LinkStatus(LinkState.connected);
const notHome = LinkStatus(LinkState.notHome);

class FakeSystemVpn implements SystemVpn {
  final List<SystemVpnRequest> starts = [];
  int stops = 0;
  bool running = false;
  bool transportUp = true;
  String? failWith;
  String? lastError;
  bool other = false;
  bool allow = true;

  @override
  bool get isSupported => true;
  @override
  String? get unsupportedReason => null;
  @override
  Future<bool> prepare() async => allow;
  @override
  Future<void> start(SystemVpnRequest request) async {
    if (failWith != null) throw SystemVpnException(failWith!);
    starts.add(request);
    running = true;
  }

  @override
  Future<void> stop() async {
    stops++;
    running = false;
  }

  @override
  Future<SystemVpnStatus> status() async =>
      SystemVpnStatus(running: running, transportUp: transportUp, lastError: lastError);
  @override
  Future<bool> otherVpnActive() async => other;
}

class FakeTunnel implements AppTunnel {
  final List<TunnelSpec> started = [];
  bool _up = false;
  @override
  bool get isAvailable => true;
  @override
  String? get unavailableReason => null;
  @override
  bool get isUp => _up;
  @override
  Future<int> up(TunnelSpec spec) async {
    started.add(spec);
    _up = true;
    return 40000;
  }

  @override
  Future<void> down() async => _up = false;
  @override
  TunnelStatus status() => TunnelStatus(up: _up);
}

void main() {
  group('mode settings', () {
    test('defaults keep today\'s behaviour', () {
      const c = AppConfig();
      expect(c.mode, 'app');
      expect(c.protonReminder, isFalse);
      expect(systemVpnRoutes(c), isEmpty);
      expect(wantsSystemVpn(cfgFor('app'), away), isFalse);
      expect(tunnelAllowedIps(cfgFor('app')), cfgFor('app').wgAllowedIpList);
    });

    test('home devices validation', () {
      expect(homeDevicesError(''), isNull);
      expect(homeDevicesError('', required: true), contains('at least one'));
      expect(homeDevicesError('10.10.10.5, 10.10.10.0/24 192.168.7.9'), isNull);
      expect(homeDevicesError('nas.local'), contains('not an IPv4'));
      expect(homeDevicesError('10.10.10.300'), contains('not an IPv4'));
      expect(homeDevicesError('10.10.10.0/'), contains('not an IPv4'));
      expect(homeDevicesError('0.0.0.0/0'), contains('too wide'));
      expect(homeDevicesError('10.0.0.0/7'), contains('too wide'));
      expect(homeDevicesError('127.0.0.1'), contains('not a home device'));
      expect(homeDevicesError('224.0.0.1'), contains('not a home device'));
      expect(homeDevicesError('169.254.1.1'), contains('not a home device'));
    });

    test('routes: home = devices + router /32, everything = default routes', () {
      final h = cfgFor('home', devices: '10.10.10.5, 10.10.10.0/24, 10.10.10.5');
      expect(systemVpnRoutes(h), ['10.10.10.5/32', '10.10.10.0/24', '10.10.10.254/32']);
      expect(systemVpnAllowed(h), systemVpnRoutes(h));
      expect(systemVpnDns(h), isNull);

      final e = cfgFor('everything');
      expect(systemVpnRoutes(e), ['0.0.0.0/0', '::/0']);
      expect(systemVpnAllowed(e), ['0.0.0.0/0']); // IPv6 routed in, refused inside
      expect(systemVpnDns(e), '10.10.10.254');
    });

    test('router given as a name uses the router LAN IP', () {
      final c = cfgFor('home', devices: '10.10.10.5')
          .copyWith(baseUrl: 'https://router.example.com', routerLanIp: '10.10.10.1');
      expect(systemVpnRoutes(c), ['10.10.10.5/32', '10.10.10.1/32']);
    });

    test('tunnel AllowedIPs follow the mode', () {
      expect(tunnelAllowedIps(cfgFor('home', devices: '10.10.10.5')), ['10.10.10.254/32', '10.10.10.5/32']);
      expect(tunnelAllowedIps(cfgFor('everything')), ['10.10.10.254/32', '0.0.0.0/0']);
      expect(tunnelAllowedIps(cfgFor('everything', remote: false)), ['10.10.10.254/32']);
    });

    test('problems and when the system VPN is wanted', () {
      expect(remoteModeProblems(cfgFor('home')), [contains('at least one')]);
      expect(remoteModeProblems(cfgFor('everything', remote: false)), [contains('remote access')]);
      expect(remoteModeProblems(cfgFor('home', devices: '10.10.10.5')), isEmpty);

      final h = cfgFor('home', devices: '10.10.10.5');
      expect(wantsSystemVpn(h, away), isTrue);
      expect(wantsSystemVpn(h, home), isFalse);
      expect(wantsSystemVpn(h, notHome), isFalse);
      expect(wantsSystemVpn(h, const LinkStatus(LinkState.connected, viaTailscale: true)), isFalse);
      expect(wantsSystemVpn(cfgFor('home'), away), isFalse); // no devices
    });

    test('RouterLink starts the tunnel with the mode\'s AllowedIPs', () async {
      final tun = FakeTunnel();
      final link = RouterLink(
        tunnel: tun,
        probe: (t, route, timeout) async =>
            route.viaTunnel ? const ProbeResult(ProbeKind.ok) : const ProbeResult(ProbeKind.unreachable, 'x'),
        resolver: (h, p) async => '203.0.113.7:$p',
      );
      final st = await link.check(cfgFor('home', devices: '10.10.10.5'), _secrets);
      expect(st.viaTunnel, isTrue);
      expect(tun.started.single.allowedIps, ['10.10.10.254/32', '10.10.10.5/32']);
      // A mode change restarts the tunnel with the new list.
      await link.check(cfgFor('everything'), _secrets);
      expect(tun.started.last.allowedIps, contains('0.0.0.0/0'));
      await link.close();
    });
  });

  group('platform request / status', () {
    test('request from config', () {
      final r = SystemVpnRequest.fromConfig(cfgFor('everything'));
      expect(r.toArgs(), {
        'mode': 'everything',
        'routes': ['0.0.0.0/0', '::/0'],
        'allowed': ['0.0.0.0/0'],
        'dns': '10.10.10.254',
        'mtu': 1280,
        'transport': 'wireguard',
      });
      expect(SystemVpnRequest.fromConfig(cfgFor('everything')).signature, r.signature);
    });

    test('status from the Android channel', () {
      final s = SystemVpnStatus.fromChannel({
        'running': true,
        'mode': 'home',
        'lastError': null,
        'native': '{"up":true,"transportUp":true,"tcpActive":3,"rx":10,"tx":20}',
      });
      expect(s.running, isTrue);
      expect(s.transportUp, isTrue);
      expect(s.tcpActive, 3);
      expect(s.rxBytes, 10);
      expect(SystemVpnStatus.fromChannel({'running': false, 'native': 'garbage'}).running, isFalse);
    });
  });

  group('HomeLink keeps the system VPN in line', () {
    test('on when away via the tunnel, off at home, no needless restarts', () async {
      final vpn = FakeSystemVpn();
      final hl = HomeLink(vpn);
      final cfg = cfgFor('home', devices: '10.10.10.5');

      expect(await hl.onLink(cfg, away), isTrue);
      expect(vpn.starts, hasLength(1));
      expect(hl.state, HomeLinkState.connected);
      expect(hl.describe(), 'Home link: Home devices - connected');

      await hl.onLink(cfg, away);
      expect(vpn.starts, hasLength(1), reason: 'same settings: no restart');

      vpn.transportUp = false;
      await hl.onLink(cfg, away);
      expect(hl.describe(), contains('waiting'));

      await hl.onLink(cfgFor('home', devices: '10.10.10.5, 10.10.10.6'), away);
      expect(vpn.starts, hasLength(2), reason: 'new routes: restart');

      await hl.onLink(cfg, home);
      expect(vpn.stops, 1);
      expect(hl.state, HomeLinkState.off);
      expect(hl.describe(), isNull);
    });

    test('app mode never starts it', () async {
      final vpn = FakeSystemVpn();
      final hl = HomeLink(vpn);
      expect(await hl.onLink(cfgFor('app'), away), isFalse);
      expect(vpn.starts, isEmpty);
      expect(hl.keepTunnelInBackground(cfgFor('app')), isFalse);
      expect(hl.keepTunnelInBackground(cfgFor('everything')), isTrue);
    });

    test('start failure and revoke are shown, not retried every poll', () async {
      final vpn = FakeSystemVpn()..failWith = 'Allow Cybervulcan\'s VPN first.';
      final hl = HomeLink(vpn);
      final cfg = cfgFor('everything');
      await hl.onLink(cfg, away);
      expect(hl.state, HomeLinkState.error);
      expect(hl.describe(), contains('Allow'));

      vpn.failWith = null;
      await hl.onLink(cfg, away);
      expect(hl.state, HomeLinkState.connected);

      // Android revoked it (another VPN app started).
      vpn.running = false;
      vpn.lastError = 'The VPN was turned off by Android.';
      await hl.onLink(cfg, away);
      expect(hl.state, HomeLinkState.error);
      await hl.onLink(cfg, away);
      expect(vpn.starts, hasLength(1), reason: 'not restarted against the user');

      vpn.lastError = null;
      await hl.retry(cfg, away);
      expect(vpn.starts, hasLength(2));
      expect(hl.state, HomeLinkState.connected);
    });

    test('retry without permission explains it', () async {
      final vpn = FakeSystemVpn()..allow = false;
      final hl = HomeLink(vpn);
      await hl.retry(cfgFor('everything'), away);
      expect(hl.error, contains('permission'));
    });
  });

  group('VPN-app reminder', () {
    final t0 = DateTime.utc(2026, 11, 20, 8);

    (ReminderState, ReminderKind?) step(ReminderState s, Place p, bool vpnOn, int minutes) =>
        reminderStep(s, now: p, otherVpnActive: vpnOn, at: t0.add(Duration(minutes: minutes)));

    test('place from the router link', () {
      expect(placeFromLink(home), Place.home);
      expect(placeFromLink(away), Place.away);
      expect(placeFromLink(notHome), Place.away);
      expect(placeFromLink(const LinkStatus(LinkState.wrongCertificate)), Place.unknown);
      expect(placeFromLink(null), Place.unknown);
    });

    test('first reading never reminds', () {
      var (s, k) = step(const ReminderState(), Place.home, true, 0);
      expect(k, isNull);
      (s, k) = step(s, Place.home, true, 1);
      expect(k, isNull);
      expect(s.place, Place.home);
    });

    test('leaving home with the VPN app off, then arriving with it on', () {
      var s = const ReminderState(place: Place.home);
      ReminderKind? k;
      (s, k) = step(s, Place.away, false, 0);
      expect(k, isNull, reason: 'needs a second reading');
      (s, k) = step(s, Place.away, false, 1);
      expect(k, ReminderKind.turnOn);
      (s, k) = step(s, Place.away, false, 2);
      expect(k, isNull, reason: 'only on transitions');

      (s, k) = step(s, Place.home, true, 60);
      (s, k) = step(s, Place.home, true, 61);
      expect(k, ReminderKind.turnOff);
    });

    test('no reminder when the VPN app is already right', () {
      var s = const ReminderState(place: Place.home);
      ReminderKind? k;
      (s, k) = step(s, Place.away, true, 0);
      (s, k) = step(s, Place.away, true, 1);
      expect(k, isNull);
      expect(s.place, Place.away);
      (s, k) = step(s, Place.home, false, 5);
      (s, k) = step(s, Place.home, false, 6);
      expect(k, isNull);
    });

    test('Wi-Fi edge flapping and cooldown', () {
      var s = const ReminderState(place: Place.home);
      ReminderKind? k;
      // One "away" reading between homes: ignored.
      (s, k) = step(s, Place.away, false, 0);
      (s, k) = step(s, Place.home, false, 1);
      (s, k) = step(s, Place.away, false, 2);
      expect(k, isNull);
      expect(s.place, Place.home);
      // Real departure.
      (s, k) = step(s, Place.away, false, 3);
      expect(k, ReminderKind.turnOn);
      // Back and away again within the cooldown: silent.
      (s, k) = step(s, Place.home, true, 5);
      (s, k) = step(s, Place.home, true, 6);
      expect(k, isNull);
      expect(s.place, Place.home);
      // Unknown readings change nothing.
      (s, k) = step(s, Place.unknown, true, 7);
      expect(s.place, Place.home);
      // After the cooldown it reminds again.
      (s, k) = step(s, Place.away, false, 40);
      (s, k) = step(s, Place.away, false, 41);
      expect(k, ReminderKind.turnOn);
    });

    test('texts are neutral and use the VPN name', () {
      final (t1, b1) = reminderText(ReminderKind.turnOff, const AppConfig(vpnName: 'Mullvad'));
      expect(t1, 'You\'re home - you can turn your VPN app off');
      expect(b1, contains('Mullvad'));
      final (t2, b2) = reminderText(ReminderKind.turnOn, const AppConfig(vpnName: ''));
      expect(t2, 'You\'ve left home - turn your VPN app back on');
      expect(b2, contains('your VPN'));
    });
  });
}
