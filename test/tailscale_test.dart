import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/storage.dart';
import 'package:opnsense_cybervulcan/src/core/wg_keys.dart';
import 'package:opnsense_cybervulcan/src/net/router_link.dart';
import 'package:opnsense_cybervulcan/src/net/tailscale_engine.dart';
import 'package:opnsense_cybervulcan/src/net/tunnel.dart';

const _wgPort = 40000;
const _tsPort = 41000;

class _FakeTunnel implements AppTunnel {
  final List<TunnelSpec> started = [];
  int downs = 0;
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
    return _wgPort;
  }

  @override
  Future<void> down() async {
    downs++;
    _up = false;
  }

  @override
  TunnelStatus status() => TunnelStatus(up: _up, port: _up ? _wgPort : null);
}

/// Built-in Tailscale stand-in: [states] are reported one per status() call
/// after a start (the last one repeats).
class _FakeTailscale implements TailscaleEngine {
  _FakeTailscale({this.states = const [TailscaleState.running], this.available = true, this.peerFound = true});

  List<TailscaleState> states;
  final bool available;
  final bool peerFound;
  final List<TailscaleSpec> started = [];
  final List<String> loggedOut = [];
  int downs = 0;
  int _i = 0;
  bool _up = false;

  @override
  bool get isAvailable => available;
  @override
  String? get unavailableReason => available ? null : 'no library';
  @override
  bool get isUp => _up;

  @override
  Future<TailscaleStatus> start(TailscaleSpec spec) async {
    started.add(spec);
    _up = true;
    _i = 0;
    return status();
  }

  @override
  TailscaleStatus status() {
    if (!_up) return const TailscaleStatus();
    final s = states[_i < states.length ? _i : states.length - 1];
    if (_i < states.length) _i++;
    return TailscaleStatus(
      up: true,
      state: s,
      port: _tsPort,
      authUrl: s == TailscaleState.needsLogin ? 'https://login.example.com/a/xyz' : null,
      tailnetIp: s == TailscaleState.running ? '100.64.0.5' : null,
      peerFound: peerFound,
      peerOnline: peerFound ? true : null,
    );
  }

  @override
  Future<void> down() async {
    downs++;
    _up = false;
  }

  @override
  Future<void> logout(String stateDir) async {
    loggedOut.add(stateDir);
    _up = false;
  }
}

final _serverPub = wireGuardPublicKey(generateWireGuardPrivateKey());
final _secrets = WireGuardSecrets(privateKey: generateWireGuardPrivateKey());

AppConfig cfgWith({String transport = 'wireguard', bool wg = true, bool builtIn = true, bool enabled = true}) =>
    const AppConfig().copyWith(
      baseUrl: 'https://10.10.10.254',
      remoteEnabled: enabled,
      remoteTransport: transport,
      tailscaleBuiltIn: builtIn,
      wgEndpointHost: wg ? 'home.example.com' : '',
      wgServerPublicKey: _serverPub,
      wgAddress: '10.10.99.2/32',
    );

/// Probe answers by route: direct / WireGuard forwarder / Tailscale forwarder.
RouterProbe probeBy(List<String> log,
        {ProbeKind direct = ProbeKind.unreachable,
        ProbeKind wg = ProbeKind.unreachable,
        ProbeKind ts = ProbeKind.ok,
        ProbeKind device = ProbeKind.unreachable}) =>
    (target, route, timeout) async {
      final kind = !route.viaTunnel
          ? (route.host == target.host ? 'direct' : 'device')
          : route.port == _wgPort
              ? 'wg'
              : 'ts';
      log.add(kind);
      return ProbeResult(switch (kind) {
        'direct' => direct,
        'wg' => wg,
        'ts' => ts,
        _ => device,
      }, kind);
    };

RouterLink linkWith(_FakeTunnel tun, _FakeTailscale ts, RouterProbe probe) => RouterLink(
      tunnel: tun,
      tailscale: ts,
      probe: probe,
      resolver: (h, p) async => '203.0.113.9:$p',
      tailscaleStateDir: () async => '/data/app/tailscale',
      tailscaleHostname: () => 'cybervulcan-test',
      tailscaleTimeout: const Duration(milliseconds: 200),
      pollStep: const Duration(milliseconds: 5),
    );

void main() {
  group('remoteSteps', () {
    test('engine choice and order', () {
      expect(remoteSteps(cfgWith(enabled: false)), isEmpty);
      expect(remoteSteps(cfgWith()), [RemoteStep.wireguard]);
      expect(remoteSteps(cfgWith(transport: 'tailscale')), [RemoteStep.tailscaleBuiltIn]);
      expect(remoteSteps(cfgWith(transport: 'tailscale', builtIn: false)), [RemoteStep.tailscaleDevice]);
      expect(remoteSteps(cfgWith(transport: 'auto')), [RemoteStep.wireguard, RemoteStep.tailscaleBuiltIn]);
      expect(remoteSteps(cfgWith(transport: 'auto', builtIn: false)),
          [RemoteStep.wireguard, RemoteStep.tailscaleDevice]);
      expect(remoteSteps(cfgWith(transport: 'nonsense')), [RemoteStep.wireguard]);
    });

    test('v2.0 Tailscale switch still means the device app', () {
      final legacy = const AppConfig().copyWith(tailscaleEnabled: true, tailscaleAddress: '100.101.102.103');
      expect(remoteSteps(legacy), [RemoteStep.tailscaleDevice]);
      expect(remoteSteps(legacy.copyWith(remoteEnabled: true)),
          [RemoteStep.tailscaleDevice, RemoteStep.wireguard]);
    });

    test('Tailscale target: tailnet address, else router LAN IP', () {
      expect(tailscaleTargetFor(cfgWith(), 443), '10.10.10.254:443');
      expect(tailscaleTargetFor(cfgWith().copyWith(tailscaleAddress: '100.64.0.1'), 8443), '100.64.0.1:8443');
      expect(tailscaleTargetFor(cfgWith().copyWith(tailscaleAddress: 'router.tail1.ts.net'), 443),
          'router.tail1.ts.net:443');
      expect(tailscaleTargetFor(cfgWith().copyWith(tailscaleAddress: 'fd7a:115c:a1e0::1'), 443),
          '[fd7a:115c:a1e0::1]:443');
      expect(
          tailscaleTargetFor(const AppConfig(baseUrl: 'https://router.example.com', routerLanIp: ''), 443), isNull);
    });
  });

  group('RouterLink with the built-in Tailscale engine', () {
    late List<String> probed;
    setUp(() => probed = []);

    test('auto: WireGuard first, Tailscale when WireGuard cannot get in', () async {
      final tun = _FakeTunnel(), ts = _FakeTailscale();
      final link = linkWith(tun, ts, probeBy(probed));
      final s = await link.check(cfgWith(transport: 'auto'), _secrets);
      expect(probed, ['direct', 'wg', 'ts']);
      expect(s.state, LinkState.connected);
      expect(s.viaTailscale, isTrue);
      expect(s.builtInTailscale, isTrue);
      expect(s.viaTunnel, isFalse);
      expect(s.remote, isTrue);
      expect(s.describe(cfgWith()), 'Connected via Tailscale (built-in)');
      expect(tun.started, hasLength(1));
      expect(tun.downs, 1, reason: 'the failed WireGuard tunnel is stopped');
      final spec = ts.started.single;
      expect(spec.target, '10.10.10.254:443');
      expect(spec.stateDir, '/data/app/tailscale');
      expect(spec.hostname, 'cybervulcan-test');
      expect(base64.decode(spec.token), hasLength(32));
      expect(spec.toString(), isNot(contains(spec.token)));
      final route = link.routeFor(RouterTarget.fromConfig(cfgWith())!);
      expect(route.port, _tsPort);
      expect(route.token, base64.decode(spec.token));

      // Still away: the running engine is reused and tried first (no
      // WireGuard timeout on every check).
      probed.clear();
      await link.check(cfgWith(transport: 'auto'), _secrets);
      expect(ts.started, hasLength(1));
      expect(probed, ['direct', 'ts']);
      expect(tun.started, hasLength(1));
    });

    test('auto: WireGuard works, Tailscale never started', () async {
      final tun = _FakeTunnel(), ts = _FakeTailscale();
      final link = linkWith(tun, ts, probeBy(probed, wg: ProbeKind.ok));
      final s = await link.check(cfgWith(transport: 'auto'), _secrets);
      expect(probed, ['direct', 'wg']);
      expect(s.viaTunnel, isTrue);
      expect(ts.started, isEmpty);
    });

    test('auto without WireGuard set up: straight to Tailscale', () async {
      final tun = _FakeTunnel(), ts = _FakeTailscale();
      final link = linkWith(tun, ts, probeBy(probed));
      final s = await link.check(cfgWith(transport: 'auto', wg: false), _secrets);
      expect(probed, ['direct', 'ts']);
      expect(tun.started, isEmpty);
      expect(s.viaTailscale, isTrue);
    });

    test('auto: both fail - Not home, both reasons given', () async {
      final tun = _FakeTunnel(), ts = _FakeTailscale();
      final link = linkWith(tun, ts, probeBy(probed, ts: ProbeKind.unreachable));
      final s = await link.check(cfgWith(transport: 'auto'), _secrets);
      expect(s.state, LinkState.notHome);
      expect(s.remoteTried, isTrue);
      expect(s.detail, allOf(contains('tunnel'), contains('Tailscale')));
    });

    test('Tailscale only: WireGuard never touched', () async {
      final tun = _FakeTunnel(), ts = _FakeTailscale();
      final link = linkWith(tun, ts, probeBy(probed, wg: ProbeKind.ok));
      final s = await link.check(cfgWith(transport: 'tailscale'), _secrets);
      expect(probed, ['direct', 'ts']);
      expect(tun.started, isEmpty);
      expect(s.viaTailscale, isTrue);
    });

    test('engine still starting: waits, then connects', () async {
      final ts = _FakeTailscale(states: [TailscaleState.starting, TailscaleState.starting, TailscaleState.running]);
      final link = linkWith(_FakeTunnel(), ts, probeBy(probed));
      final s = await link.check(cfgWith(transport: 'tailscale'), _secrets);
      expect(s.connected, isTrue);
    });

    test('engine never comes up: plain-English timeout', () async {
      final ts = _FakeTailscale(states: [TailscaleState.starting]);
      final link = linkWith(_FakeTunnel(), ts, probeBy(probed));
      final s = await link.check(cfgWith(transport: 'tailscale'), _secrets);
      expect(s.state, LinkState.notHome);
      expect(s.detail, contains('did not connect in time'));
      expect(probed, ['direct']);
    });

    test('not signed in / waiting for approval: says what to do', () async {
      var link = linkWith(_FakeTunnel(), _FakeTailscale(states: [TailscaleState.needsLogin]), probeBy(probed));
      var s = await link.check(cfgWith(transport: 'tailscale'), _secrets);
      expect(s.state, LinkState.notHome);
      expect(s.detail, contains('sign in to Tailscale'));
      expect(s.describe(cfgWith()), contains('sign in to Tailscale'));

      link = linkWith(_FakeTunnel(), _FakeTailscale(states: [TailscaleState.needsApproval]), probeBy(probed));
      s = await link.check(cfgWith(transport: 'tailscale'), _secrets);
      expect(s.detail, contains('admin console'));
    });

    test('router not visible on the tailnet: hints at the subnet route', () async {
      final link = linkWith(_FakeTunnel(), _FakeTailscale(peerFound: false),
          probeBy(probed, ts: ProbeKind.unreachable));
      final s = await link.check(cfgWith(transport: 'tailscale'), _secrets);
      expect(s.detail, contains('subnet route'));
    });

    test('wrong certificate through Tailscale: reported, engine stopped', () async {
      final ts = _FakeTailscale();
      final link = linkWith(_FakeTunnel(), ts, probeBy(probed, ts: ProbeKind.wrongCertificate));
      final s = await link.check(cfgWith(transport: 'tailscale'), _secrets);
      expect(s.state, LinkState.wrongCertificate);
      expect(s.viaTailscale, isTrue);
      expect(ts.downs, 1);
    });

    test('library without Tailscale: not attempted, WireGuard still used in auto', () async {
      final tun = _FakeTunnel();
      final ts = _FakeTailscale(available: false);
      final link = linkWith(tun, ts, probeBy(probed));
      var s = await link.check(cfgWith(transport: 'tailscale'), _secrets);
      expect(s.state, LinkState.notHome);
      expect(s.remoteTried, isFalse);
      expect(ts.started, isEmpty);
      s = await link.check(cfgWith(transport: 'auto'), _secrets);
      expect(probed.last, 'wg');
    });

    test('background: no in-app engine starts; device Tailscale still tried', () async {
      final tun = _FakeTunnel(), ts = _FakeTailscale();
      final link = linkWith(tun, ts, probeBy(probed));
      final s = await link.check(cfgWith(transport: 'auto'), _secrets, background: true);
      expect(s.state, LinkState.notHome);
      expect(tun.started, isEmpty);
      expect(ts.started, isEmpty);

      final device = cfgWith(transport: 'tailscale', builtIn: false).copyWith(tailscaleAddress: '100.64.0.1');
      final link2 = linkWith(_FakeTunnel(), _FakeTailscale(), probeBy(probed, device: ProbeKind.ok));
      final s2 = await link2.check(device, _secrets, background: true);
      expect(s2.viaTailscale, isTrue);
      expect(s2.builtInTailscale, isFalse);
    });

    test('back home: engine stopped, direct again', () async {
      final ts = _FakeTailscale();
      var home = false;
      final link = linkWith(_FakeTunnel(), ts, (t, r, timeout) async {
        if (!r.viaTunnel) return ProbeResult(home ? ProbeKind.ok : ProbeKind.unreachable);
        return const ProbeResult(ProbeKind.ok);
      });
      expect((await link.check(cfgWith(transport: 'tailscale'), _secrets)).viaTailscale, isTrue);
      home = true;
      final s = await link.check(cfgWith(transport: 'tailscale'), _secrets);
      expect(s.remote, isFalse);
      expect(ts.downs, 1);
      expect(link.tailscaleUp, isFalse);
      expect(link.routeFor(RouterTarget.fromConfig(cfgWith())!).viaTunnel, isFalse);
    });

    test('sign-in from Settings at home: engine kept up, auth URL returned; sign out', () async {
      final ts = _FakeTailscale(states: [TailscaleState.starting, TailscaleState.needsLogin]);
      final link = linkWith(_FakeTunnel(), ts, probeBy(probed, direct: ProbeKind.ok));
      final st = await link.startTailscale(cfgWith(transport: 'tailscale'));
      expect(st.state, TailscaleState.needsLogin);
      expect(st.authUrl, startsWith('https://'));
      // A poll at home does not stop the engine while the person signs in.
      await link.check(cfgWith(transport: 'tailscale'), _secrets);
      expect(ts.downs, 0);
      expect(link.tailscaleUp, isTrue);

      await link.logoutTailscale();
      expect(ts.loggedOut, ['/data/app/tailscale']);
      expect(link.tailscaleUp, isFalse);
      // close() (settings saved, app closing) ends the hold.
      await link.startTailscale(cfgWith(transport: 'tailscale'));
      await link.close();
      expect(ts.downs, 1);
    });

    test('startTailscale without a router address explains', () async {
      final link = linkWith(_FakeTunnel(), _FakeTailscale(), probeBy(probed));
      await expectLater(link.startTailscale(const AppConfig(baseUrl: '')), throwsA(isA<TailscaleException>()));
    });
  });

  group('TailscaleStatus / TailscaleSpec', () {
    test('status JSON from the native library', () {
      final s = TailscaleStatus.fromJson({
        'up': true,
        'state': 'running',
        'port': 4242,
        'tailnetIp': '100.64.0.5',
        'peerOnline': true,
        'peerFound': true,
        'derp': 'syd',
        'keyExpiry': 1900000000,
        'health': ['some warning'],
      });
      expect(s.running, isTrue);
      expect(s.port, 4242);
      expect(s.peerOnline, isTrue);
      expect(s.direct, isFalse);
      expect(s.keyExpiry, DateTime.fromMillisecondsSinceEpoch(1900000000 * 1000, isUtc: true));
      expect(s.health, ['some warning']);
      expect(s.describe(), 'Connected as 100.64.0.5 - router reachable via relay (syd)');

      final login = TailscaleStatus.fromJson({'up': true, 'state': 'needs_login', 'authUrl': 'https://x.example/a'});
      expect(login.state, TailscaleState.needsLogin);
      expect(login.authUrl, 'https://x.example/a');
      expect(login.describe(), contains('Sign in'));
      expect(TailscaleStatus.fromJson({'up': false, 'state': 'stopped'}).state, TailscaleState.stopped);
      expect(TailscaleStatus.fromJson({'state': 'needs_approval'}).describe(), contains('approval'));
      expect(TailscaleStatus.fromJson({'state': 'error', 'lastError': 'boom'}).describe(), contains('boom'));
      expect(TailscaleStatus.fromJson({'state': 'weird'}).state, TailscaleState.stopped);
      expect(TailscaleStatus.fromJson({'state': 'running', 'peerFound': false}).describe(),
          contains('approve its subnet route'));
    });

    test('spec JSON has the native field names; toString hides the token', () {
      const spec = TailscaleSpec(
          stateDir: '/d', hostname: 'h', target: '10.10.10.254:443', token: 'SECRET-TOKEN', controlUrl: '');
      expect(spec.toJson(), {'stateDir': '/d', 'hostname': 'h', 'target': '10.10.10.254:443', 'token': 'SECRET-TOKEN'});
      expect(spec.toString(), isNot(contains('SECRET')));
      const custom = TailscaleSpec(
          stateDir: '/d', hostname: 'h', target: 't:1', token: 'x', controlUrl: 'https://hs.example.com');
      expect(custom.toJson()['controlURL'], 'https://hs.example.com');
    });

    test('unavailable engine', () async {
      const u = UnavailableTailscale('nope');
      expect(u.isAvailable, isFalse);
      expect(u.status().state, TailscaleState.stopped);
      await expectLater(
          u.start(const TailscaleSpec(stateDir: '/d', hostname: 'h', target: 't:1', token: 'x')),
          throwsA(isA<TailscaleException>()));
      expect(NativeTailscale.fromTunnel(const UnavailableTunnel('no lib')).isAvailable, isFalse);
    });
  });

  group('settings migration (v2.0 -> v2.1)', () {
    test('new install: built-in Tailscale on, engine WireGuard, remote off', () {
      final c = AppConfig.fromJson(const {});
      expect(c.remoteEnabled, isFalse);
      expect(c.transport, 'wireguard');
      expect(c.tailscaleBuiltIn, isTrue);
    });

    test('v2.0 Tailscale choice: remote on, Tailscale via the device app', () {
      final c = AppConfig.fromJson(const {'tailscaleEnabled': true, 'remoteEnabled': false});
      expect(c.remoteEnabled, isTrue);
      expect(c.transport, 'tailscale');
      expect(c.tailscaleBuiltIn, isFalse);
      expect(remoteSteps(c), [RemoteStep.tailscaleDevice]);
    });

    test('v2.0 with WireGuard and Tailscale both on: Auto', () {
      final c = AppConfig.fromJson(const {'tailscaleEnabled': true, 'remoteEnabled': true});
      expect(c.transport, 'auto');
      expect(remoteSteps(c), [RemoteStep.wireguard, RemoteStep.tailscaleDevice]);
    });

    test('v2.0 WireGuard only: unchanged', () {
      final c = AppConfig.fromJson(const {'remoteEnabled': true});
      expect(c.transport, 'wireguard');
      expect(remoteSteps(c), [RemoteStep.wireguard]);
    });

    test('v2.1 settings are taken as saved', () {
      final c = AppConfig.fromJson(const {
        'tailscaleEnabled': true,
        'remoteEnabled': false,
        'remoteTransport': 'tailscale',
        'tailscaleBuiltIn': true,
      });
      expect(c.remoteEnabled, isFalse);
      expect(c.tailscaleBuiltIn, isTrue);
      final back = AppConfig.decode(cfgWith(transport: 'auto', builtIn: false).encode());
      expect(back.transport, 'auto');
      expect(back.tailscaleBuiltIn, isFalse);
      expect(back.remoteEnabled, isTrue);
    });
  });
}
