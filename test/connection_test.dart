import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/api/opnsense_client.dart';
import 'package:opnsense_cybervulcan/src/api/tls.dart';
import 'package:opnsense_cybervulcan/src/core/client_factory.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/storage.dart';
import 'package:opnsense_cybervulcan/src/core/wg_keys.dart';
import 'package:opnsense_cybervulcan/src/net/router_link.dart';
import 'package:opnsense_cybervulcan/src/net/tunnel.dart';

/// Records what the link manager asks of the native tunnel.
class FakeTunnel implements AppTunnel {
  FakeTunnel({this.available = true, this.failUp = false});

  final bool available;
  final bool failUp;
  final List<TunnelSpec> started = [];
  int downs = 0;
  bool _up = false;

  @override
  bool get isAvailable => available;
  @override
  String? get unavailableReason => available ? null : 'no library';
  @override
  bool get isUp => _up;
  @override
  Future<int> up(TunnelSpec spec) async {
    if (failUp) throw TunnelException('boom');
    started.add(spec);
    _up = true;
    return 40000;
  }

  @override
  Future<void> down() async {
    downs++;
    _up = false;
  }

  @override
  TunnelStatus status() => TunnelStatus(up: _up, port: _up ? 40000 : null);
}

final _serverPub = wireGuardPublicKey(generateWireGuardPrivateKey());

AppConfig remoteCfg({bool enabled = true}) => const AppConfig().copyWith(
      remoteEnabled: enabled,
      wgServerPublicKey: _serverPub,
      wgAddress: '10.10.99.2/32',
    );

final secrets = WireGuardSecrets(privateKey: generateWireGuardPrivateKey());

void main() {
  group('RouterTarget (address vs certificate name)', () {
    test('connects to the IP, checks the certificate name, Host = name', () {
      final t = RouterTarget.fromConfig(const AppConfig())!;
      expect(t.host, '10.10.10.254');
      expect(t.port, 443);
      expect(t.tlsName, 'router.cybervulcan.com');
      expect(t.requestBase.toString(), 'https://router.cybervulcan.com');
    });

    test('empty certificate name falls back to the address; custom port kept', () {
      final t = RouterTarget.fromConfig(
          const AppConfig(baseUrl: 'https://10.10.10.254:8443', certName: ''))!;
      expect(t.tlsName, '10.10.10.254');
      expect(t.requestBase.toString(), 'https://10.10.10.254:8443');
    });

    test('plain http uses the address and port 80', () {
      final t = RouterTarget.fromConfig(const AppConfig(baseUrl: 'http://10.10.10.254'))!;
      expect(t.secure, isFalse);
      expect(t.port, 80);
      expect(t.requestBase.toString(), 'http://10.10.10.254');
    });
  });

  group('RouterLink decisions', () {
    late List<RouterRoute> probed;
    RouterProbe probeWith(ProbeKind direct, [ProbeKind tunnel = ProbeKind.ok]) =>
        (target, route, timeout) async {
          probed.add(route);
          return ProbeResult(route.viaTunnel ? tunnel : direct, 'x');
        };
    Future<String> resolver(String h, int p) async => '203.0.113.9:$p';

    setUp(() => probed = []);

    test('home: direct works, tunnel never started, short timeout', () async {
      final tun = FakeTunnel();
      Duration? used;
      final link = RouterLink(
        tunnel: tun,
        resolver: resolver,
        probe: (t, r, timeout) async {
          used = timeout;
          probed.add(r);
          return const ProbeResult(ProbeKind.ok);
        },
      );
      final s = await link.check(remoteCfg(), secrets);
      expect(s.state, LinkState.connected);
      expect(s.viaTunnel, isFalse);
      expect(tun.started, isEmpty);
      expect(used, const Duration(seconds: 2));
      expect(probed.single.host, '10.10.10.254');
    });

    test('away without remote access: Not home', () async {
      final link = RouterLink(tunnel: FakeTunnel(), probe: probeWith(ProbeKind.unreachable));
      final s = await link.check(remoteCfg(enabled: false), secrets);
      expect(s.state, LinkState.notHome);
      expect(s.remoteTried, isFalse);
    });

    test('away with remote access: tunnel up, routed through the forwarder', () async {
      final tun = FakeTunnel();
      final link = RouterLink(tunnel: tun, probe: probeWith(ProbeKind.unreachable), resolver: resolver);
      final s = await link.check(remoteCfg(), secrets);
      expect(s.state, LinkState.connected);
      expect(s.viaTunnel, isTrue);
      final spec = tun.started.single;
      expect(spec.endpoint, '203.0.113.9:51830');
      expect(spec.target, '10.10.10.254:443');
      expect(spec.allowedIps, ['10.10.10.254/32']);
      expect(spec.keepalive, 25);
      expect(base64.decode(spec.token), hasLength(32));
      final route = link.routeFor(RouterTarget.fromConfig(remoteCfg())!);
      expect(route.viaTunnel, isTrue);
      expect(route.host, '127.0.0.1');
      expect(route.port, 40000);
      expect(route.token, base64.decode(spec.token));
      // The spec's toString (used in errors) never carries keys.
      expect(spec.toString(), isNot(contains(secrets.privateKey)));

      // Second check while still away reuses the running tunnel.
      await link.check(remoteCfg(), secrets);
      expect(tun.started, hasLength(1));
    });

    test('back home: tunnel torn down, direct again', () async {
      final tun = FakeTunnel();
      var home = false;
      final link = RouterLink(
        tunnel: tun,
        resolver: resolver,
        probe: (t, r, timeout) async =>
            ProbeResult(r.viaTunnel || home ? ProbeKind.ok : ProbeKind.unreachable),
      );
      expect((await link.check(remoteCfg(), secrets)).viaTunnel, isTrue);
      home = true;
      final s = await link.check(remoteCfg(), secrets);
      expect(s.viaTunnel, isFalse);
      expect(tun.downs, 1);
      expect(link.routeFor(RouterTarget.fromConfig(remoteCfg())!).viaTunnel, isFalse);
    });

    test('idle tunnel goes down by itself', () async {
      final tun = FakeTunnel();
      final link = RouterLink(
          tunnel: tun,
          resolver: resolver,
          probe: probeWith(ProbeKind.unreachable),
          idleTimeout: const Duration(milliseconds: 20));
      await link.check(remoteCfg(), secrets);
      await Future<void>.delayed(const Duration(milliseconds: 80));
      expect(tun.downs, 1);
      expect(link.tunnelUp, isFalse);
    });

    test('wrong certificate at home without remote: Wrong certificate', () async {
      final link = RouterLink(tunnel: FakeTunnel(), probe: probeWith(ProbeKind.wrongCertificate));
      final s = await link.check(remoteCfg(enabled: false), secrets);
      expect(s.state, LinkState.wrongCertificate);
      expect(s.describe(const AppConfig()), contains('API key was not sent'));
    });

    test('wrong certificate through the tunnel is reported, tunnel stopped', () async {
      final tun = FakeTunnel();
      final link = RouterLink(
          tunnel: tun,
          resolver: resolver,
          probe: probeWith(ProbeKind.unreachable, ProbeKind.wrongCertificate));
      final s = await link.check(remoteCfg(), secrets);
      expect(s.state, LinkState.wrongCertificate);
      expect(s.viaTunnel, isTrue);
      expect(tun.downs, 1);
    });

    test('tunnel up but router silent: Not home (remote tried)', () async {
      final tun = FakeTunnel();
      final link = RouterLink(
          tunnel: tun,
          resolver: resolver,
          probe: probeWith(ProbeKind.unreachable, ProbeKind.unreachable));
      final s = await link.check(remoteCfg(), secrets);
      expect(s.state, LinkState.notHome);
      expect(s.remoteTried, isTrue);
      expect(tun.downs, 1);
    });

    test('incomplete remote setup or missing library: tunnel not attempted', () async {
      final tun = FakeTunnel();
      final link = RouterLink(tunnel: tun, probe: probeWith(ProbeKind.unreachable), resolver: resolver);
      await link.check(remoteCfg(), const WireGuardSecrets());
      await link.check(remoteCfg().copyWith(wgAddress: ''), secrets);
      await link.check(remoteCfg().copyWith(wgAllowedIps: '10.10.40.0/24'), secrets);
      expect(tun.started, isEmpty);
      final noLib = RouterLink(
          tunnel: FakeTunnel(available: false), probe: probeWith(ProbeKind.unreachable));
      expect((await noLib.check(remoteCfg(), secrets)).state, LinkState.notHome);
    });

    test('remoteAccessProblems explains what is missing', () {
      final p = remoteAccessProblems(
          const AppConfig(remoteEnabled: true), const WireGuardSecrets());
      expect(p.join(' '), allOf(contains('no WireGuard key'), contains('Router public key'),
          contains('Tunnel address')));
      expect(remoteAccessProblems(remoteCfg(), secrets), isEmpty);
    });
  });

  group('TLS name check against a real local server', () {
    late SecurityContext serverCtx;
    late HttpServer server;
    late List<HttpRequest> received;

    setUp(() async {
      serverCtx = SecurityContext()
        ..useCertificateChain('test/fixtures/test_router_cert.pem')
        ..usePrivateKey('test/fixtures/test_router_key.pem');
      server = await HttpServer.bindSecure('127.0.0.1', 0, serverCtx);
      received = [];
      server.listen((r) {
        received.add(r);
        r.response
          ..headers.contentType = ContentType.json
          ..write(jsonEncode({'items': <Object>[], 'status': 'ok'}));
        unawaited(r.response.close());
      });
    });

    tearDown(() => server.close(force: true));

    AppConfig cfgFor({String certName = 'router.test.invalid', String? pin}) => AppConfig(
          baseUrl: 'https://127.0.0.1:${server.port}',
          certName: certName,
          pinnedCertSha256: pin,
        );

    test('certificate not trusted for the name: refused, API key never sent', () async {
      final cfg = cfgFor(certName: 'router.cybervulcan.com');
      final target = RouterTarget.fromConfig(cfg)!;
      final probe = await probeRouter(
          target, RouterRoute.direct('127.0.0.1', server.port), const Duration(seconds: 3));
      expect(probe.kind, ProbeKind.wrongCertificate);

      final client = buildRouterClient(cfg, const ApiCredentials('KEY', 'SECRET'))!;
      await expectLater(
        client.gatewayStatus(),
        throwsA(isA<OpnsenseException>()
            .having((e) => e.kind, 'kind', ApiErrorKind.untrustedCertificate)),
      );
      client.close();
      expect(received, isEmpty, reason: 'no HTTP request (and so no Authorization) may reach the server');
    });

    test('pinned certificate is accepted; request goes to the IP with Host = name', () async {
      final presented = await probeCertificate('127.0.0.1', server.port);
      final cfg = cfgFor(pin: presented!.fingerprint);
      final client = buildRouterClient(cfg, const ApiCredentials('KEY', 'SECRET'))!;
      expect(await client.gatewayStatus(), isEmpty);
      client.close();
      expect(received.single.headers.host, 'router.test.invalid');
      expect(received.single.uri.path, '/api/routes/gateway/status');
    });

    test('a different pin is rejected', () async {
      final cfg = cfgFor(pin: 'AA:BB:CC');
      final client = buildRouterClient(cfg, const ApiCredentials('KEY', 'SECRET'))!;
      await expectLater(client.gatewayStatus(), throwsA(isA<OpnsenseException>()));
      client.close();
      expect(received, isEmpty);
    });

    test('nothing listening: unreachable, not a certificate problem', () async {
      final s = await ServerSocket.bind('127.0.0.1', 0);
      final port = s.port;
      await s.close();
      final target = RouterTarget.fromConfig(cfgFor())!;
      final r = await probeRouter(target, RouterRoute.direct('127.0.0.1', port), const Duration(seconds: 2));
      expect(r.kind, ProbeKind.unreachable);
    });
  });

  test('tunnel route sends the access token before anything else', () async {
    final server = await ServerSocket.bind('127.0.0.1', 0);
    final token = List<int>.generate(32, (i) => i + 1);
    final got = Completer<List<int>>();
    server.listen((sock) {
      final buf = <int>[];
      sock.listen((data) {
        buf.addAll(data);
        if (utf8.decode(buf, allowMalformed: true).contains('\r\n\r\n') && !got.isCompleted) {
          got.complete(List.of(buf));
          sock.add(utf8.encode('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
              'Content-Length: 2\r\nConnection: close\r\n\r\n{}'));
          unawaited(sock.close());
        }
      });
    });
    const cfg = AppConfig(baseUrl: 'http://10.10.10.254');
    final client = buildRouterClient(cfg, const ApiCredentials('k', 's'),
        route: (_) => RouterRoute.tunnel(server.port, token))!;
    await client.gatewayStatus();
    client.close();
    final bytes = await got.future;
    expect(bytes.take(32).toList(), token);
    expect(utf8.decode(bytes.skip(32).toList()), startsWith('GET /api/routes/gateway/status'));
    await server.close();
  });
}
