import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import '../api/tls.dart';
import '../core/config.dart';
import '../core/network_map.dart';
import '../core/remote_modes.dart' show tunnelAllowedIps;
import '../core/storage.dart';
import '../core/wg_keys.dart';
import 'tailscale_engine.dart';
import 'tunnel.dart';

/// How the app reaches the router API and how it proves it is the router.
///
/// "Option A": the app always *connects* to the configured address (an IP,
/// e.g. 10.10.10.254) but checks the TLS certificate against the configured
/// certificate name (e.g. router.example.com, covered by a Let's Encrypt
/// `*.example.com` certificate) using the normal system CAs. An optional
/// SHA-256 pin replaces the CA check for self-signed certificates. If the
/// check fails the connection is dropped before any HTTP is sent, so the API
/// key never leaves the device.
class RouterTarget {
  const RouterTarget({
    required this.secure,
    required this.host,
    required this.port,
    required this.tlsName,
    this.pinnedSha256,
  });

  final bool secure;

  /// Address the app connects to (IP or host).
  final String host;
  final int port;

  /// Name the certificate must be valid for (and the HTTP Host header).
  final String tlsName;
  final String? pinnedSha256;

  bool get pinned => pinnedSha256 != null && pinnedSha256!.isNotEmpty;

  static RouterTarget? fromConfig(AppConfig cfg) {
    final u = cfg.baseUri;
    final host = cfg.routerHost;
    final port = cfg.routerPort;
    final name = cfg.tlsName;
    if (u == null || host == null || port == null || name == null) return null;
    return RouterTarget(
      secure: u.scheme == 'https',
      host: host,
      port: port,
      tlsName: name,
      pinnedSha256: cfg.pinnedCertSha256,
    );
  }

  /// URL base used for requests: the certificate name (so the Host header
  /// matches the certificate), while the socket goes to [host].
  Uri get requestBase => Uri(
        scheme: secure ? 'https' : 'http',
        host: secure ? tlsName : host,
        port: port == (secure ? 443 : 80) ? null : port,
      );

  /// With a pin, the system trust store is not used at all: only the pinned
  /// certificate is accepted (a rogue CA in the OS store can't MITM it).
  SecurityContext? securityContext() => pinned ? SecurityContext(withTrustedRoots: false) : null;

  bool acceptBadCertificate(X509Certificate cert) =>
      pinned && fingerprintsMatch(certificateFingerprint(cert), pinnedSha256!);
}

/// Where sockets for the router currently go: straight to the router, or to
/// the in-app tunnel's loopback forwarder.
class RouterRoute {
  const RouterRoute.direct(this.host, this.port)
      : token = null,
        viaTunnel = false;
  const RouterRoute.tunnel(this.port, this.token)
      : host = '127.0.0.1',
        viaTunnel = true;

  final String host;
  final int port;

  /// Forwarder access token, sent before anything else.
  final List<int>? token;
  final bool viaTunnel;
}

/// Thrown when the router's certificate was rejected (wrong name, not CA
/// valid, or not the pinned one).
class WrongCertificateException extends HandshakeException {
  WrongCertificateException(this.detail) : super('Certificate rejected: $detail');
  final String detail;
}

/// Opens a socket to the router along [route] and, for https, completes the
/// TLS handshake against [target]'s certificate name. Nothing else is sent.
Future<Socket> openRouterSocket(RouterTarget target, RouterRoute route, Duration timeout) async {
  final raw = await Socket.connect(route.host, route.port, timeout: timeout);
  try {
    final token = route.token;
    if (token != null) {
      raw.add(token);
      await raw.flush().timeout(timeout);
    }
    if (!target.secure) return raw;
    X509Certificate? rejected;
    try {
      return await SecureSocket.secure(
        raw,
        host: target.tlsName,
        context: target.securityContext(),
        onBadCertificate: (cert) {
          final ok = target.acceptBadCertificate(cert);
          if (!ok) rejected = cert;
          return ok;
        },
      ).timeout(timeout);
    } on HandshakeException catch (e) {
      final cert = rejected;
      if (cert != null) {
        throw WrongCertificateException(target.pinned
            ? 'it is not the pinned certificate (got ${cert.subject})'
            : 'it is not valid for ${target.tlsName} (got ${cert.subject}, issued by ${cert.issuer})');
      }
      // Closed mid-handshake (e.g. the tunnel could not reach the router):
      // a connectivity problem, not a certificate one.
      throw SocketException('TLS connection closed: ${e.message}');
    }
  } catch (_) {
    try {
      raw.destroy();
    } on Object catch (_) {
      // Already detached by the TLS layer; nothing left to close.
    }
    rethrow;
  }
}

enum ProbeKind { ok, unreachable, wrongCertificate }

class ProbeResult {
  const ProbeResult(this.kind, [this.detail]);
  final ProbeKind kind;
  final String? detail;
  bool get ok => kind == ProbeKind.ok;
}

typedef RouterProbe = Future<ProbeResult> Function(RouterTarget target, RouterRoute route, Duration timeout);

/// Connect + TLS handshake only (no HTTP, no credentials).
Future<ProbeResult> probeRouter(RouterTarget target, RouterRoute route, Duration timeout) async {
  try {
    final s = await openRouterSocket(target, route, timeout);
    s.destroy();
    return const ProbeResult(ProbeKind.ok);
  } on WrongCertificateException catch (e) {
    return ProbeResult(ProbeKind.wrongCertificate, e.detail);
  } on HandshakeException catch (e) {
    return ProbeResult(ProbeKind.wrongCertificate, e.message);
  } on TimeoutException {
    return const ProbeResult(ProbeKind.unreachable, 'no answer in time');
  } on SocketException catch (e) {
    return ProbeResult(ProbeKind.unreachable, e.message);
  } on TlsException catch (e) {
    return ProbeResult(ProbeKind.unreachable, e.message);
  }
}

/// [HttpClient] whose sockets come from [openRouterSocket] along the current
/// route, so every API request gets the same certificate-name check.
HttpClient buildRouterHttpClient(RouterTarget target, RouterRoute Function() route,
    {Duration connectionTimeout = const Duration(seconds: 8)}) {
  final client = HttpClient()
    ..connectionTimeout = connectionTimeout
    ..idleTimeout = const Duration(seconds: 15)
    ..userAgent = 'OPNsense-Cybervulcan'
    ..findProxy = ((_) => 'DIRECT');
  client.connectionFactory = (uri, proxyHost, proxyPort) async =>
      ConnectionTask.fromSocket(openRouterSocket(target, route(), connectionTimeout), () {});
  return client;
}

// ------------------------------------------------------------ link manager

enum LinkState {
  /// Router address / name not set.
  notConfigured,

  /// Router answered and proved its identity.
  connected,

  /// Router not reachable (and no working remote access).
  notHome,

  /// Something answered at the router address but its certificate is wrong.
  wrongCertificate,
}

class LinkStatus {
  const LinkStatus(this.state,
      {this.viaTunnel = false,
      this.viaTailscale = false,
      this.builtInTailscale = false,
      this.detail,
      this.remoteTried = false});

  final LinkState state;
  final bool viaTunnel;

  /// Reached through Tailscale: the device's Tailscale app (router's tailnet
  /// address) or the engine built into the app ([builtInTailscale]).
  final bool viaTailscale;

  /// [viaTailscale] through the app's built-in Tailscale engine.
  final bool builtInTailscale;

  /// Reached the router some other way than directly at home.
  bool get remote => viaTunnel || viaTailscale;
  final String? detail;

  /// Remote access was configured and tried (and failed when not connected).
  final bool remoteTried;

  static const unknown = LinkStatus(LinkState.notConfigured);

  bool get connected => state == LinkState.connected;

  String describe(AppConfig cfg) => switch (state) {
        LinkState.notConfigured => 'Router address not set',
        LinkState.connected => viaTunnel
            ? 'Connected via remote access (WireGuard)'
            : viaTailscale
                ? builtInTailscale
                    ? 'Connected via Tailscale (built-in)'
                    : 'Connected via Tailscale'
                : 'Connected',
        LinkState.notHome => 'Not home - ${cfg.routerHost ?? 'the router'} did not answer'
            '${remoteTried ? ' (remote access: ${detail ?? 'no answer'})' : ''}',
        LinkState.wrongCertificate =>
          'Wrong certificate - this may not be your router: ${detail ?? ''}. The API key was not sent.',
      };
}

/// Problems that stop remote access from being used (empty = ready).
List<String> remoteAccessProblems(AppConfig cfg, WireGuardSecrets secrets) {
  final p = <String>[];
  if (!secrets.hasPrivateKey) p.add('This device has no WireGuard key yet (generate one).');
  if (!isWireGuardKey(cfg.wgServerPublicKey)) p.add('Router public key is missing or invalid.');
  if (Ipv4Subnet.tryParse(cfg.wgAddress) == null) p.add('Tunnel address is missing (e.g. 10.10.99.2/32).');
  if (cfg.wgEndpointHost.trim().isEmpty) p.add('Endpoint host is missing.');
  if (cfg.wgEndpointPort < 1 || cfg.wgEndpointPort > 65535) p.add('Endpoint port must be 1-65535.');
  final host = cfg.routerTunnelIp;
  if (host == null) {
    p.add('Remote access needs the router\'s LAN IPv4 (e.g. 10.10.10.254) - set "Router LAN IP".');
  } else if (!cfg.wgAllowedIpList.any((a) => Ipv4Subnet.tryParse(a)?.contains(host) ?? false)) {
    p.add('Allowed IPs must include the router address $host.');
  }
  return p;
}

/// True when this device has a Tailscale address (100.64.0.0/10), i.e. the
/// Tailscale app is connected here.
Future<bool> tailscaleActiveOnDevice() async {
  try {
    final ifaces = await NetworkInterface.list(type: InternetAddressType.IPv4);
    final cgnat = Ipv4Subnet.tryParse('100.64.0.0/10')!;
    return ifaces.any((i) => i.addresses.any((a) => cgnat.contains(a.address)));
  } on Object {
    return false;
  }
}

typedef EndpointResolver = Future<String> Function(String host, int port);

/// Resolves the WireGuard endpoint with the platform resolver (prefers IPv4).
Future<String> resolveEndpoint(String host, int port) async {
  final h = host.trim();
  final literal = InternetAddress.tryParse(h);
  final InternetAddress addr;
  if (literal != null) {
    addr = literal;
  } else {
    final all = await InternetAddress.lookup(h).timeout(const Duration(seconds: 5));
    if (all.isEmpty) throw SocketException('cannot resolve $h');
    addr = all.firstWhere((a) => a.type == InternetAddressType.IPv4, orElse: () => all.first);
  }
  return addr.type == InternetAddressType.IPv6 ? '[${addr.address}]:$port' : '${addr.address}:$port';
}

/// A way to reach the router from away, tried in order by [RouterLink].
enum RemoteStep {
  /// The in-app WireGuard tunnel (native lib, package tunnel).
  wireguard,

  /// Tailscale built into the app (native lib, package ts).
  tailscaleBuiltIn,

  /// The separate Tailscale app on this device (probe the router's tailnet address).
  tailscaleDevice,
}

/// Which remote routes to try, in order, for [cfg] (empty = remote access off).
///
/// - `wireguard`: WireGuard only (today's behaviour).
/// - `tailscale`: built-in Tailscale ([AppConfig.tailscaleBuiltIn]) or the
///   device's Tailscale app.
/// - `auto`: WireGuard first; when it cannot get in (no handshake / no answer
///   within its timeout, e.g. behind CGNAT) Tailscale.
List<RemoteStep> remoteSteps(AppConfig cfg) {
  // v2.0 configs (built in code, or older saved settings) kept Tailscale as
  // its own switch, meaning the device's Tailscale app, tried before WireGuard.
  if (cfg.tailscaleEnabled && cfg.transport == 'wireguard') {
    return [RemoteStep.tailscaleDevice, if (cfg.remoteEnabled) RemoteStep.wireguard];
  }
  if (!cfg.remoteEnabled) return const [];
  final ts = cfg.tailscaleBuiltIn ? RemoteStep.tailscaleBuiltIn : RemoteStep.tailscaleDevice;
  return switch (cfg.transport) {
    'tailscale' => [ts],
    'auto' => [RemoteStep.wireguard, ts],
    _ => const [RemoteStep.wireguard],
  };
}

/// Destination ("host:port") the built-in Tailscale engine forwards to: the
/// router's tailnet address when set, else its LAN IP (through the subnet
/// route the router advertises). Null when neither is known.
String? tailscaleTargetFor(AppConfig cfg, int port) {
  final ts = cfg.tailscaleAddress.trim();
  if (ts.isNotEmpty) return ts.contains(':') && !ts.contains('.') ? '[$ts]:$port' : '$ts:$port';
  final lan = cfg.routerTunnelIp;
  return lan == null ? null : '$lan:$port';
}

/// Outcome of one remote step: [done] ends the check (connected or a wrong
/// certificate); otherwise [failure] explains why it did not work and
/// [tried] says whether anything was actually attempted.
class _Attempt {
  const _Attempt.done(LinkStatus this.done)
      : failure = null,
        tried = true;
  const _Attempt.failed(String this.failure, {this.tried = true}) : done = null;
  final LinkStatus? done;
  final String? failure;
  final bool tried;
}

/// Decides, on every check, how the router is reached:
///
/// 1. Try the router directly (short timeout, ~2 s).
/// 2. If it does not answer and remote access is on, try the remote routes
///    from [remoteSteps] in order: the in-app WireGuard tunnel, the built-in
///    Tailscale engine, or the device's Tailscale app.
/// 3. Back home (direct works again), or idle for a while: in-app engines down.
class RouterLink {
  RouterLink({
    required this.tunnel,
    TailscaleEngine? tailscale,
    RouterProbe? probe,
    EndpointResolver? resolver,
    Future<String> Function()? tailscaleStateDir,
    String Function()? tailscaleHostname,
    this.directTimeout = const Duration(seconds: 2),
    this.tunnelTimeout = const Duration(seconds: 8),
    this.tailscaleTimeout = const Duration(seconds: 20),
    this.pollStep = const Duration(milliseconds: 250),
    this.idleTimeout = const Duration(minutes: 3),
    this.signInHold = const Duration(minutes: 10),
    Random? random,
  })  : tailscale = tailscale ?? NativeTailscale.fromTunnel(tunnel),
        _probe = probe ?? probeRouter,
        _resolve = resolver ?? resolveEndpoint,
        _tsStateDir = tailscaleStateDir ?? defaultTailscaleStateDir,
        _tsHostname = tailscaleHostname ?? defaultTailscaleHostname,
        _random = random ?? Random.secure();

  final AppTunnel tunnel;

  /// Tailscale built into the app (shares the native library with [tunnel]).
  final TailscaleEngine tailscale;
  final RouterProbe _probe;
  final EndpointResolver _resolve;
  final Future<String> Function() _tsStateDir;
  final String Function() _tsHostname;
  final Duration directTimeout;
  final Duration tunnelTimeout;

  /// How long the built-in Tailscale engine may take to come up (cold start:
  /// control server, relay) before the check gives up on it.
  final Duration tailscaleTimeout;
  final Duration pollStep;
  final Duration idleTimeout;

  /// After [startTailscale] (sign-in from Settings) the engine stays up this
  /// long even at home, so the person can finish signing in.
  final Duration signInHold;
  final Random _random;

  RouterRoute? _route;
  LinkStatus status = LinkStatus.unknown;
  Timer? _idle;
  String? _tunnelSig;
  int? _tunnelPort;
  List<int>? _token;

  String? _tsSig;
  int? _tsPort;
  List<int>? _tsToken;
  DateTime? _tsHoldUntil;

  /// Route for API sockets; falls back to the direct address.
  RouterRoute routeFor(RouterTarget target) => _route ?? RouterRoute.direct(target.host, target.port);

  bool get tunnelUp => _tunnelPort != null;

  /// The built-in Tailscale engine is running (any state).
  bool get tailscaleUp => _tsPort != null;

  /// Current state of the built-in Tailscale engine.
  TailscaleStatus get tailscaleStatus => tailscale.status();

  bool get _tsHeld => _tsHoldUntil != null && DateTime.now().isBefore(_tsHoldUntil!);

  /// [background]: the app is not in the foreground (Android): in-app engines
  /// are not started then; the device's own Tailscale app can still be used.
  Future<LinkStatus> check(AppConfig cfg, WireGuardSecrets secrets, {bool background = false}) async {
    final target = RouterTarget.fromConfig(cfg);
    if (target == null) {
      await _allDown();
      return status = const LinkStatus(LinkState.notConfigured);
    }
    final direct = RouterRoute.direct(target.host, target.port);
    final d = await _probe(target, direct, directTimeout);
    if (d.ok) {
      _route = direct;
      await _allDown(keepHeldTailscale: true);
      return status = const LinkStatus(LinkState.connected);
    }

    final failures = <String>[];
    var tried = false;
    var steps = remoteSteps(cfg);
    // Auto: while the built-in Tailscale route is the one in use, try it
    // first (no WireGuard timeout on every check); WireGuard is tried again
    // as soon as Tailscale stops working.
    if (status.builtInTailscale && status.connected && tailscaleUp && steps.contains(RemoteStep.tailscaleBuiltIn)) {
      steps = [RemoteStep.tailscaleBuiltIn, ...steps.where((s) => s != RemoteStep.tailscaleBuiltIn)];
    }
    for (final step in steps) {
      final _Attempt a;
      switch (step) {
        case RemoteStep.wireguard:
          a = background
              ? const _Attempt.failed('not started in the background', tried: false)
              : await _tryWireGuard(cfg, secrets, target);
        case RemoteStep.tailscaleBuiltIn:
          a = background
              ? const _Attempt.failed('not started in the background', tried: false)
              : await _tryTailscaleBuiltIn(cfg, target);
        case RemoteStep.tailscaleDevice:
          a = d.kind == ProbeKind.wrongCertificate
              ? const _Attempt.failed('skipped', tried: false)
              : await _tryTailscaleDevice(cfg, target);
      }
      final done = a.done;
      if (done != null) return status = done;
      tried |= a.tried;
      if (a.tried) failures.add(a.failure!);
    }

    _route = direct;
    if (d.kind == ProbeKind.wrongCertificate) {
      return status = LinkStatus(LinkState.wrongCertificate, detail: d.detail, remoteTried: tried);
    }
    return status = tried
        ? LinkStatus(LinkState.notHome, detail: failures.join('; '), remoteTried: true)
        : LinkStatus(LinkState.notHome, detail: d.detail);
  }

  // ------------------------------------------------------------ WireGuard

  Future<_Attempt> _tryWireGuard(AppConfig cfg, WireGuardSecrets secrets, RouterTarget target) async {
    if (!tunnel.isAvailable || remoteAccessProblems(cfg, secrets).isNotEmpty) {
      await _tunnelDown();
      return const _Attempt.failed('WireGuard is not set up', tried: false);
    }
    final String? err = await _ensureTunnel(cfg, secrets, target);
    if (err != null) return _Attempt.failed(err);
    final via = RouterRoute.tunnel(_tunnelPort!, _token!);
    final t = await _probe(target, via, tunnelTimeout);
    if (t.ok) {
      _route = via;
      _touch();
      return const _Attempt.done(LinkStatus(LinkState.connected, viaTunnel: true));
    }
    if (_route?.viaTunnel ?? false) _route = null;
    await _tunnelDown();
    if (t.kind == ProbeKind.wrongCertificate) {
      return _Attempt.done(
          LinkStatus(LinkState.wrongCertificate, viaTunnel: true, detail: t.detail, remoteTried: true));
    }
    return const _Attempt.failed('no answer through the tunnel - check the endpoint, keys and the router peer');
  }

  /// Starts the tunnel unless it is already up with the same settings.
  /// Returns an error message, or null when it is up.
  Future<String?> _ensureTunnel(AppConfig cfg, WireGuardSecrets secrets, RouterTarget target) async {
    final sig = [
      cfg.wgEndpointHost, cfg.wgEndpointPort, cfg.wgServerPublicKey, cfg.wgAddress,
      // v2.1: AllowedIPs include what the remote mode needs (home devices / everything).
      tunnelAllowedIps(cfg).join(','), cfg.wgKeepalive, cfg.routerTunnelIp, target.port,
      // Not the keys themselves: just whether they changed.
      secrets.privateKey.hashCode, secrets.presharedKey.hashCode,
    ].join('|');
    if (_tunnelPort != null && sig == _tunnelSig) return null;
    final String endpoint;
    try {
      endpoint = await _resolve(cfg.wgEndpointHost, cfg.wgEndpointPort);
    } on Object catch (e) {
      return 'cannot resolve ${cfg.wgEndpointHost}: $e';
    }
    final token = _newToken();
    try {
      _tunnelPort = await tunnel.up(TunnelSpec(
        privateKey: secrets.privateKey!,
        peerPublicKey: cfg.wgServerPublicKey!.trim(),
        presharedKey: secrets.presharedKey,
        endpoint: endpoint,
        address: cfg.wgAddress.trim(),
        allowedIps: tunnelAllowedIps(cfg),
        keepalive: cfg.wgKeepalive,
        target: '${cfg.routerTunnelIp}:${target.port}',
        token: base64.encode(token),
      ));
      _token = token;
      _tunnelSig = sig;
      return null;
    } on TunnelException catch (e) {
      _tunnelPort = null;
      return 'tunnel failed to start: ${e.message}';
    }
  }

  List<int> _newToken() => List<int>.generate(32, (_) => _random.nextInt(256));

  // ------------------------------------------------------------ Tailscale

  /// The device's own Tailscale app carries the packets. With a subnet route
  /// for the router address the direct probe already worked; otherwise try
  /// the router's tailnet address (100.x / MagicDNS). The certificate is
  /// still checked against the certificate name.
  Future<_Attempt> _tryTailscaleDevice(AppConfig cfg, RouterTarget target) async {
    final tsAddr = cfg.tailscaleAddress.trim();
    if (tsAddr.isEmpty) {
      return const _Attempt.failed('the router did not answer through the Tailscale app on this device - '
          'is Tailscale connected here and the router\'s subnet route approved?');
    }
    final via = RouterRoute.direct(tsAddr, target.port);
    final r = await _probe(target, via, tunnelTimeout);
    if (r.ok) {
      await _allDown(keepHeldTailscale: true);
      _route = via;
      return const _Attempt.done(LinkStatus(LinkState.connected, viaTailscale: true));
    }
    if (r.kind == ProbeKind.wrongCertificate) {
      return _Attempt.done(LinkStatus(LinkState.wrongCertificate, detail: r.detail, remoteTried: true));
    }
    return _Attempt.failed('Tailscale address $tsAddr did not answer - is Tailscale connected on this device?');
  }

  Future<_Attempt> _tryTailscaleBuiltIn(AppConfig cfg, RouterTarget target) async {
    if (!tailscale.isAvailable) {
      return _Attempt.failed(tailscale.unavailableReason ?? 'built-in Tailscale is not available', tried: false);
    }
    final TailscaleStatus st;
    try {
      st = await _ensureTailscale(cfg, target);
    } on TailscaleException catch (e) {
      return _Attempt.failed('Tailscale did not start: ${e.message}');
    }
    switch (st.state) {
      case TailscaleState.needsLogin:
        return const _Attempt.failed('sign in to Tailscale first (Settings > Remote access)');
      case TailscaleState.needsApproval:
        return const _Attempt.failed('approve this device in the Tailscale admin console');
      case TailscaleState.running:
        break;
      case TailscaleState.error:
        return _Attempt.failed('Tailscale problem: ${st.lastError ?? 'the engine stopped'}');
      case TailscaleState.starting:
      case TailscaleState.stopped:
        return const _Attempt.failed('Tailscale did not connect in time - no Internet, or Tailscale is down?');
    }
    final via = RouterRoute.tunnel(_tsPort!, _tsToken!);
    final r = await _probe(target, via, tunnelTimeout);
    if (r.ok) {
      _route = via;
      _touch();
      return const _Attempt.done(LinkStatus(LinkState.connected, viaTailscale: true, builtInTailscale: true));
    }
    if (_route?.viaTunnel ?? false) _route = null;
    if (r.kind == ProbeKind.wrongCertificate) {
      await _tsDown();
      return _Attempt.done(LinkStatus(LinkState.wrongCertificate,
          viaTailscale: true, builtInTailscale: true, detail: r.detail, remoteTried: true));
    }
    // Keep the engine up (it is signed in; the router may just be offline).
    _touch();
    return _Attempt.failed(!st.peerFound
        ? 'Tailscale is connected but the router is not visible - approve its subnet route in the admin console'
        : st.peerOnline == false
            ? 'Tailscale is connected but the router is offline'
            : 'no answer from the router through Tailscale');
  }

  /// Starts the built-in engine unless it already runs with the same
  /// settings, then waits (up to [tailscaleTimeout]) until it is running or
  /// needs the person (sign-in / approval).
  Future<TailscaleStatus> _ensureTailscale(AppConfig cfg, RouterTarget target) async {
    await _startTailscaleEngine(cfg, target);
    final until = DateTime.now().add(tailscaleTimeout);
    var st = tailscale.status();
    while (st.state == TailscaleState.starting && DateTime.now().isBefore(until)) {
      await Future<void>.delayed(pollStep);
      st = tailscale.status();
    }
    return st;
  }

  Future<TailscaleStatus> _startTailscaleEngine(AppConfig cfg, RouterTarget target) async {
    final dest = tailscaleTargetFor(cfg, target.port);
    if (dest == null) {
      throw TailscaleException('set "Router LAN IP" or the router\'s Tailscale address');
    }
    final dir = await _tsStateDir();
    final host = _tsHostname();
    final sig = [dir, host, dest].join('|');
    if (_tsPort != null && sig == _tsSig && tailscale.isUp) return tailscale.status();
    if (TailscaleCrashGuard.blocked) {
      throw TailscaleException('paused - it closed the app last time. Settings > Remote access > "Sign in to '
          'Tailscale" tries again; Copy diagnostics shows the crash');
    }
    final token = _newToken();
    await TailscaleCrashGuard.starting();
    Future<void>.delayed(const Duration(seconds: 20), TailscaleCrashGuard.survived);
    final st = await tailscale.start(TailscaleSpec(
      stateDir: dir,
      hostname: host,
      target: dest,
      token: base64.encode(token),
    ));
    _tsPort = st.port;
    _tsToken = token;
    _tsSig = sig;
    if (_tsPort == null) {
      await _tsDown();
      throw TailscaleException('no loopback port');
    }
    return st;
  }

  /// Starts the built-in engine now (even at home), e.g. to sign in from
  /// Settings, and keeps it up for [signInHold]. Waits up to
  /// [tailscaleTimeout] for an auth URL / running. Throws [TailscaleException].
  Future<TailscaleStatus> startTailscale(AppConfig cfg) async {
    if (!tailscale.isAvailable) throw TailscaleException(tailscale.unavailableReason ?? 'not available');
    final target = RouterTarget.fromConfig(cfg);
    if (target == null) throw TailscaleException('set the router address first');
    await TailscaleCrashGuard.unblock(); // an explicit sign-in tries again
    _tsHoldUntil = DateTime.now().add(signInHold);
    await _startTailscaleEngine(cfg, target);
    final until = DateTime.now().add(tailscaleTimeout);
    var st = tailscale.status();
    while ((st.state == TailscaleState.starting ||
            (st.state == TailscaleState.needsLogin && st.authUrl == null)) &&
        DateTime.now().isBefore(until)) {
      await Future<void>.delayed(pollStep);
      st = tailscale.status();
    }
    return st;
  }

  /// Signs this device out of Tailscale and deletes the saved login.
  Future<void> logoutTailscale() async {
    _tsHoldUntil = null;
    if (_route?.viaTunnel ?? false) _route = null;
    _tsPort = null;
    _tsToken = null;
    _tsSig = null;
    if (!tailscale.isAvailable) return;
    await tailscale.logout(await _tsStateDir());
  }

  // ------------------------------------------------------------ lifecycle

  void _touch() {
    _idle?.cancel();
    _idle = Timer(idleTimeout, () => unawaited(_allDown(keepHeldTailscale: true)));
  }

  Future<void> _tunnelDown() async {
    if (_tunnelPort == null && !tunnel.isUp) return;
    if (_route?.viaTunnel ?? false) {
      if (_route!.port == _tunnelPort) _route = null;
    }
    _tunnelPort = null;
    _token = null;
    _tunnelSig = null;
    await tunnel.down();
  }

  Future<void> _tsDown() async {
    if (_tsPort == null && !tailscale.isUp) return;
    if ((_route?.viaTunnel ?? false) && _route!.port == _tsPort) _route = null;
    _tsPort = null;
    _tsToken = null;
    _tsSig = null;
    await tailscale.down();
  }

  Future<void> _allDown({bool keepHeldTailscale = false}) async {
    _idle?.cancel();
    _idle = null;
    if (_route?.viaTunnel ?? false) _route = null;
    await _tunnelDown();
    if (!(keepHeldTailscale && _tsHeld)) await _tsDown();
  }

  /// In-app engines down now (app closing, settings changed, background).
  Future<void> close() {
    _tsHoldUntil = null;
    return _allDown();
  }

  /// Like [close], but a Tailscale engine waiting for its browser sign-in
  /// stays up (the browser itself sends the app to the background, and the
  /// person may tap Save before finishing the sign-in).
  Future<void> pause() => _allDown(keepHeldTailscale: true);
}
