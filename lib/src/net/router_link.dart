import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import '../api/tls.dart';
import '../core/config.dart';
import '../core/network_map.dart';
import '../core/storage.dart';
import '../core/wg_keys.dart';
import 'tunnel.dart';

/// How the app reaches the router API and how it proves it is the router.
///
/// "Option A": the app always *connects* to the configured address (an IP,
/// e.g. 10.10.10.254) but checks the TLS certificate against the configured
/// certificate name (e.g. router.cybervulcan.com, covered by a Let's Encrypt
/// `*.cybervulcan.com` certificate) using the normal system CAs. An optional
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
  const LinkStatus(this.state, {this.viaTunnel = false, this.detail, this.remoteTried = false});

  final LinkState state;
  final bool viaTunnel;
  final String? detail;

  /// Remote access was configured and tried (and failed when not connected).
  final bool remoteTried;

  static const unknown = LinkStatus(LinkState.notConfigured);

  bool get connected => state == LinkState.connected;

  String describe(AppConfig cfg) => switch (state) {
        LinkState.notConfigured => 'Router address not set',
        LinkState.connected => viaTunnel ? 'Connected via remote access (WireGuard)' : 'Connected',
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
  final host = cfg.routerHost;
  if (host == null || ipv4ToInt(host) == null) {
    p.add('Remote access needs the router address as an IPv4 address (e.g. 10.10.10.254).');
  } else if (!cfg.wgAllowedIpList.any((a) => Ipv4Subnet.tryParse(a)?.contains(host) ?? false)) {
    p.add('Allowed IPs must include the router address $host.');
  }
  return p;
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

/// Decides, on every check, whether the router is reached directly or
/// through the in-app WireGuard tunnel:
///
/// 1. Try the router directly (short timeout, ~2 s).
/// 2. If it does not answer and remote access is set up and enabled, start
///    the tunnel and try again through it.
/// 3. Back home (direct works again), or idle for a while: tunnel down.
class RouterLink {
  RouterLink({
    required this.tunnel,
    RouterProbe? probe,
    EndpointResolver? resolver,
    this.directTimeout = const Duration(seconds: 2),
    this.tunnelTimeout = const Duration(seconds: 8),
    this.idleTimeout = const Duration(minutes: 3),
    Random? random,
  })  : _probe = probe ?? probeRouter,
        _resolve = resolver ?? resolveEndpoint,
        _random = random ?? Random.secure();

  final AppTunnel tunnel;
  final RouterProbe _probe;
  final EndpointResolver _resolve;
  final Duration directTimeout;
  final Duration tunnelTimeout;
  final Duration idleTimeout;
  final Random _random;

  RouterRoute? _route;
  LinkStatus status = LinkStatus.unknown;
  Timer? _idle;
  String? _tunnelSig;
  int? _tunnelPort;
  List<int>? _token;

  /// Route for API sockets; falls back to the direct address.
  RouterRoute routeFor(RouterTarget target) => _route ?? RouterRoute.direct(target.host, target.port);

  bool get tunnelUp => _tunnelPort != null;

  Future<LinkStatus> check(AppConfig cfg, WireGuardSecrets secrets) async {
    final target = RouterTarget.fromConfig(cfg);
    if (target == null) {
      await _tunnelDown();
      return status = const LinkStatus(LinkState.notConfigured);
    }
    final direct = RouterRoute.direct(target.host, target.port);
    final d = await _probe(target, direct, directTimeout);
    if (d.ok) {
      _route = direct;
      await _tunnelDown();
      return status = const LinkStatus(LinkState.connected);
    }

    final remoteReady = cfg.remoteEnabled &&
        tunnel.isAvailable &&
        remoteAccessProblems(cfg, secrets).isEmpty;
    if (!remoteReady) {
      _route = direct;
      await _tunnelDown();
      return status = d.kind == ProbeKind.wrongCertificate
          ? LinkStatus(LinkState.wrongCertificate, detail: d.detail)
          : LinkStatus(LinkState.notHome, detail: d.detail);
    }

    final String? err = await _ensureTunnel(cfg, secrets, target);
    if (err != null) {
      _route = direct;
      return status = d.kind == ProbeKind.wrongCertificate
          ? LinkStatus(LinkState.wrongCertificate, detail: d.detail, remoteTried: true)
          : LinkStatus(LinkState.notHome, detail: err, remoteTried: true);
    }
    final via = RouterRoute.tunnel(_tunnelPort!, _token!);
    final t = await _probe(target, via, tunnelTimeout);
    if (t.ok) {
      _route = via;
      _touch();
      return status = const LinkStatus(LinkState.connected, viaTunnel: true);
    }
    _route = direct;
    await _tunnelDown();
    if (t.kind == ProbeKind.wrongCertificate) {
      return status = LinkStatus(LinkState.wrongCertificate, viaTunnel: true, detail: t.detail, remoteTried: true);
    }
    return status = LinkStatus(LinkState.notHome,
        detail: 'no answer through the tunnel - check the endpoint, keys and the router peer',
        remoteTried: true);
  }

  /// Starts the tunnel unless it is already up with the same settings.
  /// Returns an error message, or null when it is up.
  Future<String?> _ensureTunnel(AppConfig cfg, WireGuardSecrets secrets, RouterTarget target) async {
    final sig = [
      cfg.wgEndpointHost, cfg.wgEndpointPort, cfg.wgServerPublicKey, cfg.wgAddress,
      cfg.wgAllowedIps, cfg.wgKeepalive, target.host, target.port,
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
    final token = List<int>.generate(32, (_) => _random.nextInt(256));
    try {
      _tunnelPort = await tunnel.up(TunnelSpec(
        privateKey: secrets.privateKey!,
        peerPublicKey: cfg.wgServerPublicKey!.trim(),
        presharedKey: secrets.presharedKey,
        endpoint: endpoint,
        address: cfg.wgAddress.trim(),
        allowedIps: cfg.wgAllowedIpList,
        keepalive: cfg.wgKeepalive,
        target: '${target.host}:${target.port}',
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

  void _touch() {
    _idle?.cancel();
    _idle = Timer(idleTimeout, () => unawaited(_tunnelDown()));
  }

  Future<void> _tunnelDown() async {
    _idle?.cancel();
    _idle = null;
    if (_route?.viaTunnel ?? false) _route = null;
    if (_tunnelPort == null && !tunnel.isUp) return;
    _tunnelPort = null;
    _token = null;
    _tunnelSig = null;
    await tunnel.down();
  }

  /// Tunnel down now (app closing, settings changed).
  Future<void> close() => _tunnelDown();
}
