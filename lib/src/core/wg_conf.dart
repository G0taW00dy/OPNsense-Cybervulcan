import 'network_map.dart';
import 'wg_keys.dart';

/// Fields read from a standard wg-quick `.conf` (text or the text of a QR
/// code). Only the first [Peer] is used: Cybervulcan talks to one router.
class WgQuickImport {
  const WgQuickImport({
    this.privateKey,
    this.presharedKey,
    this.address,
    this.serverPublicKey,
    this.endpointHost,
    this.endpointPort,
    this.allowedIps,
    this.keepalive,
    this.warnings = const [],
  });

  /// Secret: goes to secure storage only, never into settings.
  final String? privateKey;

  /// Secret: goes to secure storage only, never into settings.
  final String? presharedKey;
  final String? address;
  final String? serverPublicKey;
  final String? endpointHost;
  final int? endpointPort;
  final String? allowedIps;
  final int? keepalive;
  final List<String> warnings;
}

/// Splits `host:port`, `[v6]:port` or `host` (port null).
(String, int?) splitHostPort(String s) {
  final t = s.trim();
  final v6 = RegExp(r'^\[([^\]]+)\](?::(\d+))?$').firstMatch(t);
  if (v6 != null) return (v6.group(1)!, int.tryParse(v6.group(2) ?? ''));
  final i = t.lastIndexOf(':');
  if (i > 0 && t.indexOf(':') == i) {
    return (t.substring(0, i), int.tryParse(t.substring(i + 1)));
  }
  return (t, null);
}

/// Parses wg-quick text. Throws [FormatException] when it is clearly not a
/// WireGuard configuration.
WgQuickImport parseWgQuick(String text) {
  String? section;
  var peers = 0;
  final iface = <String, String>{};
  final peer = <String, String>{};
  for (final raw in text.split(RegExp(r'\r?\n'))) {
    final line = raw.split('#').first.trim();
    if (line.isEmpty) continue;
    final sec = RegExp(r'^\[(\w+)\]$').firstMatch(line);
    if (sec != null) {
      section = sec.group(1)!.toLowerCase();
      if (section == 'peer') peers++;
      continue;
    }
    final eq = line.indexOf('=');
    if (eq < 0) continue;
    final key = line.substring(0, eq).trim().toLowerCase();
    final value = line.substring(eq + 1).trim();
    if (section == 'interface') {
      iface[key] = value;
    } else if (section == 'peer' && peers == 1) {
      peer[key] = value;
    }
  }
  if (iface.isEmpty && peer.isEmpty) {
    throw const FormatException('Not a WireGuard configuration ([Interface] / [Peer] missing)');
  }
  final warnings = <String>[];
  if (peers > 1) warnings.add('Only the first [Peer] was used.');
  if (iface.containsKey('dns')) warnings.add('DNS is ignored: the app connects to the router by IP.');

  String? key(Map<String, String> m, String k, String label) {
    final v = m[k];
    if (v == null || v.isEmpty) return null;
    if (!isWireGuardKey(v)) {
      warnings.add('$label is not a valid WireGuard key and was ignored.');
      return null;
    }
    return v.trim();
  }

  String? address;
  final addr = iface['address'];
  if (addr != null) {
    // Prefer the IPv4 address; the app's tunnel is IPv4.
    for (final a in addr.split(',')) {
      final net = Ipv4Subnet.tryParse(a.trim());
      if (net != null) {
        address = a.trim().contains('/') ? a.trim() : '${a.trim()}/32';
        break;
      }
    }
    if (address == null) warnings.add('No IPv4 Address found.');
  }

  String? host;
  int? port;
  final ep = peer['endpoint'];
  if (ep != null && ep.isNotEmpty) {
    (host, port) = splitHostPort(ep);
  }

  final ka = int.tryParse(peer['persistentkeepalive'] ?? '');
  final allowed = peer['allowedips']
      ?.split(',')
      .map((e) => e.trim())
      .where((e) => e.isNotEmpty)
      .join(', ');
  if (allowed != null && (allowed.contains('0.0.0.0/0') || allowed.contains('::/0'))) {
    warnings.add('AllowedIPs is a full tunnel. The app only ever sends its router '
        'connection through the tunnel, so the router address alone is enough.');
  }

  return WgQuickImport(
    privateKey: key(iface, 'privatekey', 'PrivateKey'),
    presharedKey: key(peer, 'presharedkey', 'PresharedKey'),
    address: address,
    serverPublicKey: key(peer, 'publickey', 'PublicKey'),
    endpointHost: host,
    endpointPort: port,
    allowedIps: allowed,
    keepalive: ka,
    warnings: warnings,
  );
}
