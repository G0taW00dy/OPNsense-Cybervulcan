/// IPv4 subnet helpers and the house network layout (suggested default).
library;

int? ipv4ToInt(String ip) {
  final parts = ip.trim().split('.');
  if (parts.length != 4) return null;
  var value = 0;
  for (final p in parts) {
    final n = int.tryParse(p);
    if (n == null || n < 0 || n > 255) return null;
    value = (value << 8) | n;
  }
  return value;
}

String intToIpv4(int value) =>
    [24, 16, 8, 0].map((s) => (value >> s) & 0xff).join('.');

class Ipv4Subnet {
  const Ipv4Subnet._(this.network, this.prefix);

  final int network;
  final int prefix;

  static Ipv4Subnet? tryParse(String cidr) {
    final parts = cidr.trim().split('/');
    final ip = ipv4ToInt(parts.first);
    if (ip == null) return null;
    final prefix = parts.length > 1 ? int.tryParse(parts[1]) : 32;
    if (prefix == null || prefix < 0 || prefix > 32) return null;
    final mask = prefix == 0 ? 0 : (0xffffffff << (32 - prefix)) & 0xffffffff;
    return Ipv4Subnet._(ip & mask, prefix);
  }

  int get mask => prefix == 0 ? 0 : (0xffffffff << (32 - prefix)) & 0xffffffff;

  bool contains(String ip) {
    final v = ipv4ToInt(ip.split('/').first);
    return v != null && (v & mask) == network;
  }

  @override
  String toString() => '${intToIpv4(network)}/$prefix';

  @override
  bool operator ==(Object other) =>
      other is Ipv4Subnet && other.network == network && other.prefix == prefix;

  @override
  int get hashCode => Object.hash(network, prefix);
}

class NamedNetwork {
  const NamedNetwork(this.name, this.cidr, {this.description = ''});

  final String name;
  final String cidr;
  final String description;

  Ipv4Subnet get subnet => Ipv4Subnet.tryParse(cidr)!;
}

/// Default layout of the house (see README). Editable in settings.
const defaultNetworks = <NamedNetwork>[
  NamedNetwork('MGMT', '10.10.10.0/24', description: 'Management'),
  NamedNetwork('CLEAR', '10.10.20.0/24', description: 'Direct internet (gaming)'),
  NamedNetwork('VPN', '10.10.40.0/24', description: 'Everything via Proton'),
  NamedNetwork('IOT', '10.10.50.0/24', description: 'IoT devices'),
];

/// Returns the network name for [ip], or null if it is in none of them.
String? networkNameFor(String ip, List<NamedNetwork> networks) {
  for (final n in networks) {
    final s = Ipv4Subnet.tryParse(n.cidr);
    if (s != null && s.contains(ip)) return n.name;
  }
  return null;
}

/// Canonical CIDR text (`10.10.40.7/24` -> `10.10.40.0/24`); null if invalid.
String? canonicalCidr(String cidr) => Ipv4Subnet.tryParse(cidr)?.toString();

/// Whether a pf table entry (as listed by alias_util) covers [cidrOrIp].
/// pf lists host entries without `/32`, networks as `a.b.c.d/nn`.
bool tableEntryMatches(String entry, String cidrOrIp) {
  final a = Ipv4Subnet.tryParse(entry);
  final b = Ipv4Subnet.tryParse(cidrOrIp);
  return a != null && b != null && a == b;
}

/// v2.1.22: the house networks the router itself has (from
/// `/api/interfaces/overview/interfaces_info` rows), so the app can offer
/// the ones missing from Settings > Network layout (23 Nov: CAMS was
/// missing). Skips the WAN, loopback, tunnels (wg*, tailscale*) and
/// single-address interfaces.
List<NamedNetwork> networksFromInterfaceRows(List<Object?> rows) {
  final out = <NamedNetwork>[];
  for (final r in rows) {
    if (r is! Map) continue;
    final id = '${r['identifier'] ?? ''}'.trim();
    final device = '${r['device'] ?? ''}'.trim().toLowerCase();
    final name = '${r['description'] ?? ''}'.trim();
    if (id.isEmpty || id == 'wan' || id.startsWith('lo') || name.isEmpty) continue;
    if (const ['wg', 'tailscale', 'lo', 'enc', 'pflog', 'pfsync', 'ovpn', 'tun'].any(device.startsWith)) continue;
    final v4 = r['ipv4'];
    if (v4 is! List) continue;
    for (final a in v4) {
      final addr = a is Map ? '${a['ipaddr'] ?? ''}' : '$a';
      final s = Ipv4Subnet.tryParse(addr);
      if (s == null || s.prefix >= 31 || !addr.contains('/')) continue;
      final cidr = s.toString();
      if (!out.any((n) => n.cidr == cidr)) out.add(NamedNetwork(name.replaceAll(' ', '_'), cidr));
    }
  }
  return out;
}

/// Router networks whose subnet is not in [listed].
List<NamedNetwork> missingNetworks(List<NamedNetwork> router, List<NamedNetwork> listed) => [
      for (final n in router)
        if (!listed.any((l) => Ipv4Subnet.tryParse(l.cidr) == Ipv4Subnet.tryParse(n.cidr))) n,
    ];
