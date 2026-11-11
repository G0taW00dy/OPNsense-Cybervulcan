/// IPv4 subnet helpers and the mapping of Tim's house networks.
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
