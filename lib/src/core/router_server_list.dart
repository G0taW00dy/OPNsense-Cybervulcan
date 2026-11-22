/// The server list kept on the router (v2.1.8), so every device with the
/// owner's key sees the same list.
///
/// Each server is stored as a WireGuard peer that is switched OFF and linked
/// to no instance: it never carries traffic and the live tunnels are not
/// reconfigured when it is added or removed. The peer's name carries the
/// server name and city; address, port and public key are the peer's own.
library;

import '../api/wireguard_models.dart';
import 'server_switcher.dart';

/// Name prefix of list peers. Peers without it are never touched.
const routerListPrefix = 'CVL_';

/// Inert "Allowed IPs" for list peers (a documentation address): even if
/// someone switched one on by hand, it would route nothing real.
const routerListAllowedIps = '192.0.2.1/32';

String _enc(String s) => s.trim().replaceAll('#', '.').replaceAll(RegExp(r'\s+'), '--').replaceAll(RegExp(r'[^A-Za-z0-9.\-]+'), '-');

/// Peer name for [s]: `CVL_<name>_<city>` using only letters, digits, `.`
/// and `-` (OPNsense's name rule), at most 64 characters.
String listPeerName(ProtonServer s) {
  final city = s.city == null || s.city!.trim().isEmpty ? '' : '_${_enc(s.city!)}';
  final full = '$routerListPrefix${_enc(s.name)}$city';
  return full.length <= 64 ? full : full.substring(0, 64);
}

/// Joins server names that are the same machine (same address + key):
/// Proton runs several names on one server (JP#153 and JP#157). Space
/// separated, the first name kept first; names that no longer fit the
/// router's 64-character peer name are left off (v2.1.18).
String mergeServerNames(String existing, String added, {String? city}) {
  final names = <String>[];
  for (final n in [...existing.split(RegExp(r'\s*/\s*|\s+')), ...added.split(RegExp(r'\s*/\s*|\s+'))]) {
    final t = n.trim();
    if (t.isNotEmpty && !names.any((x) => x.toLowerCase() == t.toLowerCase())) names.add(t);
  }
  // "Former ... server" style names are not codes: keep them only alone.
  if (names.length > 1 && !existing.contains('#')) return added.trim().isEmpty ? existing : added.trim();
  var out = names.join(' ');
  while (names.length > 1 &&
      listPeerName(ProtonServer(name: out, entryIp: '0.0.0.0', publicKey: '', port: 0, city: city)).length >= 64) {
    names.removeLast();
    out = names.join(' ');
  }
  return out;
}

/// Name prefix the app gives a LIVE tunnel peer when it switches it
/// (v2.1.13): the router can't hold that server in the list too (one peer
/// per key), so the tunnel peer's own name carries the server name and city.
const tunnelPeerPrefix = 'CVT_';

/// Name for a live tunnel peer pointed at [s]: `CVT_<name>_<city>`.
String tunnelPeerName(ProtonServer s) => tunnelPeerPrefix + listPeerName(s).substring(routerListPrefix.length);

/// The server a live tunnel peer named by the app stands for, else null.
ProtonServer? serverFromTunnelPeer({required String name, required String address, required String publicKey, required int port}) {
  if (!name.startsWith(tunnelPeerPrefix) || address.isEmpty) return null;
  final (n, city) = _decode(name.substring(tunnelPeerPrefix.length));
  return ProtonServer(name: n.isEmpty ? address : n, entryIp: address, publicKey: publicKey, port: port, city: city);
}

(String, String?) _decode(String rest) {
  final i = rest.indexOf('_');
  // "--" is a space (v2.1.12); a single "-" stays (US-CA#742).
  var name = (i < 0 ? rest : rest.substring(0, i)).replaceAll('--', ' ').replaceAll('.', '#');
  // Names saved before v2.1.12 used "-" for spaces ("Former-Los-Angeles-server").
  // Server codes keep theirs (US-CA#742, JP-FREE-1: a "#" or no lower case).
  if (!name.contains('#') && !name.contains(' ') && RegExp('[a-z]').hasMatch(name)) name = name.replaceAll('-', ' ');
  final city = i < 0 ? null : rest.substring(i + 1).replaceAll('--', ' ').replaceAll('-', ' ').trim();
  var c = city == null || city.isEmpty ? null : city;
  // "Former Los Angeles server" (saved before cities were stored): the city
  // is in the name (v2.1.17).
  final f = RegExp(r'^Former (.+) server$').firstMatch(name);
  if (c == null && f != null && !{'main', 'backup'}.contains(f.group(1)!.toLowerCase())) c = f.group(1);
  return (name, c);
}

/// A list peer: our prefix, switched off, linked to no instance.
bool isListPeer(WgPeer p) => p.name.startsWith(routerListPrefix) && !p.enabled && p.instanceNames.isEmpty;

/// The server a list peer stands for, or null when it is not a list peer or
/// its endpoint / key are unusable.
ProtonServer? serverFromListPeer(WgPeer p) {
  if (!isListPeer(p) || !isWgPublicKey(p.publicKey) || p.serverAddress.isEmpty) return null;
  final (name, city) = _decode(p.name.substring(routerListPrefix.length));
  return ProtonServer(
    name: name.isEmpty ? p.serverAddress : name,
    entryIp: p.serverAddress,
    publicKey: p.publicKey,
    port: p.serverPort,
    city: city,
  );
}

/// Servers in [local] that a live tunnel peer uses: the router list can't
/// hold them (one peer per key), so a device keeps its own copy of their
/// name and city.
List<ProtonServer> inUseByTunnels(List<WgPeer> routerPeers, List<ProtonServer> local) {
  final liveKeys = {for (final p in routerPeers) if (!isListPeer(p)) p.publicKey};
  return [for (final s in local) if (liveKeys.contains(s.publicKey.trim())) s];
}

/// What to change on the router so its list equals [wanted]: list peers to
/// delete (by uuid) and servers to add. A server whose name or city changed
/// is deleted and added again.
({List<String> delete, List<ProtonServer> add}) planListSync(List<WgPeer> routerPeers, List<ProtonServer> wanted) {
  String id(String name, String ip, String key) => '$name|$ip|$key';
  final have = <String, String>{
    for (final p in routerPeers)
      if (isListPeer(p)) id(p.name, p.serverAddress, p.publicKey): p.uuid,
  };
  // A server a live tunnel uses is already on the router (that peer holds its
  // key), and the router allows each public key on one peer only: skip it.
  final liveKeys = {for (final p in routerPeers) if (!isListPeer(p)) p.publicKey};
  final want = <String, ProtonServer>{
    for (final s in wanted)
      if (!liveKeys.contains(s.publicKey.trim())) id(listPeerName(s), s.entryIp, s.publicKey): s,
  };
  return (
    delete: [for (final e in have.entries) if (!want.containsKey(e.key)) e.value],
    add: [for (final e in want.entries) if (!have.containsKey(e.key)) e.value],
  );
}
