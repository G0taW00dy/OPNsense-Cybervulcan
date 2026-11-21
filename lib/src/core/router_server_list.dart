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

String _enc(String s) => s.trim().replaceAll('#', '.').replaceAll(RegExp(r'[^A-Za-z0-9.\-]+'), '-');

/// Peer name for [s]: `CVL_<name>_<city>` using only letters, digits, `.`
/// and `-` (OPNsense's name rule), at most 64 characters.
String listPeerName(ProtonServer s) {
  final city = s.city == null || s.city!.trim().isEmpty ? '' : '_${_enc(s.city!)}';
  final full = '$routerListPrefix${_enc(s.name)}$city';
  return full.length <= 64 ? full : full.substring(0, 64);
}

/// A list peer: our prefix, switched off, linked to no instance.
bool isListPeer(WgPeer p) => p.name.startsWith(routerListPrefix) && !p.enabled && p.instanceNames.isEmpty;

/// The server a list peer stands for, or null when it is not a list peer or
/// its endpoint / key are unusable.
ProtonServer? serverFromListPeer(WgPeer p) {
  if (!isListPeer(p) || !isWgPublicKey(p.publicKey) || p.serverAddress.isEmpty) return null;
  final rest = p.name.substring(routerListPrefix.length);
  final i = rest.indexOf('_');
  final name = (i < 0 ? rest : rest.substring(0, i)).replaceAll('.', '#');
  final city = i < 0 ? null : rest.substring(i + 1).replaceAll('-', ' ').trim();
  return ProtonServer(
    name: name.isEmpty ? p.serverAddress : name,
    entryIp: p.serverAddress,
    publicKey: p.publicKey,
    port: p.serverPort,
    city: city == null || city.isEmpty ? null : city,
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
