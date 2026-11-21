import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/api/wireguard_models.dart';
import 'package:opnsense_cybervulcan/src/core/router_server_list.dart';
import 'package:opnsense_cybervulcan/src/core/server_switcher.dart';

import 'fake_router.dart';

const _k1 = 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=';
const _k2 = 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=';

void main() {
  const sj = ProtonServer(name: 'US-CA#742', entryIp: '149.102.228.1', publicKey: _k1, city: 'San Jose');
  const la = ProtonServer(name: 'US-CA#100', entryIp: '203.0.113.9', publicKey: _k2, city: 'Los Angeles');

  test('peer name: OPNsense-safe, round-trips name and city', () {
    final n = listPeerName(sj);
    expect(n, 'CVL_US-CA.742_San-Jose');
    expect(RegExp(r'^[A-Za-z0-9._-]{1,64}$').hasMatch(n), isTrue);
    final p = WgPeer(
        uuid: 'u', name: n, enabled: false, serverAddress: sj.entryIp, serverPort: 51820, publicKey: _k1, instanceNames: const []);
    final back = serverFromListPeer(p)!;
    expect(back.name, 'US-CA#742');
    expect(back.city, 'San Jose');
    expect(back.sameEndpoint(sj.entryIp, _k1), isTrue);
  });

  test('a live tunnel peer is never treated as a list entry', () {
    WgPeer peer({bool enabled = false, List<String> inst = const [], String name = 'CVL_X'}) => WgPeer(
        uuid: 'u', name: name, enabled: enabled, serverAddress: '1.2.3.4', serverPort: 51820, publicKey: _k1, instanceNames: inst);
    expect(isListPeer(peer()), isTrue);
    expect(isListPeer(peer(enabled: true)), isFalse);
    expect(isListPeer(peer(inst: ['Proton_VPN_Main'])), isFalse);
    expect(isListPeer(peer(name: 'Proton_446')), isFalse);
  });

  test('sync against the router: adds, renames, removes - tunnels untouched', () async {
    final r = FakeRouter();
    final c = r.client();
    Future<void> sync(List<ProtonServer> wanted) async {
      final plan = planListSync(await c.wgPeers(), wanted);
      for (final u in plan.delete) {
        await c.deleteWgPeer(u);
      }
      for (final s in plan.add) {
        await c.addWgListPeer(name: listPeerName(s), address: s.entryIp, port: s.port, publicKey: s.publicKey);
      }
    }

    final tunnelsBefore = [for (final p in await c.wgPeers()) '${p.name}|${p.enabled}|${p.serverAddress}'];
    await sync([sj, la]);
    var list = [for (final p in await c.wgPeers()) ?serverFromListPeer(p)];
    expect(list.map((s) => s.name), containsAll(['US-CA#742', 'US-CA#100']));

    // Added entries are switched off, unlinked, with the inert allowed IPs.
    final added = r.wgClients.where((x) => '${x['name']}'.startsWith('CVL_'));
    expect(added.every((x) => x['enabled'] == '0' && x['%servers'] == '' && x['tunneladdress'] == routerListAllowedIps), isTrue);

    // City change = delete + add; removing LA deletes only its entry.
    const sjLa = ProtonServer(name: 'US-CA#742', entryIp: '149.102.228.1', publicKey: _k1, city: 'Los Angeles');
    await sync([sjLa]);
    list = [for (final p in await c.wgPeers()) ?serverFromListPeer(p)];
    expect(list.single.city, 'Los Angeles');

    // Nothing else changed: the two real tunnel peers are as they were, and
    // WireGuard was never reconfigured.
    final tunnelsAfter = [
      for (final p in await c.wgPeers())
        if (!p.name.startsWith('CVL_')) '${p.name}|${p.enabled}|${p.serverAddress}',
    ];
    expect(tunnelsAfter, tunnelsBefore);
    expect(r.wgReconfigures, 0);
  });
}
