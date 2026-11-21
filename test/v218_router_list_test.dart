import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/api/wireguard_models.dart';
import 'package:opnsense_cybervulcan/src/core/router_server_list.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/house_state.dart';
import 'package:opnsense_cybervulcan/src/api/models.dart';
import 'package:opnsense_cybervulcan/src/core/quick_tests.dart';
import 'package:opnsense_cybervulcan/src/core/security_tests.dart';
import 'package:opnsense_cybervulcan/src/api/shaper_models.dart';
import 'package:opnsense_cybervulcan/src/core/server_switcher.dart';
import 'package:opnsense_cybervulcan/src/ui/servers_page.dart' show knownCities, withTunnelServers;

import 'fake_router.dart';

const _k1 = 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=';
const _k2 = 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=';

void main() {
  const sj = ProtonServer(name: 'US-CA#742', entryIp: '149.102.228.1', publicKey: _k1, city: 'San Jose');
  const la = ProtonServer(name: 'US-CA#100', entryIp: '203.0.113.9', publicKey: _k2, city: 'Los Angeles');

  test('peer name: OPNsense-safe, round-trips name and city', () {
    final n = listPeerName(sj);
    expect(n, 'CVL_US-CA.742_San--Jose');
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

  test('known cities: one spelling each, from the list and Settings, sorted', () {
    const cfg = AppConfig(serverCities: 'San Jose, los angeles');
    final c = knownCities(const [sj, la, ProtonServer(name: 'JP#1', entryIp: '1.1.1.1', publicKey: _k1, city: 'Tokyo')], cfg);
    expect(c, ['los angeles', 'San Jose', 'Tokyo']);
  });

  test('a server a tunnel uses is skipped (router: one peer per public key)', () async {
    final r = FakeRouter();
    final c = r.client();
    const inUse = ProtonServer(name: 'US-CA#742', entryIp: '149.102.228.1', publicKey: FakeRouter.keyB, city: 'Los Angeles');
    final plan = planListSync(await c.wgPeers(), [inUse, la]);
    expect(plan.add.map((s) => s.name), ['US-CA#100']);
    expect(inUseByTunnels(await c.wgPeers(), [inUse, la]).single.name, 'US-CA#742');
  });

  test('switching a tunnel to a listed server removes its list entry first', () async {
    final r = FakeRouter();
    final c = r.client();
    await c.addWgListPeer(name: listPeerName(la), address: la.entryIp, port: la.port, publicKey: la.publicKey);
    final sw = ServerSwitcher(client: c, config: const AppConfig(
        mainGateway: 'WG_MAIN_GW', backupGateway: 'WG_BACKUP_GW',
        mainWgInstance: 'Proton_VPN_Main', backupWgInstance: 'Proton_VPN_Failover'));
    final (_, backup) = await sw.peers();
    try {
      await sw.apply(backup, la, main: false);
    } on Object {
      // The fake may not complete a handshake; the list entry must be gone anyway.
    }
    final listed = [for (final p in await c.wgPeers()) if (p.name.startsWith('CVL_')) p];
    expect(listed, isEmpty);
    expect((await c.wgPeers()).where((p) => p.publicKey == _k2).length, 1);
  });

  test('tunnel servers not in the list are shown on every device', () {
    const cfg = AppConfig(mainLabel: 'San Jose', backupLabel: 'Los Angeles');
    const peers = (WgPeerInfo('149.36.48.154', 51820, FakeRouter.keyA), WgPeerInfo('149.102.228.1', 51820, _k1));
    final out = withTunnelServers(const [sj, la], peers, cfg);
    expect(out.length, 3); // backup already listed (sj has _k1), main added
    expect(out.first.name, 'San Jose tunnel server');
  });

  group('21 Nov PC test results', () {
    const cfg = AppConfig();
    final vpn = vpnCountriesFor(cfg, ['JP#153', 'US-CA#742']);
    test('tunnel countries come from the servers in use', () => expect(vpn, {'US', 'JP'}));
    test('Tokyo exit on Datacamp passes when main is JP#153', () {
      const tokyo = ExitInfo(ip: '37.19.205.236', countryCode: 'JP', org: 'Datacamp Limited');
      expect(evaluateExit(tokyo, ExpectedPath.vpn, cfg, vpnCountries: vpn).verdict, Verdict.ok);
      expect(classifyResolver(countryCode: 'JP', org: 'Datacamp Limited', expected: ExpectedPath.vpn, cfg: cfg,
          vpnCountries: vpn), TestStatus.pass);
    });
    test('the device\'s own Proton app (Adelaide, Host Universal) is a warning, not a leak', () {
      const adl = ExitInfo(ip: '103.25.57.57', countryCode: 'AU', org: 'Host Universal Pty Ltd');
      expect(evaluateExit(adl, ExpectedPath.vpn, cfg, vpnCountries: vpn).verdict, Verdict.warn);
      expect(classifyResolver(countryCode: 'AU', org: 'Host Universal', expected: ExpectedPath.vpn, cfg: cfg,
          vpnCountries: vpn), TestStatus.warn);
    });
    test('a real ISP exit at home is still a leak', () {
      const isp = ExitInfo(ip: '1.2.3.4', countryCode: 'AU', org: 'Telstra');
      expect(evaluateExit(isp, ExpectedPath.vpn, cfg, vpnCountries: vpn).verdict, Verdict.mismatch);
    });
    test('MGMT (unknown path) gets no shaper-limit advice', () {
      const p = [ShaperPipe(uuid: 'a', number: 1, description: 'VPN upload', mbit: 10, enabled: true)];
      expect(shaperAdvice(p, ExpectedPath.unknown, downMbps: 40, upMbps: 17, lagDown: false), contains('not on the VPN or CLEAR'));
    });
    test('a limit below the measured speed is not blamed', () {
      const p = [ShaperPipe(uuid: 'a', number: 1, description: 'VPN upload', mbit: 10, enabled: true)];
      expect(shaperAdvice(p, ExpectedPath.vpn, downMbps: 40, upMbps: 17.2, lagDown: false), contains('already below'));
    });
  });

  test('server names with spaces survive the router list', () {
    const s = ProtonServer(name: 'Former Los Angeles server', entryIp: '149.102.228.1', publicKey: _k1, city: 'Los Angeles');
    final p = WgPeer(uuid: 'u', name: listPeerName(s), enabled: false, serverAddress: s.entryIp, serverPort: 51820,
        publicKey: _k1, instanceNames: const []);
    final back = serverFromListPeer(p)!;
    expect(back.name, 'Former Los Angeles server');
    expect(back.city, 'Los Angeles');
    expect(serverFromListPeer(WgPeer(uuid: 'u', name: listPeerName(sj), enabled: false, serverAddress: sj.entryIp,
        serverPort: 51820, publicKey: _k1, instanceNames: const []))!.name, 'US-CA#742');
  });

  test('internet line down is only reported when the WAN gateway has a monitor', () {
    const cfg = AppConfig(mainGateway: 'WG_MAIN_GW', backupGateway: 'WG_BACKUP_GW');
    GatewayStatus wan(GatewayHealth h, String? mon) => GatewayStatus(name: 'WAN_DHCP', health: h, monitor: mon);
    expect(wanDownFrom([wan(GatewayHealth.online, '~')], cfg), isNull); // 22 Nov: no monitor -> "online" always
    expect(wanDownFrom([wan(GatewayHealth.down, '9.9.9.9')], cfg), isTrue);
    expect(wanDownFrom([wan(GatewayHealth.online, '9.9.9.9')], cfg), isFalse);
  });

  group('review 22 Nov', () {
    const cfg = AppConfig();
    final auTunnel = vpnCountriesFor(cfg, ['AU#321', 'JP#153']);
    test('an ISP exit/DNS in AU is still a leak when a tunnel server is in AU', () {
      const telstra = ExitInfo(ip: '1.2.3.4', countryCode: 'AU', org: 'Telstra Limited');
      const unknown = ExitInfo(ip: '1.2.3.4', countryCode: 'AU');
      expect(evaluateExit(telstra, ExpectedPath.vpn, cfg, vpnCountries: auTunnel).verdict, Verdict.mismatch);
      expect(evaluateExit(unknown, ExpectedPath.vpn, cfg, vpnCountries: auTunnel).verdict, Verdict.mismatch);
      expect(classifyResolver(countryCode: 'AU', org: 'Telstra', expected: ExpectedPath.vpn, cfg: cfg,
          vpnCountries: auTunnel), TestStatus.fail);
    });
    test('an AU Proton server used by a tunnel passes', () {
      const adl = ExitInfo(ip: '103.25.57.57', countryCode: 'AU', org: 'Host Universal Pty Ltd');
      expect(evaluateExit(adl, ExpectedPath.vpn, cfg, vpnCountries: auTunnel).verdict, Verdict.ok);
    });
    test('VPN network names match whole words only', () {
      expect(looksLikeVpnNetwork('AS131173 Example ISP'), isFalse);
      expect(looksLikeVpnNetwork('Datacamp Limited'), isTrue);
      expect(looksLikeVpnNetwork('Host Universal Pty Ltd'), isTrue);
    });
  });
}
