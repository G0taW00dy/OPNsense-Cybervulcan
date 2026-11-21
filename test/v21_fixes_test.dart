import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/api/models.dart';
import 'package:opnsense_cybervulcan/src/api/shaper_models.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/house_state.dart';
import 'package:opnsense_cybervulcan/src/core/shaper_tuner.dart';
import 'package:opnsense_cybervulcan/src/core/quick_tests.dart';
import 'package:opnsense_cybervulcan/src/core/security_tests.dart';
import 'package:opnsense_cybervulcan/src/core/server_switcher.dart';

import 'fake_router.dart';

/// Regression tests for the bugs found while testing v2.0.4 on 20 Nov 2026.
void main() {
  group('CLEAR auto-tune', () {
    ShaperPipe p(String d) => ShaperPipe(uuid: d, number: 1, description: d, mbit: 50, enabled: true);
    test('finds CLEAR pipes, never the VPN ones', () {
      final pipes = [p('VPN download'), p('VPN upload'), p('CLEAR download'), p('CLEAR upload')];
      final c = findClearPipes(pipes)!;
      expect(c.down.description, 'CLEAR download');
      expect(c.up.description, 'CLEAR upload');
      expect(findClearPipes([p('VPN download'), p('VPN upload')]), isNull);
    });
    test('WAN gateway: setting wins, else first WAN-named non-VPN gateway', () {
      GatewayStatus g(String n) => GatewayStatus(name: n, health: GatewayHealth.online, delayMs: 30);
      const cfg = AppConfig(mainGateway: 'WG_MAIN_GW', backupGateway: 'WG_BACKUP_GW');
      final all = [g('WG_MAIN_GW'), g('WG_BACKUP_GW'), g('WAN_DHCP')];
      expect(pickWanGateway(all, cfg)!.name, 'WAN_DHCP');
      expect(pickWanGateway(all, cfg.copyWith(wanGateway: 'WG_BACKUP_GW'))!.name, 'WG_BACKUP_GW');
      expect(pickWanGateway([g('WG_MAIN_GW')], cfg), isNull);
    });
    test('uses the CLEAR range, not the VPN one', () {
      const cfg = AppConfig(shaperClearMinDown: 40, shaperClearMaxDown: 100, shaperMaxDown: 80);
      final d = decideTune(
          delayMs: 20, baselineMs: 15, rateDownMbit: 95, rateUpMbit: 0, down: 99, up: 10,
          cfg: cfg, range: TuneRange.clear(cfg), label: 'CLEAR');
      expect(d.down, 100); // raised within the CLEAR max, above the VPN max of 80
    });
  });

  test('shaper display order: VPN first, download before upload, disabled hidden', () {
    ShaperPipe p(String d, {bool on = true}) => ShaperPipe(uuid: d, number: 1, description: d, mbit: 10, enabled: on);
    final order = shaperDisplayOrder([p('CLEAR upload'), p('VPN upload'), p('Old', on: false), p('CLEAR download'), p('VPN download')]);
    expect(order.map((e) => e.description), ['VPN download', 'VPN upload', 'CLEAR download', 'CLEAR upload']);
  });

  GatewayStatus gw(String name, double delay, double jitter, double loss) => GatewayStatus.fromJson({
        ...FakeRouter.gw(name, 'none', '$delay ms', '$loss %'),
        'stddev': '$jitter ms',
      });

  test('WireGuard reconfigure answering {"result":"ok"} is not an error ("status: null" banner)', () async {
    final r = FakeRouter();
    await r.client().wgReconfigure(); // the fake answers like the real router: {"result": "ok"}
    expect(r.wgReconfigures, 1);
  });

  test('Quad9 is recognised under all its network names', () {
    for (final o in ['Quad9', 'WoodyNet', 'Streamline Network Solutions Pty Ltd', 'Anycast Holdings Pty Ltd']) {
      expect(isQuad9Org(o), isTrue, reason: o);
    }
    expect(isQuad9Org('Telstra'), isFalse);
    expect(
        classifyResolver(
            countryCode: 'AU', org: 'Streamline Network Solutions', expected: ExpectedPath.vpn, cfg: const AppConfig()),
        TestStatus.pass);
  });

  test('both tunnels slow alike = line congestion', () {
    expect(lineCongestion(gw('a', 260, 50, 0), gw('b', 250, 48, 0)), isTrue);
    expect(lineCongestion(gw('a', 260, 5, 0), gw('b', 250, 4, 0)), isFalse); // steady
    expect(lineCongestion(gw('a', 400, 50, 0), gw('b', 200, 50, 0)), isFalse); // one server is the problem
    expect(lineCongestion(null, gw('b', 250, 48, 0)), isFalse);
  });

  test('server region hint from provider names', () {
    expect(serverRegionHint('US-CA#742'), 'US-CA');
    expect(serverRegionHint('CH#10'), 'CH');
    expect(serverRegionHint('US-FREE#3'), isNull);
    expect(serverRegionHint('my server'), isNull);
  });

  test('bufferbloat advice knows the shaper is already there (21 Nov PC test)', () {
    ShaperPipe pipe(String d, int mbit) => ShaperPipe(uuid: 'u', number: 1, description: d, mbit: mbit.toDouble(), enabled: true);
    final pipes = [pipe('VPN download (5G)', 60), pipe('VPN upload (5G)', 10), pipe('CLEAR download (5G)', 85), pipe('CLEAR upload (5G)', 18)];
    final direct = shaperAdvice(pipes, ExpectedPath.direct, downMbps: 73.8, upMbps: 12.6, lagDown: false);
    expect(direct, contains('CLEAR upload (5G)'));
    expect(direct, contains('10 Mbit/s'));
    expect(direct, isNot(contains('Set up')));
    expect(shaperAdvice(pipes, ExpectedPath.vpn, downMbps: 50, upMbps: 5, lagDown: true), contains('VPN download'));
    expect(shaperAdvice(const [], ExpectedPath.vpn, downMbps: 50, upMbps: 5, lagDown: true), contains('Set up'));
    expect(shaperAdvice(null, ExpectedPath.vpn, downMbps: 50, upMbps: 5, lagDown: true), contains('fixes this'));
  });
}
