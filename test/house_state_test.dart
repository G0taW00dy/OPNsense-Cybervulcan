import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/api/models.dart';
import 'package:opnsense_cybervulcan/src/api/opnsense_client.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/events.dart';
import 'package:opnsense_cybervulcan/src/core/house_state.dart';

GatewayStatus g(String name, GatewayHealth h, {double delay = 20}) =>
    GatewayStatus(name: name, health: h, delayMs: delay, lossPercent: 0);

HouseSnapshot snap({
  GatewayHealth? main = GatewayHealth.online,
  GatewayHealth? backup = GatewayHealth.online,
  bool? bypass = false,
  bool? armed = true,
  OpnsenseException? error,
  DateTime? expires,
}) =>
    HouseSnapshot(
      fetchedAt: DateTime(2026, 11, 12, 20),
      main: main == null ? null : g('WG_MAIN_GW', main),
      backup: backup == null ? null : g('WG_BACKUP_GW', backup),
      bypassActive: bypass,
      bypassExpiresAt: expires,
      killSwitchArmed: armed,
      error: error,
    );

void main() {
  const cfg = AppConfig();

  group('exit + health', () {
    test('main up -> main, green', () {
      final s = snap();
      expect(s.exit, ProtonExit.main);
      expect(s.failoverActive, isFalse);
      expect(s.health, Health.ok);
    });

    test('main down, backup up -> failover, amber', () {
      final s = snap(main: GatewayHealth.down);
      expect(s.exit, ProtonExit.backup);
      expect(s.failoverActive, isTrue);
      expect(s.health, Health.warning);
    });

    test('force_down main counts as down', () {
      expect(snap(main: GatewayHealth.forcedDown).exit, ProtonExit.backup);
    });

    test('both down -> none, kill switch tripped, red', () {
      final s = snap(main: GatewayHealth.down, backup: GatewayHealth.down);
      expect(s.exit, ProtonExit.none);
      expect(s.killSwitch.tripped, isTrue);
      expect(s.health, Health.problem);
    });

    test('latency on the active tunnel -> amber', () {
      expect(snap(main: GatewayHealth.latency).health, Health.warning);
      expect(snap(main: GatewayHealth.latency).exit, ProtonExit.main);
    });

    test('bypass wins over tripped (house is direct anyway)', () {
      final s = snap(main: GatewayHealth.down, backup: GatewayHealth.down, bypass: true);
      expect(s.health, Health.bypass);
    });

    test('router error -> red, exit unknown', () {
      final s = snap(error: OpnsenseException(ApiErrorKind.network, 'x'), bypass: true);
      expect(s.exit, ProtonExit.unknown);
      expect(s.health, Health.problem);
    });

    test('kill switch rule missing -> red', () {
      expect(snap(armed: false).health, Health.problem);
      expect(snap(armed: null).health, Health.ok);
    });

    test('unconfigured -> grey', () {
      expect(HouseSnapshot.unconfigured(DateTime.now()).health, Health.notConfigured);
    });

    test('gateway names not found -> unknown/red', () {
      final s = snap(main: null, backup: null);
      expect(s.exit, ProtonExit.unknown);
      expect(s.health, Health.problem);
    });
  });

  group('kill switch rule evaluation', () {
    FirewallRule r({String action = 'block', String tagged = 'NO_WAN_EGRESS', bool enabled = true}) =>
        FirewallRule(uuid: 'u', enabled: enabled, action: action, tagged: tagged, packets: 3);

    test('enabled block rule with tag -> armed', () {
      final res = evaluateKillSwitchRules([r()], 'NO_WAN_EGRESS');
      expect(res.armed, isTrue);
      expect(res.detail, contains('3 packets'));
    });

    test('disabled -> not armed', () {
      expect(evaluateKillSwitchRules([r(enabled: false)], 'NO_WAN_EGRESS').armed, isFalse);
    });

    test('pass rule that sets the tag is ignored', () {
      expect(evaluateKillSwitchRules([r(action: 'pass')], 'NO_WAN_EGRESS').armed, isFalse);
    });

    test('legacy-style capitalised action still counts', () {
      expect(evaluateKillSwitchRules([r(action: 'Block')], 'no_wan_egress').armed, isTrue);
    });
  });

  group('alerts', () {
    List<AlertKind> kinds(HouseSnapshot a, HouseSnapshot b) =>
        diffSnapshots(a, b, cfg).map((e) => e.kind).toList();

    test('first snapshot never alerts', () {
      expect(diffSnapshots(null, snap(main: GatewayHealth.down), cfg), isEmpty);
    });

    test('failover and failback', () {
      expect(kinds(snap(), snap(main: GatewayHealth.down)), [AlertKind.failover]);
      expect(kinds(snap(main: GatewayHealth.down), snap()), [AlertKind.failback]);
    });

    test('both down and restore', () {
      final down = snap(main: GatewayHealth.down, backup: GatewayHealth.down);
      expect(kinds(snap(), down), [AlertKind.bothDown]);
      expect(kinds(snap(main: GatewayHealth.down), down), [AlertKind.bothDown]);
      expect(kinds(down, snap(main: GatewayHealth.down)), [AlertKind.vpnRestored]);
    });

    test('router unreachable is silent both ways', () {
      final err = snap(error: OpnsenseException(ApiErrorKind.network, 'x'));
      expect(kinds(snap(), err), isEmpty);
      expect(kinds(err, snap(main: GatewayHealth.down)), isEmpty);
    });

    test('bypass start/end, unknown is silent', () {
      final on = snap(bypass: true, expires: DateTime.utc(2026, 11, 12, 11, 30));
      expect(kinds(snap(), on), [AlertKind.bypassStarted]);
      expect(diffSnapshots(snap(), on, cfg).single.body, contains('until'));
      expect(kinds(on, snap()), [AlertKind.bypassEnded]);
      expect(kinds(snap(bypass: null), on), isEmpty);
    });

    test('notification toggles are respected', () {
      final quiet = cfg.copyWith(notifyOnFailover: false, notifyOnBypass: false);
      expect(diffSnapshots(snap(), snap(main: GatewayHealth.down, bypass: true), quiet), isEmpty);
    });
  });
}
