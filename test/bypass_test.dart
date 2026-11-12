import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/core/bypass.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/pc_mode.dart';
import 'package:opnsense_cybervulcan/src/core/states.dart';

import 'fake_router.dart';

void main() {
  const cfg = AppConfig();

  group('expiry marker', () {
    test('round-trips to the minute and lives in 240.0.0.0/4', () {
      final t = DateTime.utc(2026, 11, 12, 21, 37);
      final m = encodeExpiryMarker(t);
      expect(m, matches(RegExp(r'^2(4\d|5[0-5])\.')));
      expect(decodeExpiryMarker(m), t);
      expect(decodeExpiryMarker('$m/32'), t);
    });

    test('normal addresses are not markers', () {
      expect(decodeExpiryMarker('10.10.40.0/24'), isNull);
      expect(decodeExpiryMarker('10.10.40.50'), isNull);
      expect(decodeExpiryMarker('garbage'), isNull);
    });

    test('readBypassState: earliest marker wins, needs the network to be active', () {
      final a = DateTime.utc(2026, 11, 12, 22);
      final b = DateTime.utc(2026, 11, 12, 23);
      final s = readBypassState(
          ['10.10.40.0/24', encodeExpiryMarker(b), encodeExpiryMarker(a)], cfg);
      expect(s.active, isTrue);
      expect(s.expiresAt, a);
      final off = readBypassState([encodeExpiryMarker(a)], cfg);
      expect(off.active, isFalse);
      expect(off.expiresAt, isNull);
    });
  });

  group('BypassManager', () {
    late FakeRouter router;
    late MemoryStore store;
    late DateTime now;
    BypassManager manager({AppConfig c = cfg}) =>
        BypassManager(client: router.client(), config: c, store: store, clock: () => now);

    setUp(() {
      router = FakeRouter();
      store = MemoryStore();
      now = DateTime.utc(2026, 11, 12, 10, 0);
    });

    test('no time limit: marker fits, never expires, stays on until turned off', () async {
      final s = await manager().turnOn(duration: bypassNoLimit);
      expect(s.active, isTrue);
      expect(isNoLimitExpiry(s.expiresAt), isTrue);
      now = now.add(const Duration(days: 3650));
      final (action, after) = await manager().enforce(await manager().read());
      expect(action, EnforceAction.none);
      expect(after.active, isTrue);
      final off = await manager().turnOff();
      expect(off.active, isFalse);
    });

    test('a normal deadline is not "no time limit"', () {
      expect(isNoLimitExpiry(DateTime.utc(2026, 11, 12, 22)), isFalse);
      expect(isNoLimitExpiry(null), isFalse);
      expect(isNoLimitDuration(const Duration(hours: 4)), isFalse);
      expect(isNoLimitDuration(bypassNoLimit), isTrue);
    });

    test('turnOn adds network + marker and records local expiry', () async {
      final s = await manager().turnOn();
      expect(s.active, isTrue);
      expect(s.expiresAt, DateTime.utc(2026, 11, 12, 12, 0));
      expect(router.tables['BYPASS_ALL'], contains('10.10.40.0/24'));
      expect(router.tables['BYPASS_ALL'], hasLength(2));
      expect(store.getString(localExpiryKey), isNotNull);
    });

    test('turnOn with a custom duration and without marker', () async {
      final s = await manager(c: cfg.copyWith(useExpiryMarker: false))
          .turnOn(duration: const Duration(minutes: 30));
      expect(router.tables['BYPASS_ALL'], ['10.10.40.0/24']);
      expect(s.expiresAt, DateTime.utc(2026, 11, 12, 10, 30));
    });

    test('turning on again replaces the old marker', () async {
      await manager().turnOn();
      now = now.add(const Duration(minutes: 10));
      await manager().turnOn();
      final markers = router.tables['BYPASS_ALL']!.where((e) => decodeExpiryMarker(e) != null);
      expect(markers, hasLength(1));
      expect(decodeExpiryMarker(markers.single), DateTime.utc(2026, 11, 12, 12, 10));
    });

    test('turnOff flushes and clears local expiry', () async {
      await manager().turnOn();
      final s = await manager().turnOff();
      expect(s.active, isFalse);
      expect(router.tables['BYPASS_ALL'], isEmpty);
      expect(store.getString(localExpiryKey), isNull);
    });

    test('enforce turns bypass off once the deadline passed (e.g. app was closed)', () async {
      await manager().turnOn();
      now = now.add(const Duration(hours: 2, minutes: 1));
      final m = manager();
      final (action, state) = await m.enforce(await m.read());
      expect(action, EnforceAction.expiredTurnedOff);
      expect(state.active, isFalse);
      expect(router.tables['BYPASS_ALL'], isEmpty);
    });

    test('enforce leaves a running bypass alone before the deadline', () async {
      await manager().turnOn();
      now = now.add(const Duration(minutes: 119));
      final m = manager();
      final (action, state) = await m.enforce(await m.read());
      expect(action, EnforceAction.none);
      expect(state.active, isTrue);
    });

    test('bypass enabled elsewhere without deadline gets one', () async {
      router.tables['BYPASS_ALL']!.add('10.10.40.0/24');
      final m = manager();
      final (action, state) = await m.enforce(await m.read());
      expect(action, EnforceAction.adoptedWithNewDeadline);
      expect(state.expiresAt, DateTime.utc(2026, 11, 12, 12, 0));
      // Another device now sees the same deadline from the router.
      final other = BypassManager(client: router.client(), config: cfg, store: MemoryStore());
      expect((await other.read()).expiresAt, DateTime.utc(2026, 11, 12, 12, 0));
    });

    test('a different device enforces the deadline set by the first', () async {
      await manager().turnOn();
      now = now.add(const Duration(hours: 3));
      final phone = BypassManager(
          client: router.client(), config: cfg, store: MemoryStore(), clock: () => now);
      final (action, _) = await phone.enforce(await phone.read());
      expect(action, EnforceAction.expiredTurnedOff);
    });

    test('router reboot (table emptied) clears the stale local deadline', () async {
      await manager().turnOn();
      router.tables['BYPASS_ALL']!.clear();
      final m = manager();
      final (action, _) = await m.enforce(await m.read());
      expect(action, EnforceAction.clearedStaleLocal);
      expect(store.getString(localExpiryKey), isNull);
    });

    test('turnOff falls back to per-entry delete when flush is forbidden', () async {
      await manager().turnOn();
      router.forbidden.add('/api/firewall/alias_util/flush');
      await manager().turnOff();
      expect(router.tables['BYPASS_ALL'], isEmpty);
    });
  });

  group('state kill', () {
    test('filters survive the router sanitiser (no "/")', () {
      expect(stateKillFilter('10.10.40.50'), '10.10.40.50');
      expect(stateKillFilter('10.10.40.50/32'), '10.10.40.50');
      expect(stateKillFilter('10.10.40.0/24'), '10.10.40.');
      expect(stateKillFilter('10.10.40.0/25'), '10.10.40.');
      expect(stateKillFilter('10.10.0.0/16'), '10.10.');
      expect(stateKillFilter('10.0.0.0/8'), '10.');
      expect(() => stateKillFilter('nope'), throwsArgumentError);
    });

    test('bypass on, off and auto-expiry each kill the subnet states', () async {
      final router = FakeRouter();
      var now = DateTime.utc(2026, 11, 12, 10);
      final m = BypassManager(
          client: router.client(), config: cfg, store: MemoryStore(), clock: () => now);
      await m.turnOn();
      expect(router.killedFilters, ['10.10.40.']);
      expect(m.lastKill?.dropped, 3);
      await m.turnOff();
      expect(router.killedFilters, ['10.10.40.', '10.10.40.']);
      await m.turnOn();
      now = now.add(const Duration(hours: 3));
      await m.enforce(await m.read());
      expect(router.killedFilters, hasLength(4));
    });

    test('lost reply (own connection killed) counts as done', () async {
      final router = FakeRouter()..dropKillReply = true;
      final r = await killStatesFor(router.client(), '10.10.40.0/24');
      expect(r.warning, isNull);
      expect(r.dropped, isNull);
    });

    test('missing "Diagnostics: Show States" is a warning, not a failure', () async {
      final router = FakeRouter()..forbidden.add('/api/diagnostics/');
      final m = BypassManager(client: router.client(), config: cfg, store: MemoryStore());
      final s = await m.turnOn();
      expect(s.active, isTrue);
      expect(m.lastKill?.warning, contains('Show States'));
    });

    test('requests never use keep-alive', () async {
      final router = FakeRouter();
      await router.client().aliasList('BYPASS_ALL');
      expect(router.requests.single.persistentConnection, isFalse);
    });
  });

  group('PC mode', () {
    test('switch to CLEAR and back, confirmed by the router', () async {
      final router = FakeRouter();
      final c = router.client();
      final (on, kill) = await setPcMode(client: c, cfg: cfg, pcIp: '10.10.40.50', clear: true);
      expect(on, isTrue);
      expect(kill.dropped, 3);
      expect(router.tables['PCMODE_CLEAR'], ['10.10.40.50']);
      expect(isPcInClearAlias(router.tables['PCMODE_CLEAR']!, '10.10.40.50'), isTrue);
      final (off, _) = await setPcMode(client: c, cfg: cfg, pcIp: '10.10.40.50', clear: false);
      expect(off, isFalse);
      expect(router.tables['PCMODE_CLEAR'], isEmpty);
      // States are killed for the PC's own IP after each switch.
      expect(router.killedFilters, ['10.10.40.50', '10.10.40.50']);
      // Only alias_util (never /api/firewall/alias/) is used for the alias.
      expect(router.requests.where((r) => r.url.path.startsWith('/api/firewall/alias/')), isEmpty);
    });

    test('choosePcIp prefers the VPN network', () {
      expect(choosePcIp(['192.168.56.1', '10.10.20.7', '10.10.40.50'], cfg), '10.10.40.50');
      expect(choosePcIp(['192.168.56.1', '10.10.20.7'], cfg), '10.10.20.7');
      expect(choosePcIp(['192.168.56.1', '172.17.0.1'], cfg), isNull);
    });
  });
}
