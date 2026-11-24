import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/core/router_pacing.dart';

void main() {
  group('Router write pacing (v2.2.7)', () {
    test('no gap before the first write, the gap before the next ones', () async {
      final slept = <Duration>[];
      final p = RouterWritePacer(probe: () async {}, sleep: (d) async => slept.add(d));
      expect(await p.beforeWrite(0), isTrue);
      expect(slept, isEmpty);
      expect(await p.beforeWrite(1), isTrue);
      expect(slept, [RouterWritePacer.defaultGap]);
      expect(RouterWritePacer.defaultGap, const Duration(seconds: 5));
    });

    test('a slow read stops the writes', () async {
      var now = DateTime(2026, 11, 24, 14, 28);
      final p = RouterWritePacer(
        probe: () async => now = now.add(const Duration(seconds: 6)),
        sleep: (_) async {},
        clock: () => now,
      );
      expect(await p.beforeWrite(0), isFalse);
    });

    test('a failing read stops the writes', () async {
      final p = RouterWritePacer(probe: () async => throw Exception('503'), sleep: (_) async {});
      expect(await p.beforeWrite(0), isFalse);
    });

    test('a quick read lets the write go ahead', () async {
      var now = DateTime(2026, 11, 24);
      final p = RouterWritePacer(
        probe: () async => now = now.add(const Duration(milliseconds: 300)),
        sleep: (_) async {},
        clock: () => now,
      );
      expect(await p.beforeWrite(3), isTrue);
    });
  });

  group('Poll back-off (v2.2.7)', () {
    const s15 = Duration(seconds: 15);
    test('normal rate while the router answers quickly', () {
      expect(backedOffPollInterval(s15, 0), s15);
    });
    test('doubles per slow poll, capped at 5 minutes', () {
      expect(backedOffPollInterval(s15, 1), const Duration(seconds: 30));
      expect(backedOffPollInterval(s15, 2), const Duration(minutes: 1));
      expect(backedOffPollInterval(s15, 4), const Duration(minutes: 4));
      expect(backedOffPollInterval(s15, 5), const Duration(minutes: 5));
      expect(backedOffPollInterval(s15, 10), const Duration(minutes: 5));
    });
    test('a setting already slower than the cap is kept', () {
      expect(backedOffPollInterval(const Duration(minutes: 10), 3), const Duration(minutes: 10));
    });
  });

  group('Router watchdog (v2.2.7)', () {
    final script = File('router/install.sh').readAsStringSync();
    test('installs the watchdog and its cron-able action', () {
      expect(script, contains('/usr/local/sbin/cybervulcan-api-watchdog'));
      expect(script, contains('[api.watchdog]'));
    });
    test('only ever stops the stuck service-status calls', () {
      expect(script, contains("'pluginctl -S'"));
      expect(script, isNot(contains('kill -9 1 ')));
      expect(script, isNot(contains('killall')));
    });
  });
}
