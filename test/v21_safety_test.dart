import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/api/shaper_models.dart';
import 'package:opnsense_cybervulcan/src/core/bypass.dart';
import 'package:opnsense_cybervulcan/src/core/change_journal.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/diagnostics.dart';
import 'package:opnsense_cybervulcan/src/core/shaper_tuner.dart';

import 'fake_router.dart';

void main() {
  const cfg = AppConfig(shaperMinDown: 20, shaperMaxDown: 80, shaperMinUp: 3, shaperMaxUp: 15);

  group('shaper auto-tune decisions', () {
    test('lag while downloading lowers download only', () {
      final d = decideTune(delayMs: 400, baselineMs: 250, rateDownMbit: 55, rateUpMbit: 1, down: 60, up: 10, cfg: cfg);
      expect(d.down, 51);
      expect(d.up, isNull);
    });

    test('busy with low lag raises a little, within max', () {
      final d = decideTune(delayMs: 260, baselineMs: 250, rateDownMbit: 50, rateUpMbit: 9, down: 60, up: 10, cfg: cfg);
      expect(d.down, 65);
      expect(d.up, 11);
      final top = decideTune(delayMs: 255, baselineMs: 250, rateDownMbit: 79, rateUpMbit: 0, down: 80, up: 10, cfg: cfg);
      expect(top.down, isNull); // already at max
    });

    test('lag without VPN load is not the shaper\'s doing', () {
      final d = decideTune(delayMs: 600, baselineMs: 250, rateDownMbit: 2, rateUpMbit: 0.5, down: 60, up: 10, cfg: cfg);
      expect(d.changes, isFalse);
      expect(d.reason, contains('not the shaper'));
    });

    test('never below min', () {
      final d = decideTune(delayMs: 900, baselineMs: 250, rateDownMbit: 20, rateUpMbit: 3, down: 21, up: 3, cfg: cfg);
      expect(d.down, 20);
      expect(d.up, isNull); // 3 is the floor already
    });

    test('baseline is the recent quiet minimum and resets after a switch', () {
      final b = DelayBaseline();
      final t0 = DateTime(2026, 11, 20, 22);
      b.add(t0, 260);
      b.add(t0.add(const Duration(minutes: 1)), 248);
      b.add(t0.add(const Duration(minutes: 2)), 270);
      expect(b.value, 248);
      b.add(t0.add(const Duration(minutes: 13)), 300); // the old ones fall out
      expect(b.value, 300);
      b.reset();
      expect(b.value, isNull);
    });
  });

  group('shaper on the fake router', () {
    test('finds the VPN pipes and counts bytes per pipe', () async {
      final r = FakeRouter()..pipeBytes = {10000: 5000, 10001: 700};
      final c = r.client();
      final pipes = findVpnPipes(await c.shaperPipes())!;
      expect(pipes.down.mbit, 60);
      expect(pipes.up.number, 10001);
      expect(await c.shaperBytes(), {10000: 5000, 10001: 700});
    });

    test('tuner lowers the busy direction when lag builds', () async {
      final r = FakeRouter();
      var now = DateTime(2026, 11, 20, 22);
      final tuner = ShaperTuner(clock: () => now, minGap: Duration.zero);
      final c = r.client();
      // Quiet line: baseline 250 ms.
      expect(await tuner.tick(c, cfg, 250), isNull);
      now = now.add(const Duration(seconds: 15));
      expect(await tuner.tick(c, cfg, 252), isNull);
      // Download at ~56 Mbit/s for 15 s, lag +200 ms.
      r.pipeBytes[10000] = r.pipeBytes[10000]! + 56 * 1000000 ~/ 8 * 15;
      now = now.add(const Duration(seconds: 15));
      final d = await tuner.tick(c, cfg, 450);
      expect(d?.down, 51);
      expect(r.pipes[0]['bandwidth'], '51');
      expect(r.pipes[1]['bandwidth'], '10');
      expect(r.shaperReconfigures, 1);
    });
  });

  group('safety net journal & diagnostics', () {
    test('journal keeps the newest entries', () async {
      final j = ChangeJournal(MemoryStore(), max: 3);
      for (var i = 0; i < 5; i++) {
        await j.add('change $i', ok: i.isEven);
      }
      expect(j.entries.map((e) => e.what), ['change 4', 'change 3', 'change 2']);
      expect(j.entries.first.ok, isTrue);
    });

    test('redaction blanks public IPs, domains and keys but keeps house addresses', () {
      final s = redact('router.cybervulcan.com 149.102.228.1 10.10.40.51 100.126.109.85 '
          'K4Fask4dC1qurL9ElSTyhKUZ//vtxESEvrKXh0xFQzs= speed.cloudflare.com controller.dart ApiErrorKind.forbidden');
      expect(s, isNot(contains('cybervulcan.com')));
      expect(s, isNot(contains('149.102.228.1')));
      expect(s, isNot(contains('K4Fask')));
      expect(s, contains('10.10.40.51'));
      expect(s, contains('100.126.109.85'));
      expect(s, contains('speed.cloudflare.com'));
      expect(s, contains('controller.dart'));
      expect(s, contains('ApiErrorKind.forbidden'));
      expect(redact('endpoint [2a02:6ea0:c803:5949::10]:51820'), isNot(contains('2a02')));
      expect(redact('local fe80::1 ok'), contains('fe80::1'));
    });

    test('error log is redacted and bounded', () async {
      final log = ErrorLog(MemoryStore(), max: 2);
      await log.add(Exception('cannot reach 203.0.113.9 at home.example.net'), StackTrace.current);
      await log.add(Exception('two'), null);
      await log.add(Exception('three'), null);
      expect(log.entries.length, 2);
      expect(log.entries.join(), isNot(contains('203.0.113.9')));
    });
  });
}
