import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/core/controller.dart';
import 'package:opnsense_cybervulcan/src/core/storage.dart';
import 'package:opnsense_cybervulcan/src/net/router_link.dart';
import 'package:opnsense_cybervulcan/src/platform/app_lock.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'connection_test.dart' show FakeTunnel;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('app lock: unlock once per session, re-lock after time away, always-ask actions', () async {
    SharedPreferences.setMockInitialValues({});
    var now = DateTime(2026, 11, 20, 10);
    var prompts = 0;
    var answer = true;
    final c = CybervulcanController(
      prefs: await PrefsStore.open(),
      secrets: SecretStore(),
      supportsPcMode: false,
      clock: () => now,
      link: RouterLink(tunnel: FakeTunnel()),
    );
    c.authorizer = (_) async {
      prompts++;
      return answer;
    };

    // Lock off: nothing asks.
    expect(c.locked, isFalse);
    expect(await c.authorize('x', always: true), isTrue);
    expect(prompts, 0);

    c.config = c.config.copyWith(appLock: true, lockAfterMinutes: 5);
    expect(c.locked, isTrue);
    expect(await c.unlock(), isTrue);
    expect(prompts, 1);
    expect(c.locked, isFalse);

    // Inside the session: no prompt for bypass / CLEAR / settings ...
    expect(await c.authorize('bypass'), isTrue);
    expect(prompts, 1);
    // ... but turning the lock off / server changes always ask.
    expect(await c.authorize('lock off', always: true), isTrue);
    expect(prompts, 2);

    // Short trip to the background: still unlocked.
    c.appBackgrounded();
    now = now.add(const Duration(minutes: 2));
    c.appForegrounded();
    expect(c.locked, isFalse);

    // Long trip: locked - already while hidden (tray / widget shortcuts).
    c.appBackgrounded();
    now = now.add(const Duration(minutes: 6));
    expect(c.locked, isTrue);
    c.appForegrounded();
    expect(c.locked, isTrue);

    answer = false;
    expect(await c.authorize('bypass'), isFalse);
    expect(c.lastActionError, contains('Not unlocked'));
    expect(c.locked, isTrue);

    answer = true;
    expect(await c.authorize('bypass'), isTrue); // unlocks the session too
    expect(c.locked, isFalse);
    c.lockNow();
    expect(c.locked, isTrue);
    c.dispose();
  });

  test('app PIN is stored salted and checked in constant time', () {
    final h = hashPin('2468');
    expect(h, isNot(contains('2468')));
    expect(verifyPin('2468', h), isTrue);
    expect(verifyPin('2469', h), isFalse);
    expect(hashPin('2468'), isNot(h)); // random salt
    expect(verifyPin('2468', 'garbage'), isFalse);
    expect(validPin('123'), isFalse);
    expect(validPin('1234'), isTrue);
    expect(validPin('12a4'), isFalse);
  });
}
