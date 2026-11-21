import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/core/bypass.dart';
import 'package:opnsense_cybervulcan/src/net/tailscale_engine.dart';

void main() {
  setUp(() => TailscaleCrashGuard.store = MemoryStore());

  test('one unexplained close does not pause Tailscale (21 Nov false alarm)', () async {
    await TailscaleCrashGuard.starting();
    expect(await TailscaleCrashGuard.checkAtLaunch(), isFalse);
    expect(TailscaleCrashGuard.blocked, isFalse);
  });

  test('two in a row do', () async {
    await TailscaleCrashGuard.starting();
    await TailscaleCrashGuard.checkAtLaunch();
    await TailscaleCrashGuard.starting();
    expect(await TailscaleCrashGuard.checkAtLaunch(), isTrue);
    expect(TailscaleCrashGuard.blocked, isTrue);
  });

  test('a surviving start in between resets the count', () async {
    await TailscaleCrashGuard.starting();
    await TailscaleCrashGuard.checkAtLaunch();
    await TailscaleCrashGuard.starting();
    await TailscaleCrashGuard.survived();
    await TailscaleCrashGuard.starting();
    expect(await TailscaleCrashGuard.checkAtLaunch(), isFalse);
  });

  test('a real native crash pauses straight away', () async {
    await TailscaleCrashGuard.starting();
    expect(await TailscaleCrashGuard.checkAtLaunch(nativeCrash: true), isTrue);
    expect(TailscaleCrashGuard.blocked, isTrue);
  });
}
