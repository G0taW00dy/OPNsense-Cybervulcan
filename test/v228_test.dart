import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/network_map.dart';
import 'package:opnsense_cybervulcan/src/core/remote_modes.dart';
import 'package:opnsense_cybervulcan/src/core/security_tests.dart';
import 'package:opnsense_cybervulcan/src/ui/app.dart' show ignoreUnknownRoute;

void main() {
  group('Widget tap - no "Null check" (v2.2.8)', () {
    test('Flutter deep linking is off for the main activity', () {
      final manifest = File('android/app/src/main/AndroidManifest.xml').readAsStringSync();
      expect(manifest, contains('flutter_deeplinking_enabled'));
      expect(RegExp(r'flutter_deeplinking_enabled"\s*android:value="false"').hasMatch(manifest), isTrue);
    });

    testWidgets('an unknown route name is ignored and the home page stays', (tester) async {
      await tester.pumpWidget(const MaterialApp(home: Text('home'), onUnknownRoute: ignoreUnknownRoute));
      final nav = tester.state<NavigatorState>(find.byType(Navigator));
      nav.pushNamed('/bypass/confirm');
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      expect(find.text('home'), findsOneWidget);
      expect(nav.canPop(), isFalse);
    });
  });

  group('Reach a woken device from away (v2.2.8)', () {
    test('nothing to say at home', () {
      expect(reachFromHereHint(cfg: const AppConfig(), remote: false, ip: '10.10.40.50'), isNull);
    });
    test('App only: switch to Home devices', () {
      final h = reachFromHereHint(cfg: const AppConfig(remoteMode: 'app'), remote: true, ip: '10.10.40.50');
      expect(h, contains('"Home devices"'));
      expect(h, contains('10.10.40.50'));
    });
    test('Home devices without this address: add it', () {
      const cfg = AppConfig(remoteMode: 'home', homeDevices: '10.10.10.5');
      expect(reachFromHereHint(cfg: cfg, remote: true, ip: '10.10.40.50'), contains('Add 10.10.40.50'));
    });
    test('Home devices covering it (also via a subnet): nothing to say', () {
      expect(
          reachFromHereHint(
              cfg: const AppConfig(remoteMode: 'home', homeDevices: '10.10.40.50'), remote: true, ip: '10.10.40.50'),
          isNull);
      expect(
          reachFromHereHint(
              cfg: const AppConfig(remoteMode: 'home', homeDevices: '10.10.40.0/24'), remote: true, ip: '10.10.40.50'),
          isNull);
    });
  });

  group('Bufferbloat wording on a house network (v2.2.8)', () {
    test('on the IoT Wi-Fi it is at home, not away', () {
      final n = notDirectlyHomeNote('10.10.50.162', defaultNetworks);
      expect(n, contains('at home on the IOT network'));
      expect(n, isNot(contains('away')));
    });
    test('outside the house networks it is away', () {
      expect(notDirectlyHomeNote('192.168.1.20', defaultNetworks), contains('away from home'));
      expect(notDirectlyHomeNote(null, defaultNetworks), contains('away from home'));
    });
  });
}
