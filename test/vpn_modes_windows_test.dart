import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/storage.dart';
import 'package:opnsense_cybervulcan/src/platform/vpn_modes_windows.dart';

// "Keys" are fixed byte sequences, not real WireGuard keys.
final _priv = base64.encode(List<int>.generate(32, (i) => i + 1));
final _pub = base64.encode(List<int>.generate(32, (i) => i + 33));
final _psk = base64.encode(List<int>.generate(32, (i) => i + 65));

AppConfig _cfg(String mode, {String homeDevices = ''}) => AppConfig(
      baseUrl: 'https://10.10.10.254',
      remoteEnabled: true,
      remoteMode: mode,
      homeDevices: homeDevices,
      wgEndpointHost: 'router.example.com',
      wgServerPublicKey: _pub,
      wgAddress: '10.10.99.2/32',
      wgKeepalive: 25,
    );

/// Scripted cvwg.dll.
class FakeHomeLink implements HomeLinkNative {
  FakeHomeLink({this.startReply = '{"ok":true}', List<String>? statuses})
      : statuses = statuses ?? ['{"state":"starting","mode":"home"}', '{"state":"on","mode":"home","rx":10,"tx":20}'];

  final String startReply;
  final List<String> statuses;
  final List<String> started = [];
  int stops = 0;

  @override
  String start(String requestJson) {
    started.add(requestJson);
    return startReply;
  }

  @override
  String status() => statuses.length > 1 ? statuses.removeAt(0) : statuses.first;

  @override
  void stop() => stops++;
}

void main() {
  const secrets = WireGuardSecrets(privateKey: 'x', presharedKey: null);

  group('HomeLinkRequest', () {
    test('app mode needs no adapter', () {
      expect(HomeLinkRequest.fromConfig(_cfg('app'), secrets, '203.0.113.7:51830'), isNull);
    });

    test('home mode carries the home devices and the router', () {
      final r = HomeLinkRequest.fromConfig(
          _cfg('home', homeDevices: '10.10.10.20, 192.168.50.0/24'),
          WireGuardSecrets(privateKey: _priv, presharedKey: _psk),
          '203.0.113.7:51830')!;
      expect(r.mode, 'home');
      expect(r.routerIp, '10.10.10.254');
      expect(r.homeCidrs, ['10.10.10.20/32', '192.168.50.0/24']);
      expect(r.endpoint, '203.0.113.7:51830');
      expect(r.peerPublicKey, _pub);
    });

    test('everything mode sends no home devices', () {
      final r = HomeLinkRequest.fromConfig(
          _cfg('everything', homeDevices: '10.10.10.20'), secrets, '203.0.113.7:51830')!;
      expect(r.mode, 'everything');
      expect(r.toJson().containsKey('homeCidrs'), isFalse);
    });

    test('JSON matches the Go contract fixture', () {
      final fixture = jsonDecode(File('test/fixtures/home_link_request.json').readAsStringSync())
          as Map<String, dynamic>;
      final r = HomeLinkRequest.fromConfig(
          _cfg('home', homeDevices: '10.10.10.20 192.168.50.0/24'),
          WireGuardSecrets(privateKey: _priv, presharedKey: _psk),
          '203.0.113.7:51830')!;
      expect(r.toJson(), fixture);
    });

    test('toString has no keys', () {
      final r = HomeLinkRequest.fromConfig(
          _cfg('everything'), WireGuardSecrets(privateKey: _priv, presharedKey: _psk), '203.0.113.7:51830')!;
      final s = r.toString();
      expect(s.contains(_priv), isFalse);
      expect(s.contains(_pub), isFalse);
      expect(s.contains(_psk), isFalse);
    });
  });

  group('HomeLinkStatus', () {
    test('parses helper status', () {
      final s = HomeLinkStatus.fromJson(
          jsonDecode('{"state":"on","mode":"everything","lastHandshake":1700000000,"rx":5,"tx":7}')
              as Map<String, dynamic>);
      expect(s.on, isTrue);
      expect(s.mode, 'everything');
      expect(s.rxBytes, 5);
      expect(s.txBytes, 7);
      expect(s.lastHandshake, DateTime.fromMillisecondsSinceEpoch(1700000000000, isUtc: true));
      expect(s.describe(), contains('all of this PC'));
    });

    test('unknown or missing state is off', () {
      expect(HomeLinkStatus.fromJson(const {}).state, HomeLinkState.off);
      expect(HomeLinkStatus.fromJson(const {'state': 'weird'}).state, HomeLinkState.off);
    });

    test('error state keeps the message', () {
      final s = HomeLinkStatus.fromJson(const {'state': 'error', 'error': 'No internet.'});
      expect(s.describe(), 'No internet.');
    });
  });

  group('WindowsVpnModes', () {
    final req = HomeLinkRequest.fromConfig(
        _cfg('home'), WireGuardSecrets(privateKey: _priv), '203.0.113.7:51830')!;

    test('start waits through the admin prompt until on', () async {
      final fake = FakeHomeLink();
      final m = WindowsVpnModes(fake, pollInterval: Duration.zero);
      final s = await m.start(req);
      expect(s.on, isTrue);
      expect(s.txBytes, 20);
      expect(jsonDecode(fake.started.single), req.toJson());
    });

    test('cancelled admin prompt is explained', () async {
      final fake = FakeHomeLink(statuses: [
        '{"state":"starting"}',
        '{"state":"error","error":"operation was canceled by the user"}',
      ]);
      final m = WindowsVpnModes(fake, pollInterval: Duration.zero);
      await expectLater(
          m.start(req),
          throwsA(isA<HomeLinkException>()
              .having((e) => e.message, 'message', contains('admin prompt was cancelled'))));
    });

    test('refused request is a plain error', () async {
      final fake = FakeHomeLink(startReply: '{"error":"router LAN IP \\"\\" is not a valid IPv4 address"}');
      final m = WindowsVpnModes(fake, pollInterval: Duration.zero);
      await expectLater(
          m.start(req),
          throwsA(isA<HomeLinkException>().having((e) => e.message, 'message', contains('router LAN IP'))));
    });

    test('unanswered prompt times out and stops', () async {
      final fake = FakeHomeLink(statuses: ['{"state":"starting"}']);
      final m = WindowsVpnModes(fake, pollInterval: Duration.zero);
      await expectLater(m.start(req, timeout: Duration.zero), throwsA(isA<HomeLinkException>()));
      expect(fake.stops, 1);
    });

    test('garbage from the library does not crash', () {
      final m = WindowsVpnModes(FakeHomeLink(statuses: ['not json']));
      expect(m.status().state, HomeLinkState.off);
    });

    test('unavailable without the library', () async {
      final m = WindowsVpnModes(null);
      expect(m.isAvailable, isFalse);
      expect(m.unavailableReason, isNotNull);
      expect(m.status(), HomeLinkStatus.off);
      await expectLater(m.start(req), throwsA(isA<HomeLinkException>()));
    });
  });

  test('friendly errors never show raw exceptions', () {
    expect(friendlyHomeLinkError(null), 'The home link could not be turned on.');
    expect(friendlyHomeLinkError('Exception: 0x80070005'), isNot(contains('0x')));
  });
}
