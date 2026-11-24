import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/platform/vpn_modes.dart';
import 'package:opnsense_cybervulcan/src/platform/vpn_modes_windows.dart';

AppConfig _cfg(String mode, {String homeDevices = ''}) => AppConfig(
      baseUrl: 'https://10.10.10.254',
      remoteEnabled: true,
      remoteMode: mode,
      homeDevices: homeDevices,
      wgEndpointHost: 'router.example.com',
      wgEndpointPort: 51830,
      wgAddress: '10.10.99.2/32',
    );

Future<String> _resolver(String host, int port) async => '203.0.113.7:$port';

/// Scripted cvwg.dll.
class FakeHomeLink implements HomeLinkNative {
  FakeHomeLink({this.startReply = '{"ok":true}', List<String>? statuses})
      : statuses = statuses ??
            [
              '{"helper":{"state":"starting","mode":"home"},"vpn":{"up":false}}',
              '{"helper":{"state":"on","mode":"home"},"vpn":{"up":true,"mode":"home","transportUp":true,"rx":10,"tx":20}}',
            ];

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

WindowsSystemVpn _vpn(FakeHomeLink? fake, {Duration timeout = const Duration(minutes: 1)}) =>
    WindowsSystemVpn(fake, resolver: _resolver, pollInterval: Duration.zero, startTimeout: timeout);

void main() {
  group('helper request', () {
    test('home mode: home devices, router and endpoint', () {
      final cfg = _cfg('home', homeDevices: '10.10.10.20, 192.168.50.0/24');
      final r = HomeLinkHelperRequest.fromConfig(cfg, 'home', '203.0.113.7:51830');
      expect(r.routerIp, '10.10.10.254');
      expect(r.homeCidrs, ['10.10.10.20/32', '192.168.50.0/24']);
      expect(r.address, '10.10.99.2/32');
    });

    test('everything mode sends no home devices', () {
      final r = HomeLinkHelperRequest.fromConfig(_cfg('everything', homeDevices: '10.10.10.20'), 'everything', '203.0.113.7:51830');
      expect(r.toJson().containsKey('homeCidrs'), isFalse);
    });

    test('JSON matches the Go contract fixture', () {
      final fixture =
          jsonDecode(File('test/fixtures/home_link_request.json').readAsStringSync()) as Map<String, dynamic>;
      final r = HomeLinkHelperRequest.fromConfig(
          _cfg('home', homeDevices: '10.10.10.20 192.168.50.0/24'), 'home', '203.0.113.7:51830');
      expect(r.toJson(), fixture);
    });

    test('start JSON carries the VPN core part like Android', () {
      final cfg = _cfg('everything');
      final req = SystemVpnRequest.fromConfig(cfg);
      final j = jsonDecode(homeLinkStartJson(req, HomeLinkHelperRequest.fromConfig(cfg, 'everything', '203.0.113.7:51830')))
          as Map<String, dynamic>;
      expect((j['helper'] as Map)['mode'], 'everything');
      final v = j['vpn'] as Map;
      expect(v['allowed'], ['0.0.0.0/0']);
      expect(v['dns'], '10.10.10.254');
      expect(v['transport'], 'wireguard');
      expect(v['mtu'], 1280);
      // No keys anywhere: the tunnel runs in the app, not in the helper.
      expect(jsonEncode(j).toLowerCase().contains('key'), isFalse);
    });
  });

  group('status', () {
    test('running needs both the adapter and the VPN core', () {
      final s = homeLinkStatusFromJson(
          '{"helper":{"state":"on","mode":"home"},"vpn":{"up":true,"mode":"home","transportUp":true,"tcpActive":2,"rx":5,"tx":7}}');
      expect(s.running, isTrue);
      expect(s.transportUp, isTrue);
      expect(s.mode, 'home');
      expect(s.tcpActive, 2);
      expect(s.rxBytes, 5);
      expect(s.txBytes, 7);
      expect(s.lastError, isNull);
      expect(homeLinkStatusFromJson('{"helper":{"state":"starting"},"vpn":{"up":true}}').running, isFalse);
    });

    test('errors from either side are shown', () {
      expect(homeLinkStatusFromJson('{"helper":{"state":"error","error":"No internet."},"vpn":{}}').lastError,
          'No internet.');
      expect(homeLinkStatusFromJson('{"helper":{"state":"off"},"vpn":{"error":"remote access is not connected"}}').lastError,
          'remote access is not connected');
      expect(homeLinkStatusFromJson('{"helper":{"state":"off"},"vpn":{}}').lastError, isNull);
    });

    test('garbage is off', () {
      expect(homeLinkStatusFromJson('not json').running, isFalse);
      expect(homeLinkStatusFromJson('[]').running, isFalse);
    });
  });

  group('WindowsSystemVpn', () {
    final req = SystemVpnRequest.fromConfig(_cfg('home', homeDevices: '10.10.10.20'));

    test('start waits through the admin prompt until on', () async {
      final fake = FakeHomeLink();
      final vpn = _vpn(fake);
      expect(await vpn.prepare(), isTrue);
      await vpn.start(req);
      final sent = jsonDecode(fake.started.single) as Map<String, dynamic>;
      expect((sent['helper'] as Map)['endpoint'], '203.0.113.7:51830');
      expect((sent['helper'] as Map)['homeCidrs'], ['10.10.10.20/32']);
      final st = await vpn.status();
      expect(st.running, isTrue);
      expect(st.txBytes, 20);
    });

    test('cancelled admin prompt is explained', () async {
      final fake = FakeHomeLink(statuses: [
        '{"helper":{"state":"starting"},"vpn":{}}',
        '{"helper":{"state":"error","error":"operation was canceled by the user"},"vpn":{}}',
      ]);
      await expectLater(
          _vpn(fake).start(req),
          throwsA(isA<SystemVpnException>()
              .having((e) => e.message, 'message', contains('admin prompt was cancelled'))));
    });

    test('a failed start is not re-prompted by the poll loop until prepare', () async {
      final fake = FakeHomeLink(statuses: [
        '{"helper":{"state":"error","error":"operation was canceled by the user"},"vpn":{}}',
      ]);
      final vpn = _vpn(fake);
      await expectLater(vpn.start(req), throwsA(isA<SystemVpnException>()));
      await expectLater(vpn.start(req), throwsA(isA<SystemVpnException>()));
      expect(fake.started, hasLength(1));
      await vpn.prepare(); // "Try again"
      await expectLater(vpn.start(req), throwsA(isA<SystemVpnException>()));
      expect(fake.started, hasLength(2));
    });

    test('refused request is a plain error', () async {
      final fake = FakeHomeLink(startReply: '{"error":"router LAN IP \\"\\" is not a valid IPv4 address"}');
      await expectLater(_vpn(fake).start(req),
          throwsA(isA<SystemVpnException>().having((e) => e.message, 'message', contains('router LAN IP'))));
    });

    test('unanswered prompt times out and stops', () async {
      final fake = FakeHomeLink(statuses: ['{"helper":{"state":"starting"},"vpn":{}}']);
      await expectLater(_vpn(fake, timeout: Duration.zero).start(req), throwsA(isA<SystemVpnException>()));
      expect(fake.stops, 1);
    });

    test('endpoint that cannot be resolved', () async {
      final vpn = WindowsSystemVpn(FakeHomeLink(),
          resolver: (h, p) async => throw const SocketException('no'), pollInterval: Duration.zero);
      await expectLater(vpn.start(req),
          throwsA(isA<SystemVpnException>().having((e) => e.message, 'message', contains('router.example.com'))));
    });

    test('unavailable without the library', () async {
      final vpn = _vpn(null);
      expect(vpn.isSupported, isFalse);
      expect(vpn.unsupportedReason, isNotNull);
      expect(await vpn.prepare(), isFalse);
      expect((await vpn.status()).running, isFalse);
      await expectLater(vpn.start(req), throwsA(isA<SystemVpnException>()));
    });
  });

  test('friendly errors never show raw exceptions', () {
    expect(friendlyHomeLinkError(null), 'The home link could not be turned on.');
    expect(friendlyHomeLinkError('Exception: 0x80070005'), isNot(contains('0x')));
  });

  test('home link only from an all-users install (Program Files)', () {
    const env = {'ProgramFiles': r'C:\Program Files', 'ProgramFiles(x86)': r'C:\Program Files (x86)'};
    expect(installedForAllUsers(r'C:\Program Files\Cybervulcan\opnsense_cybervulcan.exe', env: env), isTrue);
    expect(installedForAllUsers(r'C:\Users\alex\AppData\Local\Programs\Cybervulcan\x.exe', env: env), isFalse);
    expect(installedForAllUsers(r'C:\Program Files Evil\x.exe', env: env), isFalse);
  });
}
