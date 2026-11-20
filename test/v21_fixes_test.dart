import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/api/models.dart';
import 'package:opnsense_cybervulcan/src/core/config.dart';
import 'package:opnsense_cybervulcan/src/core/security_tests.dart';
import 'package:opnsense_cybervulcan/src/core/server_switcher.dart';

import 'fake_router.dart';

/// Regression tests for the bugs found while testing v2.0.4 on 20 Nov 2026.
void main() {
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
    expect(isQuad9Org('ExampleTel'), isFalse);
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
}
