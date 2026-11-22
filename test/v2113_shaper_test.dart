import 'package:flutter_test/flutter_test.dart';
import 'package:opnsense_cybervulcan/src/api/shaper_models.dart';

void main() {
  const pipes = [
    ShaperPipe(uuid: 'pvd', number: 1, description: 'VPN download (NBN)', mbit: 410, enabled: true),
    ShaperPipe(uuid: 'pvu', number: 2, description: 'VPN upload (NBN)', mbit: 48, enabled: true),
    ShaperPipe(uuid: 'pcd', number: 3, description: 'CLEAR download (NBN)', mbit: 540, enabled: false),
    ShaperPipe(uuid: 'pcu', number: 4, description: 'CLEAR upload (NBN)', mbit: 52, enabled: false),
  ];
  const queues = [
    ShaperQueue(uuid: 'qvd', pipe: 'pvd', description: 'VPN download queue', enabled: true),
    ShaperQueue(uuid: 'qvu', pipe: 'pvu', description: 'VPN upload queue', enabled: true),
    ShaperQueue(uuid: 'qcd', pipe: 'pcd', description: 'CLEAR download queue', enabled: true),
    ShaperQueue(uuid: 'qcu', pipe: 'pcu', description: 'CLEAR upload queue', enabled: true),
  ];
  ShaperRule r(String iface, String dir, String q, {bool on = true}) =>
      ShaperRule(uuid: '$iface$dir$q', enabled: on, interface: iface, direction: dir, target: q, description: '');
  final exitPath = [
    r('opt5', 'in', 'qvd'), r('opt5', 'out', 'qvu'), r('opt6', 'in', 'qvd'), r('opt6', 'out', 'qvu'),
    r('wan', 'in', 'qcd'), r('wan', 'out', 'qcu'),
  ];

  test('pipes are found switched on or off', () {
    expect(findClearPipesAny(pipes)?.down.uuid, 'pcd');
    expect(findClearPipes(pipes), isNull); // the old finder needs them on
    expect(findVpnPipesAny(pipes)?.up.uuid, 'pvu');
  });

  test('exit-path layout is recognised', () {
    expect(
        classifyShaperLayout(rules: exitPath, queues: queues, pipes: pipes, tunnelIfaces: {'opt5', 'opt6'}),
        ShaperLayout.exitPath);
  });

  test('rules by source network are not exit-path (22 Nov: PC on CLEAR held to the VPN limit)', () {
    final old = [r('opt3', 'out', 'qvd'), r('opt3', 'in', 'qvu'), r('opt1', 'out', 'qcd'), r('opt1', 'in', 'qcu')];
    expect(classifyShaperLayout(rules: old, queues: queues, pipes: pipes, tunnelIfaces: {'opt5', 'opt6'}),
        ShaperLayout.other);
    // Old rules left on next to the new ones would shape twice.
    expect(
        classifyShaperLayout(rules: [...exitPath, ...old], queues: queues, pipes: pipes, tunnelIfaces: {'opt5', 'opt6'}),
        ShaperLayout.other);
    // Switched-off old rules don't count.
    expect(
        classifyShaperLayout(
            rules: [...exitPath, for (final o in old) r(o.interface, o.direction, o.target, on: false)],
            queues: queues,
            pipes: pipes,
            tunnelIfaces: {'opt5', 'opt6'}),
        ShaperLayout.exitPath);
  });

  test('a missing backup tunnel rule is not exit-path; no rules is none', () {
    final partial = exitPath.where((x) => x.interface != 'opt6').toList();
    expect(classifyShaperLayout(rules: partial, queues: queues, pipes: pipes, tunnelIfaces: {'opt5', 'opt6'}),
        ShaperLayout.other);
    expect(classifyShaperLayout(rules: const [], queues: queues, pipes: pipes, tunnelIfaces: {'opt5', 'opt6'}),
        ShaperLayout.none);
  });

  test('recommended limits match the 22 Nov house tuning', () {
    // Tunnel unshaped 413/47 -> 410/48 was flat; 413/47 recommended.
    final t = recommendedLimits(tunnel: true, downMbps: 413, upMbps: 46.7);
    expect(t.down, 413);
    expect(t.up, 47);
    // Line 549/53.5 -> 540/52 was flat.
    final l = recommendedLimits(tunnel: false, downMbps: 549, upMbps: 53.5);
    expect(l.down, 538);
    expect(l.up, 52);
    expect(expectedRealMbps(tunnel: true, limit: 410), 336);
    expect(expectedRealMbps(tunnel: false, limit: 540), 524);
  });
}
