/// Plain speed test for "Measure" on the shaper (v2.1.13): eight parallel
/// streams each way to Cloudflare's speed test, like the Tests page.
///
/// It measures the path THIS device uses now (tunnel when on the VPN, the
/// direct line when on CLEAR or bypass). Speed test sites with servers close
/// to the VPN exit often show more, so the user can type their own figures.
library;

import 'dart:async';
import 'dart:math';

import 'package:http/http.dart' as http;

Future<({double down, double up})> measureSpeed(http.Client web,
    {int streams = 16, Duration each = const Duration(seconds: 12)}) async {
  Future<double> run(Future<void> Function(void Function(int) count, bool Function() stop) one) async {
    var bytes = 0;
    final sw = Stopwatch()..start();
    bool stop() => sw.elapsed > each;
    await Future.wait([
      for (var i = 0; i < streams; i++) one((n) => bytes += n, stop).catchError((Object _) {}),
    ]).timeout(each + const Duration(seconds: 8), onTimeout: () => const <void>[]);
    sw.stop();
    return bytes * 8 / max(sw.elapsedMilliseconds / 1000, 0.5) / 1e6;
  }

  final down = await run((count, stop) async {
    while (!stop()) {
      final resp = await web
          .send(http.Request('GET', Uri.parse('https://speed.cloudflare.com/__down?bytes=25000000')))
          .timeout(const Duration(seconds: 10));
      if (resp.statusCode != 200) throw Exception('download HTTP ${resp.statusCode}');
      await for (final chunk in resp.stream) {
        count(chunk.length);
        if (stop()) break;
      }
    }
  });
  final piece = List<int>.filled(256 << 10, 0x61);
  final up = await run((count, stop) async {
    while (!stop()) {
      final r = await web.post(Uri.parse('https://speed.cloudflare.com/__up'), body: piece).timeout(const Duration(seconds: 20));
      if (r.statusCode >= 400) throw Exception('upload HTTP ${r.statusCode}');
      count(piece.length);
    }
  });
  return (down: down, up: up);
}
