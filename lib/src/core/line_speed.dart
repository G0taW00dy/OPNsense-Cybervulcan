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

/// Cloudflare's speed test sometimes answers 429 (too many requests) for a
/// busy shared VPN exit - 23 Nov on a Proton Singapore exit for 15+ min.
/// Then downloads come from the nearest of these big public test files.
const _fallbackDownloads = [
  // Vultr's public test files answer from Proton exits (checked 23 Nov from
  // the Singapore exit; DigitalOcean's names no longer resolve, OVH/Linode
  // were too slow to answer).
  'https://sgp-ping.vultr.com/vultr.com.100MB.bin',
  'https://hnd-jp-ping.vultr.com/vultr.com.100MB.bin',
  'https://syd-au-ping.vultr.com/vultr.com.100MB.bin',
  'https://lax-ca-us-ping.vultr.com/vultr.com.100MB.bin',
  'https://fra-de-ping.vultr.com/vultr.com.100MB.bin',
]

DateTime? _cloudflareBlockedUntil;
String? _fallbackPick;

/// Opens one download stream for a speed test: Cloudflare, or after a 429
/// the fastest-answering public test file. Throws on other errors.
Future<http.StreamedResponse> openSpeedDownload(http.Client web) async {
  final blocked = _cloudflareBlockedUntil;
  if (blocked == null || DateTime.now().isAfter(blocked)) {
    final r = await web
        .send(http.Request('GET', Uri.parse('https://speed.cloudflare.com/__down?bytes=25000000')))
        .timeout(const Duration(seconds: 10));
    if (r.statusCode == 200) return r;
    unawaited(r.stream.drain<void>().catchError((Object _) {}));
    if (r.statusCode != 429 && r.statusCode != 403) throw Exception('download HTTP ${r.statusCode}');
    _cloudflareBlockedUntil = DateTime.now().add(const Duration(minutes: 30));
  }
  final pick = _fallbackPick ??= await _fastestFallback(web);
  final r = await web.send(http.Request('GET', Uri.parse(pick))).timeout(const Duration(seconds: 10));
  if (r.statusCode != 200) {
    _fallbackPick = null;
    throw Exception('download HTTP ${r.statusCode} (fallback)');
  }
  return r;
}

Future<String> _fastestFallback(http.Client web) async {
  final c = Completer<String>();
  var pending = _fallbackDownloads.length;
  for (final u in _fallbackDownloads) {
    final req = http.Request('GET', Uri.parse(u))..headers['Range'] = 'bytes=0-65535';
    unawaited(web.send(req).timeout(const Duration(seconds: 6)).then((r) async {
      await r.stream.drain<void>();
      if ((r.statusCode == 200 || r.statusCode == 206) && !c.isCompleted) c.complete(u);
    }).catchError((Object _) {}).whenComplete(() {
      if (--pending == 0 && !c.isCompleted) c.completeError(Exception('no speed test server answered'));
    }));
  }
  return c.future;
}

/// True when the last downloads came from a fallback (shown in results).
bool get speedTestUsedFallback => _cloudflareBlockedUntil != null && DateTime.now().isBefore(_cloudflareBlockedUntil!);

Future<({double down, double up})> measureSpeed(http.Client web,
    {int streams = 8, Duration each = const Duration(seconds: 12)}) async {
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
      final resp = await openSpeedDownload(web);
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
