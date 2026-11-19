import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

import '../api/models.dart';
import '../api/opnsense_client.dart';
import '../api/wireguard_models.dart';
import 'config.dart';

/// Proton server switcher (v2.0).
///
/// The router keeps its WireGuard private keys; the app only ever changes a
/// peer's endpoint address, port and the server's *public* key. Proton
/// accepts an account's WireGuard key on any of its servers, so moving a
/// tunnel to another server is just "point the peer somewhere else".
///
/// "Find best" never touches the main tunnel while testing: each candidate is
/// tried on the BACKUP tunnel and measured through the router's own gateway
/// monitor (dpinger: latency, jitter, loss). The house keeps using the main
/// tunnel throughout. Only at the end is the winner moved to main (if it is
/// clearly better) and the runner-up left on backup.

/// One Proton server that a peer can point at.
class ProtonServer {
  const ProtonServer({
    required this.name,
    required this.entryIp,
    required this.publicKey,
    this.port = 51820,
    this.city,
    this.country,
    this.load,
    this.score,
  });

  final String name;
  final String entryIp;
  final String publicKey;
  final int port;
  final String? city;
  final String? country;

  /// Proton's load in percent (0-100), when known.
  final int? load;

  /// Proton's own score (lower is better), when known.
  final double? score;

  String get label => [name, if (city != null) city, if (load != null) '$load% load'].join(' - ');

  Map<String, dynamic> toJson() => {
        'name': name,
        'entryIp': entryIp,
        'publicKey': publicKey,
        'port': port,
        'city': city,
        'country': country,
        'load': load,
        'score': score,
      };

  static ProtonServer? fromJson(Object? j) {
    if (j is! Map) return null;
    final ip = '${j['entryIp'] ?? ''}';
    final key = '${j['publicKey'] ?? ''}';
    if (InternetAddress.tryParse(ip) == null || !isWgPublicKey(key)) return null;
    return ProtonServer(
      name: '${j['name'] ?? ip}',
      entryIp: ip,
      publicKey: key,
      port: j['port'] is num ? (j['port'] as num).toInt() : 51820,
      city: j['city']?.toString(),
      country: j['country']?.toString(),
      load: j['load'] is num ? (j['load'] as num).toInt() : null,
      score: j['score'] is num ? (j['score'] as num).toDouble() : null,
    );
  }

  bool sameEndpoint(String address, String key) => entryIp == address.trim() && publicKey == key.trim();
}

/// Where a tunnel points right now (public data only).
class WgPeerInfo {
  const WgPeerInfo(this.address, this.port, this.publicKey);
  final String address;
  final int port;
  final String publicKey;

  /// Matching server from a list (same endpoint IP + key), if any.
  ProtonServer? match(Iterable<ProtonServer> servers) {
    for (final s in servers) {
      if (s.sameEndpoint(address, publicKey)) return s;
    }
    return null;
  }
}

bool isWgPublicKey(String? k) => k != null && RegExp(r'^[A-Za-z0-9+/]{43}=$').hasMatch(k.trim());

/// Parses Proton's `/vpn/logicals` answer: one entry per online physical
/// server of an online logical server (Plus tier and up, no Secure Core).
List<ProtonServer> parseProtonLogicals(Object? json, {String? country}) {
  if (json is! Map) return const [];
  final list = json['LogicalServers'];
  if (list is! List) return const [];
  final out = <ProtonServer>[];
  for (final l in list) {
    if (l is! Map) continue;
    if (l['Status'] != 1) continue;
    final tier = l['Tier'];
    if (tier is num && tier < 2) continue;
    final features = l['Features'];
    if (features is num && (features.toInt() & 1) == 1) continue; // Secure Core
    final exit = '${l['ExitCountry'] ?? ''}'.toUpperCase();
    if (country != null && country.isNotEmpty && exit != country.toUpperCase()) continue;
    final servers = l['Servers'];
    if (servers is! List) continue;
    for (final s in servers) {
      if (s is! Map || s['Status'] != 1) continue;
      final ip = '${s['EntryIP'] ?? ''}';
      final key = '${s['X25519PublicKey'] ?? ''}';
      if (InternetAddress.tryParse(ip) == null || !isWgPublicKey(key)) continue;
      out.add(ProtonServer(
        name: '${l['Name'] ?? ip}',
        entryIp: ip,
        publicKey: key,
        city: l['City']?.toString(),
        country: exit.isEmpty ? null : exit,
        load: l['Load'] is num ? (l['Load'] as num).toInt() : null,
        score: l['Score'] is num ? (l['Score'] as num).toDouble() : null,
      ));
      break; // one physical server per logical server is plenty
    }
  }
  return out;
}

/// Reads the public parts of a Proton WireGuard `.conf` (or any wg-quick
/// file): the [Peer] public key and endpoint. The [Interface] private key is
/// deliberately ignored and never stored - the router already has its own.
/// Returns null when the text has no usable peer.
ProtonServer? serverFromWireGuardConf(String text, {String? fallbackName}) {
  String? section;
  String? key;
  String? endpoint;
  String? name;
  for (final raw in const LineSplitter().convert(text)) {
    final line = raw.trim();
    if (line.startsWith('[')) {
      section = line.toLowerCase();
      continue;
    }
    if (line.startsWith('#')) {
      // Proton writes e.g. "# US-CA#123" above the peer, and "# Key for ..." above the interface.
      final c = line.substring(1).trim();
      if (section == '[peer]' || (name == null && RegExp(r'^[A-Z]{2}[-#]').hasMatch(c))) name ??= c;
      continue;
    }
    final eq = line.indexOf('=');
    if (eq < 0 || section != '[peer]') continue;
    final k = line.substring(0, eq).trim().toLowerCase();
    final v = line.substring(eq + 1).trim();
    if (k == 'publickey') key = v;
    if (k == 'endpoint') endpoint = v;
  }
  if (!isWgPublicKey(key) || endpoint == null) return null;
  final colon = endpoint.lastIndexOf(':');
  final host = (colon > 0 ? endpoint.substring(0, colon) : endpoint).replaceAll(RegExp(r'[\[\]]'), '');
  final port = colon > 0 ? int.tryParse(endpoint.substring(colon + 1)) ?? 51820 : 51820;
  if (InternetAddress.tryParse(host) == null) return null;
  return ProtonServer(name: name ?? fallbackName ?? host, entryIp: host, publicKey: key!, port: port);
}

/// Candidates for "find best": servers in the chosen cities, least loaded
/// first, at most [max]. Without a city list every server qualifies.
List<ProtonServer> pickCandidates(List<ProtonServer> all, List<String> cities, {int max = 3}) {
  final wanted = cities.map((c) => c.toLowerCase()).toSet();
  final pool = [
    for (final s in all)
      if (wanted.isEmpty || wanted.contains((s.city ?? '').toLowerCase())) s,
  ]..sort((a, b) => (a.load ?? 100).compareTo(b.load ?? 100));
  // Spread over the cities first, then fill up by load.
  final out = <ProtonServer>[];
  final seenCity = <String>{};
  for (final s in pool) {
    if (out.length >= max) break;
    if (seenCity.add((s.city ?? '').toLowerCase())) out.add(s);
  }
  for (final s in pool) {
    if (out.length >= max) break;
    if (!out.contains(s)) out.add(s);
  }
  return out;
}

/// One measured server.
class ServerMeasurement {
  const ServerMeasurement(this.server, {this.delayMs, this.jitterMs, this.lossPercent, this.error});

  final ProtonServer server;
  final double? delayMs;
  final double? jitterMs;
  final double? lossPercent;
  final String? error;

  bool get ok => error == null && delayMs != null;

  /// Lower is better: latency, plus jitter twice (gaming), plus loss heavily.
  double get score =>
      ok ? delayMs! + 2 * (jitterMs ?? 0) + 50 * (lossPercent ?? 0) : double.infinity;

  String describe() => ok
      ? '${delayMs!.toStringAsFixed(0)} ms, jitter ${(jitterMs ?? 0).toStringAsFixed(1)} ms, '
          'loss ${(lossPercent ?? 0).toStringAsFixed(1)} %'
      : 'failed: ${error ?? 'no data'}';
}

/// Averages gateway samples; null fields when the gateway reported nothing.
ServerMeasurement summarise(ProtonServer server, List<GatewayStatus> samples) {
  final up = samples.where((g) => g.health.isUp && g.delayMs != null).toList();
  if (up.isEmpty) {
    return ServerMeasurement(server, error: samples.isEmpty ? 'no gateway data' : 'tunnel did not come up');
  }
  double avg(Iterable<double?> v) {
    final xs = v.whereType<double>().toList();
    return xs.isEmpty ? 0 : xs.reduce((a, b) => a + b) / xs.length;
  }

  return ServerMeasurement(server,
      delayMs: avg(up.map((g) => g.delayMs)),
      jitterMs: avg(up.map((g) => g.stddevMs)),
      lossPercent: avg(up.map((g) => g.lossPercent)));
}

/// What "find best" decided.
class BestServerPlan {
  const BestServerPlan({required this.newMain, required this.newBackup, required this.changeMain, required this.reason});

  final ServerMeasurement newMain;
  final ServerMeasurement? newBackup;
  final bool changeMain;
  final String reason;
}

/// Picks main + backup from measurements. The current main is only replaced
/// when a candidate beats it by at least [minGain] (default 10 %), so the
/// house does not flap between servers that are basically equal.
BestServerPlan? planBest(ServerMeasurement current, List<ServerMeasurement> candidates, {double minGain = 0.10}) {
  final good = [...candidates.where((m) => m.ok)]..sort((a, b) => a.score.compareTo(b.score));
  if (good.isEmpty) return null;
  final best = good.first;
  final change = !current.ok || best.score < current.score * (1 - minGain);
  final main = change ? best : current;
  // Backup: best remaining, preferring another city (a city outage then
  // doesn't take both tunnels).
  final rest = good.where((m) => !identical(m, main) && m.server.entryIp != main.server.entryIp).toList();
  final otherCity = rest.where((m) => (m.server.city ?? '?') != (main.server.city ?? '!')).toList();
  final backup = otherCity.isNotEmpty ? otherCity.first : (rest.isNotEmpty ? rest.first : null);
  final reason = change
      ? (current.ok
          ? '${best.server.name} scores ${best.score.toStringAsFixed(0)} vs ${current.score.toStringAsFixed(0)} '
              'for the current main - switching.'
          : 'The current main is not working - switching to ${best.server.name}.')
      : 'The current main (${current.server.name}) is within ${(minGain * 100).round()} % of the best - keeping it.';
  return BestServerPlan(newMain: main, newBackup: backup, changeMain: change, reason: reason);
}

/// Downloads Proton's public server list. Proton has no official public API
/// for this, so it may change or need sign-in; then use "Add from .conf".
Future<List<ProtonServer>> fetchProtonServers(http.Client client, {String? country}) async {
  const urls = [
    'https://api.protonvpn.ch/vpn/logicals',
    'https://vpn-api.proton.me/vpn/logicals',
  ];
  Object? lastError;
  for (final u in urls) {
    try {
      final r = await client.get(Uri.parse(u), headers: const {
        'Accept': 'application/json',
        'x-pm-appversion': 'linux-vpn-cli@4.0.0',
      }).timeout(const Duration(seconds: 15));
      if (r.statusCode != 200) {
        lastError = 'HTTP ${r.statusCode} from ${Uri.parse(u).host}';
        continue;
      }
      final list = parseProtonLogicals(jsonDecode(r.body), country: country);
      if (list.isNotEmpty) return list;
      lastError = 'empty server list from ${Uri.parse(u).host}';
    } on Object catch (e) {
      lastError = e;
    }
  }
  throw Exception('Could not download the Proton server list ($lastError). '
      'Add servers from Proton WireGuard .conf files instead.');
}

typedef Sleep = Future<void> Function(Duration d);

/// Runs server changes against the router. Needs the "VPN: WireGuard"
/// privilege plus "System: Gateways" (already used for status).
class ServerSwitcher {
  ServerSwitcher({
    required this.client,
    required this.config,
    Sleep? sleep,
    this.settle = const Duration(seconds: 75),
    this.samples = 3,
    this.sampleGap = const Duration(seconds: 5),
  }) : _sleep = sleep ?? Future<void>.delayed;

  final OpnsenseClient client;
  final AppConfig config;
  final Sleep _sleep;

  /// Wait after a change before measuring (dpinger averages over ~60 s).
  final Duration settle;
  final int samples;
  final Duration sampleGap;

  bool _cancelled = false;
  void cancel() => _cancelled = true;

  Future<(WgPeer main, WgPeer backup)> peers() async {
    final all = await client.wgPeers();
    WgPeer find(String instance, String which) => all.firstWhere((p) => p.belongsTo(instance),
        orElse: () => throw OpnsenseException(ApiErrorKind.badResponse,
            'No WireGuard peer on instance "$instance" ($which) - check Settings > VPN tunnels.'));
    return (find(config.mainWgInstance, 'main'), find(config.backupWgInstance, 'backup'));
  }

  ProtonServer _asServer(WgPeer p, String label) => ProtonServer(
      name: '$label (${p.serverAddress})', entryIp: p.serverAddress, publicKey: p.publicKey, port: p.serverPort);

  /// Points one tunnel at [server] and applies it.
  Future<void> apply(WgPeer peer, ProtonServer server) async {
    await client.setWgPeerServer(peer.uuid, address: server.entryIp, port: server.port, publicKey: server.publicKey);
    await client.wgReconfigure();
  }

  Future<ServerMeasurement> _measure(String gateway, ProtonServer server, void Function(String) log) async {
    final got = <GatewayStatus>[];
    for (var i = 0; i < samples && !_cancelled; i++) {
      if (i > 0) await _sleep(sampleGap);
      try {
        final gws = await client.gatewayStatus();
        final g = gws.where((g) => g.name == gateway);
        if (g.isNotEmpty) got.add(g.first);
      } on OpnsenseException catch (e) {
        log('  gateway read failed: ${e.message}');
      }
    }
    return summarise(server, got);
  }

  /// Tests [candidates] one by one on the backup tunnel, then moves the
  /// winner to main and the runner-up to backup. [log] gets progress lines.
  /// Restores the original backup server if anything goes wrong.
  Future<BestServerPlan?> findBest(List<ProtonServer> candidates, void Function(String) log) async {
    _cancelled = false;
    final (main, backup) = await peers();
    final originalBackup = _asServer(backup, config.backupLabel);
    final current = _asServer(main, config.mainLabel);
    log('Measuring the current main (${main.serverAddress}) ...');
    final currentM = await _measure(config.mainGateway, current, log);
    log('  ${currentM.describe()}');

    final results = <ServerMeasurement>[];
    var backupMoved = false;
    try {
      for (final c in candidates) {
        if (_cancelled) break;
        if (c.sameEndpoint(main.serverAddress, main.publicKey)) {
          results.add(ServerMeasurement(c,
              delayMs: currentM.delayMs, jitterMs: currentM.jitterMs, lossPercent: currentM.lossPercent,
              error: currentM.error));
          continue;
        }
        log('Testing ${c.label} on the backup tunnel ...');
        await apply(backup, c);
        backupMoved = true;
        await _sleep(settle);
        final m = await _measure(config.backupGateway, c, log);
        log('  ${m.describe()}');
        results.add(m);
      }
      if (_cancelled) {
        log('Cancelled.');
        return null;
      }
      final plan = planBest(currentM, results);
      if (plan == null) {
        log('No candidate worked - nothing changed.');
        return null;
      }
      log(plan.reason);
      if (plan.changeMain) {
        log('Moving main to ${plan.newMain.server.name} ...');
        await apply(main, plan.newMain.server);
      }
      final nb = plan.newBackup?.server ?? originalBackup;
      log('Backup: ${nb.name}.');
      await apply(backup, nb);
      backupMoved = false;
      log('Done.');
      return plan;
    } finally {
      if (backupMoved) {
        log('Putting the backup tunnel back on ${originalBackup.entryIp} ...');
        try {
          await apply(backup, originalBackup);
        } on Object catch (e) {
          log('  could not restore the backup: $e');
        }
      }
    }
  }
}
