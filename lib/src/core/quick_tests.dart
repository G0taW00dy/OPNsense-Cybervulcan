import 'dart:convert';
import 'dart:math';

import 'package:http/http.dart' as http;

import 'config.dart';
import 'network_map.dart';

/// What this device's traffic *should* look like given the router state.
enum ExpectedPath { vpn, direct, unknown }

ExpectedPath expectedPathFor({
  required String? deviceIp,
  required AppConfig cfg,
  required bool? bypassActive,
  required bool? pcClear,
}) {
  if (deviceIp == null) return ExpectedPath.unknown;
  final net = networkNameFor(deviceIp, cfg.networks);
  final onVpnNet = Ipv4Subnet.tryParse(cfg.bypassNetwork)?.contains(deviceIp) ?? false;
  if (onVpnNet) {
    if (bypassActive == true || pcClear == true) return ExpectedPath.direct;
    if (bypassActive == null) return ExpectedPath.unknown;
    return ExpectedPath.vpn;
  }
  if (net == 'CLEAR') return ExpectedPath.direct;
  return ExpectedPath.unknown;
}

class ExitInfo {
  const ExitInfo({required this.ip, this.countryCode, this.country, this.city, this.org});

  final String ip;
  final String? countryCode;
  final String? country;
  final String? city;
  final String? org;
}

enum Verdict { ok, mismatch, inconclusive }

class ExitCheckResult {
  const ExitCheckResult(this.info, this.expected, this.verdict, this.explanation);

  final ExitInfo info;
  final ExpectedPath expected;
  final Verdict verdict;
  final String explanation;
}

ExitCheckResult evaluateExit(ExitInfo info, ExpectedPath expected, AppConfig cfg) {
  final cc = info.countryCode?.toUpperCase();
  if (cc == null) {
    return ExitCheckResult(info, expected, Verdict.inconclusive, 'Country lookup failed.');
  }
  final home = cfg.homeCountryCode.toUpperCase();
  final vpn = cfg.vpnCountryCode.toUpperCase();
  switch (expected) {
    case ExpectedPath.vpn:
      if (cc == home) {
        return ExitCheckResult(info, expected, Verdict.mismatch,
            'Expected a Proton exit ($vpn) but traffic leaves from $home - possible leak.');
      }
      return ExitCheckResult(info, expected, cc == vpn ? Verdict.ok : Verdict.inconclusive,
          cc == vpn ? 'Exit is in $vpn, consistent with Proton.' : 'Exit country $cc is neither $home nor $vpn.');
    case ExpectedPath.direct:
      if (cc == home) {
        return ExitCheckResult(info, expected, Verdict.ok, 'Direct exit via your ISP ($home), as expected.');
      }
      return ExitCheckResult(info, expected, Verdict.mismatch,
          'Expected direct internet ($home) but the exit is in $cc - still on the VPN?');
    case ExpectedPath.unknown:
      return ExitCheckResult(info, expected, Verdict.inconclusive,
          'This device is not on a house network Cybervulcan can reason about.');
  }
}

class DnsResolverInfo {
  const DnsResolverInfo({required this.resolverIp, this.geo});

  final String resolverIp;

  /// e.g. "Australia - Telstra" or "United States - Quad9".
  final String? geo;
}

/// Network calls for the quick tests. All third-party endpoints are free and
/// key-less; failures surface as exceptions with readable messages.
class QuickTests {
  QuickTests(this._http, {this.timeout = const Duration(seconds: 8)});

  final http.Client _http;
  final Duration timeout;

  Future<Map<String, dynamic>> _getJson(Uri uri) async {
    final r = await _http.get(uri, headers: {'Accept': 'application/json'}).timeout(timeout);
    if (r.statusCode != 200) throw Exception('${uri.host} answered HTTP ${r.statusCode}');
    final j = jsonDecode(r.body);
    if (j is! Map<String, dynamic>) throw Exception('${uri.host} returned unexpected data');
    return j;
  }

  /// Exit IP via ipify, then country/org via ipwho.is (fallback ipapi.co).
  Future<ExitInfo> exitInfo() async {
    final ipJson = await _getJson(Uri.parse('https://api.ipify.org?format=json'));
    final ip = '${ipJson['ip'] ?? ''}';
    if (ip.isEmpty) throw Exception('ipify returned no IP');
    try {
      final g = await _getJson(Uri.parse('https://ipwho.is/$ip'));
      if (g['success'] == false) throw Exception('${g['message']}');
      final conn = g['connection'];
      return ExitInfo(
        ip: ip,
        countryCode: g['country_code']?.toString(),
        country: g['country']?.toString(),
        city: g['city']?.toString(),
        org: conn is Map ? (conn['org'] ?? conn['isp'])?.toString() : null,
      );
    } on Exception {
      final g = await _getJson(Uri.parse('https://ipapi.co/$ip/json/'));
      return ExitInfo(
        ip: ip,
        countryCode: g['country_code']?.toString() ?? g['country']?.toString(),
        country: g['country_name']?.toString(),
        city: g['city']?.toString(),
        org: g['org']?.toString(),
      );
    }
  }

  /// Which recursive resolver is answering for this device. A random,
  /// never-cached subdomain forces a fresh lookup that ip-api's authoritative
  /// server records (edns.ip-api.com; plain HTTP only). The label must be
  /// exactly 32 alphanumeric characters or ip-api answers 404.
  Future<DnsResolverInfo> dnsResolver() async {
    final rnd = Random.secure();
    final label = List.generate(32, (_) => 'abcdefghijklmnopqrstuvwxyz0123456789'[rnd.nextInt(36)]).join();
    final j = await _getJson(Uri.parse('http://$label.edns.ip-api.com/json'));
    final dns = j['dns'];
    if (dns is! Map || dns['ip'] == null) throw Exception('No resolver information returned');
    return DnsResolverInfo(resolverIp: '${dns['ip']}', geo: dns['geo']?.toString());
  }
}
