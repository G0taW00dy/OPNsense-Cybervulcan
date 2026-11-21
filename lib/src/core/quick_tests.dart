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
  if (net != null && net == cfg.directNetworkName) return ExpectedPath.direct;
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

enum Verdict { ok, mismatch, inconclusive, warn }

/// A VPN provider's or hosting network (where VPN servers live), not a home
/// ISP. Used to tell "this device's own VPN app is on" apart from a leak.
bool looksLikeVpnNetwork(String? org) {
  final o = ' ${(org ?? '').toLowerCase().replaceAll(RegExp(r'[^a-z0-9]+'), ' ')} ';
  // Whole words only (review 22 Nov: "31173" matched AS131173).
  return const [
    'datacamp', 'proton ag', 'proton vpn', 'mullvad', 'm247', 'host universal', 'packethub', 'tefincom',
    'leaseweb', 'cdn77', 'zenlayer', 'choopa', 'vultr', 'the constant company', 'ovh sas', 'ovhcloud', 'hetzner',
    'digitalocean', 'quadranet', 'performive', 'xtom', 'clouvider', 'gsl networks', '31173 services',
  ].any((w) => o.contains(' $w '));
}

/// Countries the house VPN may exit in: the "VPN country" setting plus the
/// country of each server a tunnel uses now (JP#153 -> JP, US-CA#742 -> US).
Set<String> vpnCountriesFor(AppConfig cfg, Iterable<String> tunnelServerNames) => {
      cfg.vpnCountryCode.toUpperCase(),
      for (final n in tunnelServerNames)
        if (RegExp(r'^([A-Z]{2})[#-]').firstMatch(n.trim()) case final m?) m.group(1)!,
    };

class ExitCheckResult {
  const ExitCheckResult(this.info, this.expected, this.verdict, this.explanation);

  final ExitInfo info;
  final ExpectedPath expected;
  final Verdict verdict;
  final String explanation;
}

ExitCheckResult evaluateExit(ExitInfo info, ExpectedPath expected, AppConfig cfg, {Set<String>? vpnCountries}) {
  final cc = info.countryCode?.toUpperCase();
  if (cc == null) {
    return ExitCheckResult(info, expected, Verdict.inconclusive, 'Country lookup failed.');
  }
  final home = cfg.homeCountryCode.toUpperCase();
  final vpn = vpnCountries ?? {cfg.vpnCountryCode.toUpperCase()};
  final vpnNet = looksLikeVpnNetwork(info.org);
  final vpnWords = vpn.join(' / ');
  switch (expected) {
    case ExpectedPath.vpn:
      // Home country: only a known VPN network may pass, never an unknown
      // org (review 22 Nov: a tunnel server in AU must not hide an ISP leak).
      if (cc == home && !vpnNet) {
        return ExitCheckResult(info, expected, Verdict.mismatch,
            'Expected a ${cfg.vpnName} exit ($vpnWords) but traffic leaves via a $home network - possible leak.');
      }
      if (vpn.contains(cc) && (vpnNet || (info.org == null && cc != home))) {
        return ExitCheckResult(info, expected, Verdict.ok, 'Exit is in $cc on ${cfg.vpnName}, matching the house tunnels.');
      }
      if (vpnNet) {
        // A VPN server, but not one of the router's: the device's own VPN app.
        return ExitCheckResult(info, expected, Verdict.warn,
            'Exit is a VPN server in $cc that is not one of the router\'s tunnels ($vpnWords) - this device\'s '
            'own VPN app is probably on. Not a leak, but at home it adds a second VPN layer and lag.');
      }
      if (cc == home) {
        return ExitCheckResult(info, expected, Verdict.mismatch,
            'Expected a ${cfg.vpnName} exit ($vpnWords) but traffic leaves via a $home network - possible leak.');
      }
      return ExitCheckResult(info, expected, vpn.contains(cc) ? Verdict.ok : Verdict.inconclusive,
          vpn.contains(cc) ? 'Exit is in $cc, matching the house tunnels.' : 'Exit country $cc is not where the tunnels are ($vpnWords).');
    case ExpectedPath.direct:
      if (vpnNet) {
        return ExitCheckResult(info, expected, Verdict.mismatch,
            'Expected direct internet but the exit is a VPN server in $cc - still on the VPN, or this device\'s '
            'own VPN app is on.');
      }
      if (cc == home) {
        return ExitCheckResult(info, expected, Verdict.ok, 'Direct exit via your ISP ($home), as expected.');
      }
      return ExitCheckResult(info, expected, Verdict.mismatch,
          'Expected direct internet ($home) but the exit is in $cc - still on the VPN?');
    case ExpectedPath.unknown:
      // Another house network (e.g. MGMT) or not the house at all: describe it.
      return ExitCheckResult(info, expected, Verdict.inconclusive, vpnNet
          ? 'This device leaves through a VPN server in $cc${vpn.contains(cc) ? ' (the house tunnels)' : ' (its own VPN app?)'}.'
          : cc == home
              ? 'This device goes straight to the internet via a $home network - no VPN on this path.'
              : 'This device exits in $cc - not a network the app can judge.');
  }
}

class DnsResolverInfo {
  const DnsResolverInfo({required this.resolverIp, this.geo});

  final String resolverIp;

  /// e.g. "Australia - (ISP name)" or "United States - Quad9".
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
    return geo(ip);
  }

  /// This device's public IP as seen by one of two independent services.
  Future<String> publicIp({bool alternate = false}) async {
    if (alternate) {
      final j = await _getJson(Uri.parse('https://ipwho.is/?fields=ip'));
      final ip = '${j['ip'] ?? ''}';
      if (ip.isEmpty) throw Exception('ipwho.is returned no IP');
      return ip;
    }
    final j = await _getJson(Uri.parse('https://api.ipify.org?format=json'));
    final ip = '${j['ip'] ?? ''}';
    if (ip.isEmpty) throw Exception('ipify returned no IP');
    return ip;
  }

  /// IPv6 address this device reaches the internet with; throws when there
  /// is no IPv6 path (api6.ipify.org is IPv6-only).
  Future<String> publicIpv6() async {
    final j = await _getJson(Uri.parse('https://api6.ipify.org?format=json'));
    final ip = '${j['ip'] ?? ''}';
    if (!ip.contains(':')) throw Exception('no IPv6 address returned');
    return ip;
  }

  /// GET returning JSON (any shape) - for the extended leak test.
  Future<Object?> getAny(Uri uri) async {
    final r = await _http.get(uri, headers: {'Accept': 'application/json'}).timeout(timeout);
    if (r.statusCode != 200) throw Exception('${uri.host} answered HTTP ${r.statusCode}');
    return jsonDecode(r.body);
  }

  /// Country / city / organisation of [ip] via ipwho.is (fallback ipapi.co).
  Future<ExitInfo> geo(String ip) async {
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
