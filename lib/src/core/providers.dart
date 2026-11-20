import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

import 'server_switcher.dart';

/// VPN provider profiles for the server switcher (v2.1).
///
/// Everything else in the app works with any WireGuard VPN on the router;
/// only "which servers exist" is provider-specific. A profile says where a
/// server list comes from (if anywhere) and how to add servers by hand.
///
/// Server lists are only taken from the provider itself: a third-party list
/// supplies both the address AND the key, so a fake entry could send the
/// whole house's traffic somewhere else and still "connect".
abstract class ProviderProfile {
  const ProviderProfile();

  /// `proton`, `mullvad` or `other` (matches [AppConfig.providerId]).
  String get id;

  /// Display name, e.g. "Proton VPN".
  String get name;

  /// True when the app can download the provider's server list.
  bool get hasServerList => false;

  /// Where the person gets a WireGuard config for one server (shown in
  /// the "Add server" dialog and in help).
  String get configHelp;

  /// Why there is no list (shown instead of the download button), or null.
  String? get noListReason => null;

  /// Downloads the provider's servers in [country] (ISO code), active only.
  Future<List<ProtonServer>> fetchServers(http.Client client, {String? country}) =>
      throw UnsupportedError('$name has no server list in the app');

  static const proton = ProtonProfile();
  static const mullvad = MullvadProfile();
  static const other = OtherProfile();
  static const all = <ProviderProfile>[proton, mullvad, other];

  static ProviderProfile byId(String id) => all.firstWhere((p) => p.id == id, orElse: () => other);
}

class ProtonProfile extends ProviderProfile {
  const ProtonProfile();
  @override
  String get id => 'proton';
  @override
  String get name => 'Proton VPN';
  @override
  String get configHelp =>
      'account.protonvpn.com > Downloads > WireGuard configuration: platform "Router", pick a server and press '
      'Create. Then scan its QR code with this app, or paste the [Peer] part of the text.';
  @override
  String get noListReason =>
      'Proton closed its public server list in 2025 (it now needs a signed-in Proton app), so servers are added '
      'from Proton\'s config page instead: scan the QR code or paste the [Peer] part.';
}

class MullvadProfile extends ProviderProfile {
  const MullvadProfile();
  @override
  String get id => 'mullvad';
  @override
  String get name => 'Mullvad';
  @override
  bool get hasServerList => true;
  @override
  String get configHelp =>
      'mullvad.net > Account > WireGuard configuration: generate a config for any server, then scan or paste the '
      '[Peer] part. Usually not needed - the app downloads Mullvad\'s server list.';

  static final _url = Uri.parse('https://api.mullvad.net/www/relays/wireguard/');

  @override
  Future<List<ProtonServer>> fetchServers(http.Client client, {String? country}) async {
    final r = await client.get(_url, headers: const {'Accept': 'application/json'}).timeout(const Duration(seconds: 15));
    if (r.statusCode != 200) {
      throw ProviderException('Mullvad\'s server list answered HTTP ${r.statusCode} - try again later, '
          'or add servers from config files.');
    }
    final list = parseMullvadRelays(jsonDecode(r.body), country: country);
    if (list.isEmpty) throw ProviderException('Mullvad\'s server list had no active servers${country == null ? '' : ' in $country'}.');
    return list;
  }
}

class OtherProfile extends ProviderProfile {
  const OtherProfile();
  @override
  String get id => 'other';
  @override
  String get name => 'Other WireGuard provider';
  @override
  String get configHelp =>
      'Your provider\'s website: download a WireGuard config for the server you want, then scan its QR code or '
      'paste the [Peer] part. The router keeps its own key, so the provider must accept one key on all its servers '
      '(most do). The app checks for a real handshake and puts the old server back if not.';
  @override
  String get noListReason => 'The app has no server list for this provider - add servers from its config files.';
}

class ProviderException implements Exception {
  ProviderException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// Parses Mullvad's public relay list. Accepts the flat `www/relays`
/// format (`[{hostname, country_code, city_name, ipv4_addr_in, pubkey,
/// active}]`) and the nested `v1` format (`{countries: [{code, cities:
/// [{name, relays: [{hostname, ipv4_addr_in, public_key}]}]}]}`).
List<ProtonServer> parseMullvadRelays(Object? json, {String? country}) {
  final want = country?.trim().toUpperCase();
  final out = <ProtonServer>[];
  void add({required Object? host, required Object? ip, required Object? key, required Object? cc, Object? city, Object? active}) {
    final ccs = '${cc ?? ''}'.toUpperCase();
    if (want != null && want.isNotEmpty && ccs != want) return;
    if (active == false) return;
    final addr = '${ip ?? ''}'.trim();
    final pub = '${key ?? ''}'.trim();
    if (InternetAddress.tryParse(addr)?.type != InternetAddressType.IPv4 || !isWgPublicKey(pub)) return;
    out.add(ProtonServer(
      name: '${host ?? addr}',
      entryIp: addr,
      publicKey: pub,
      city: city == null || '$city'.isEmpty ? null : '$city',
      country: ccs.isEmpty ? null : ccs,
    ));
  }

  if (json is List) {
    for (final r in json) {
      if (r is! Map) continue;
      if (r['type'] != null && r['type'] != 'wireguard') continue;
      add(
          host: r['hostname'],
          ip: r['ipv4_addr_in'],
          key: r['pubkey'] ?? r['public_key'],
          cc: r['country_code'],
          city: r['city_name'],
          active: r['active']);
    }
  } else if (json is Map && json['countries'] is List) {
    for (final c in json['countries'] as List) {
      if (c is! Map || c['cities'] is! List) continue;
      for (final city in c['cities'] as List) {
        if (city is! Map || city['relays'] is! List) continue;
        for (final r in city['relays'] as List) {
          if (r is! Map) continue;
          add(
              host: r['hostname'],
              ip: r['ipv4_addr_in'],
              key: r['public_key'] ?? r['pubkey'],
              cc: c['code'],
              city: city['name'],
              active: r['active']);
        }
      }
    }
  }
  return out;
}
