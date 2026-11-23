import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

import 'models.dart';
import 'shaper_models.dart';
import 'wireguard_models.dart';

/// Why an API call failed - drives the UI wording and the tray colour.
enum ApiErrorKind {
  /// 401: wrong key/secret.
  unauthorized,

  /// 403: the API user lacks the privilege for this endpoint.
  forbidden,

  /// 404: endpoint not present on this OPNsense version / plugin missing.
  notFound,

  /// TLS failure, typically a self-signed certificate that is not pinned.
  untrustedCertificate,

  /// Router unreachable / timeout / DNS.
  network,

  /// 5xx or an API-level `{"status":"failed"}`.
  server,

  /// Response was not the JSON we expected.
  badResponse,
}

class OpnsenseException implements Exception {
  OpnsenseException(this.kind, this.message, {this.statusCode, this.endpoint});

  final ApiErrorKind kind;
  final String message;
  final int? statusCode;
  final String? endpoint;

  @override
  String toString() =>
      'OpnsenseException($kind${statusCode != null ? ' $statusCode' : ''}'
      '${endpoint != null ? ' $endpoint' : ''}): $message';
}

/// Minimal, privilege-conscious client for the OPNsense REST API.
///
/// Authentication is HTTP Basic with an API key (username) and secret
/// (password). The credentials are never logged or included in exceptions.
class OpnsenseClient {
  OpnsenseClient({
    required Uri baseUrl,
    required String apiKey,
    required String apiSecret,
    required http.Client httpClient,
    this.timeout = const Duration(seconds: 8),
  })  : _base = _normaliseBase(baseUrl),
        _auth = 'Basic ${base64Encode(utf8.encode('$apiKey:$apiSecret'))}',
        _http = httpClient;

  final Uri _base;
  final String _auth;
  final http.Client _http;
  final Duration timeout;

  Uri get baseUrl => _base;

  static Uri _normaliseBase(Uri u) {
    var path = u.path;
    while (path.endsWith('/')) {
      path = path.substring(0, path.length - 1);
    }
    return Uri(
      scheme: u.scheme.isEmpty ? 'https' : u.scheme,
      host: u.host,
      port: u.hasPort ? u.port : null,
      path: path,
    );
  }

  Uri _uri(String apiPath, [Map<String, String>? query]) {
    final p = apiPath.startsWith('/') ? apiPath : '/$apiPath';
    return _base.replace(path: '${_base.path}$p', queryParameters: query);
  }

  /// Validates alias names before they are placed in a URL path.
  static String _aliasSegment(String alias) {
    if (!RegExp(r'^[A-Za-z0-9_]{1,32}$').hasMatch(alias)) {
      throw ArgumentError.value(alias, 'alias', 'invalid OPNsense alias name');
    }
    return alias;
  }

  /// Validates IPv4/IPv6 address or CIDR before sending (mirrors the server
  /// side check in AliasUtilController).
  static String _address(String address) {
    final a = address.trim();
    if (a.isEmpty || RegExp(r'[^0-9a-fA-F:./]').hasMatch(a)) {
      throw ArgumentError.value(address, 'address', 'not an IP address/CIDR');
    }
    return a;
  }

  Future<Object?> _send(
    String method,
    String apiPath, {
    Map<String, String>? query,
    Map<String, dynamic>? body,
    Duration? timeout,
  }) async {
    final t = timeout ?? this.timeout;
    final uri = _uri(apiPath, query);
    // No keep-alive: every call gets a fresh TCP connection (and pf state).
    // Mode changes kill this device's own states, which would otherwise
    // leave a pooled connection silently dead.
    // Never follow redirects: the Authorization header must only ever go to
    // the configured base URL (a redirect is reported as an error below).
    final request = http.Request(method, uri)
      ..persistentConnection = false
      ..followRedirects = false
      ..headers['Authorization'] = _auth
      ..headers['Accept'] = 'application/json';
    if (body != null) {
      request.headers['Content-Type'] = 'application/json';
      request.body = jsonEncode(body);
    }
    http.Response response;
    try {
      final streamed = await _http.send(request).timeout(t);
      response = await http.Response.fromStream(streamed).timeout(t);
    } on HandshakeException catch (e) {
      throw OpnsenseException(
        ApiErrorKind.untrustedCertificate,
        'TLS handshake failed (certificate not trusted or not pinned): ${e.message}',
        endpoint: apiPath,
      );
    } on TimeoutException {
      throw OpnsenseException(ApiErrorKind.network, 'Router did not answer in time',
          endpoint: apiPath);
    } on SocketException catch (e) {
      throw OpnsenseException(ApiErrorKind.network, 'Cannot reach router: ${e.message}',
          endpoint: apiPath);
    } on http.ClientException catch (e) {
      throw OpnsenseException(ApiErrorKind.network, 'Connection error: ${e.message}',
          endpoint: apiPath);
    }

    final code = response.statusCode;
    if (code == 401) {
      throw OpnsenseException(ApiErrorKind.unauthorized, 'API key or secret rejected',
          statusCode: code, endpoint: apiPath);
    }
    if (code == 403) {
      throw OpnsenseException(ApiErrorKind.forbidden,
          'API user lacks the privilege for $apiPath', statusCode: code, endpoint: apiPath);
    }
    if (code == 404) {
      throw OpnsenseException(ApiErrorKind.notFound,
          'Endpoint $apiPath not found on this OPNsense version',
          statusCode: code, endpoint: apiPath);
    }
    if (code >= 300) {
      throw OpnsenseException(ApiErrorKind.server, 'HTTP $code from router',
          statusCode: code, endpoint: apiPath);
    }
    if (response.body.trim().isEmpty) return null;
    try {
      return jsonDecode(response.body);
    } on FormatException {
      throw OpnsenseException(ApiErrorKind.badResponse,
          'Router returned non-JSON (is the base URL right?)', statusCode: code, endpoint: apiPath);
    }
  }

  Map<String, dynamic> _asMap(Object? json, String endpoint) {
    if (json is Map<String, dynamic>) return json;
    if (json is Map) return json.cast<String, dynamic>();
    throw OpnsenseException(ApiErrorKind.badResponse, 'Expected a JSON object', endpoint: endpoint);
  }

  /// Rows of a searchRecordset response (`rows`), or the legacy `items` key.
  static List<Object?> _rows(Map<String, dynamic> json) {
    final rows = json['rows'] ?? json['items'];
    if (rows is List) return rows;
    if (rows is Map) return rows.values.toList();
    return const [];
  }

  void _expectDone(Object? json, String endpoint) {
    final map = _asMap(json, endpoint);
    // OPNsense answers either {"status": "ok"} or {"result": "ok"} depending
    // on the controller.
    final status = (map['status'] ?? map['result'])?.toString().toLowerCase();
    if (status != 'done' && status != 'ok') {
      final msg = map['status_msg']?.toString() ??
          (status == null ? 'The router gave an unexpected answer' : 'The router answered "$status"');
      throw OpnsenseException(ApiErrorKind.server, msg, endpoint: endpoint);
    }
  }

  // ---------------------------------------------------------------- gateways

  /// `GET /api/routes/gateway/status` - privilege "System: Gateways".
  Future<List<GatewayStatus>> gatewayStatus() async {
    const ep = '/api/routes/gateway/status';
    final map = _asMap(await _send('GET', ep), ep);
    final items = map['items'];
    final list = items is List ? items : (items is Map ? items.values.toList() : const []);
    return [
      for (final i in list)
        if (i is Map) GatewayStatus.fromJson(i.cast<String, dynamic>()),
    ];
  }

  // ---------------------------------------------------------- alias tables
  // Privilege "Diagnostics: PF Table IP addresses" (api/firewall/alias_util/*).

  /// Current runtime contents of a pf table.
  Future<List<String>> aliasList(String alias) async {
    final ep = '/api/firewall/alias_util/list/${_aliasSegment(alias)}';
    final map = _asMap(await _send('GET', ep), ep);
    return [
      for (final r in _rows(map))
        if (r is Map && r['ip'] != null)
          r['ip'].toString()
        else if (r is String)
          r,
    ];
  }

  Future<void> aliasAdd(String alias, String address) async {
    final ep = '/api/firewall/alias_util/add/${_aliasSegment(alias)}';
    _expectDone(await _send('POST', ep, body: {'address': _address(address)}), ep);
  }

  Future<void> aliasDelete(String alias, String address) async {
    final ep = '/api/firewall/alias_util/delete/${_aliasSegment(alias)}';
    _expectDone(await _send('POST', ep, body: {'address': _address(address)}), ep);
  }

  Future<void> aliasFlush(String alias) async {
    final ep = '/api/firewall/alias_util/flush/${_aliasSegment(alias)}';
    _expectDone(await _send('POST', ep, body: const {}), ep);
  }

  // ------------------------------------------------------------------ DHCP

  /// `GET /api/dnsmasq/leases/search` - privilege
  /// "Services: Dnsmasq DNS/DHCP: Settings".
  Future<List<DhcpLease>> dnsmasqLeases() async {
    const ep = '/api/dnsmasq/leases/search';
    // POST with rowCount -1: a plain GET returns one page only, so some
    // devices were missing from the list (22 Nov: the phone's new lease).
    // v2.1.22: 20 s - over the remote tunnel the first call can be slow.
    final map = _asMap(
        await _send('POST', ep, body: {'current': 1, 'rowCount': -1}, timeout: const Duration(seconds: 20)), ep);
    return [
      for (final r in _rows(map))
        if (r is Map) DhcpLease.fromJson(r.cast<String, dynamic>()),
    ];
  }

  // ------------------------------------------------------- wake on LAN

  /// `GET /api/wol/wol/searchHost` - plugin os-wol, privilege
  /// `Services: Wake on LAN`. The hosts saved on the router.
  Future<List<WolHost>> wolHosts() async {
    const ep = '/api/wol/wol/searchHost';
    final json = await _send('GET', ep);
    return [
      for (final r in _rows(_asMap(json, ep)))
        if (r is Map && _uuidRe.hasMatch('${r['uuid']}')) WolHost.fromJson(r.cast<String, dynamic>()),
    ];
  }

  /// `POST /api/wol/wol/set/{uuid}` - sends the magic packet for a saved host.
  Future<void> wakeHost(String uuid) async {
    if (!_uuidRe.hasMatch(uuid)) throw ArgumentError.value(uuid, 'uuid', 'not a UUID');
    final ep = '/api/wol/wol/set/$uuid';
    final json = await _send('POST', ep, body: const {});
    final map = _asMap(json, ep);
    final st = '${map['status'] ?? map['result'] ?? ''}'.toLowerCase();
    if (st.contains('fail') || st.contains('error')) {
      throw OpnsenseException(ApiErrorKind.server, 'Router could not send the wake-up packet', endpoint: ep);
    }
  }

  // ------------------------------------------------------- firewall rules

  /// `POST /api/firewall/filter/search_rule` - privilege
  /// `Firewall: Rules [new]`. `show_all=1` merges pf rule statistics.
  Future<List<FirewallRule>> searchRules(String phrase) async {
    const ep = '/api/firewall/filter/search_rule';
    final json = await _send('POST', ep,
        query: const {'show_all': '1'},
        body: {'searchPhrase': phrase, 'current': 1, 'rowCount': -1});
    return [
      for (final r in _rows(_asMap(json, ep)))
        if (r is Map) FirewallRule.fromJson(r.cast<String, dynamic>()),
    ];
  }

  /// `GET /api/firewall/filter_util/rule_stats` - privilege "Firewall: Rules".
  /// Keys are rule UUIDs of rules currently *loaded* in pf.
  Future<Map<String, Map<String, dynamic>>> ruleStats() async {
    const ep = '/api/firewall/filter_util/rule_stats';
    final map = _asMap(await _send('GET', ep), ep);
    final stats = map['stats'];
    if (map['status'] != 'ok' || stats is! Map) {
      throw OpnsenseException(ApiErrorKind.server, 'rule stats unavailable', endpoint: ep);
    }
    return {
      for (final e in stats.entries)
        if (e.value is Map) e.key.toString(): (e.value as Map).cast<String, dynamic>(),
    };
  }

  // ------------------------------------------------------------ pf states

  /// `POST /api/diagnostics/firewall/kill_states` {"filter": ...} -
  /// privilege "Diagnostics: Show States". Returns the number of dropped
  /// states. The router sanitises `filter` to `[0-9A-Za-z ,*._#-]`, so CIDR
  /// notation is not possible - see [stateKillFilter].
  Future<int> killStates(String filter) async {
    const ep = '/api/diagnostics/firewall/kill_states';
    final f = filter.trim();
    if (f.isEmpty || RegExp(r'[^0-9A-Za-z ,*._#\-]').hasMatch(f)) {
      throw ArgumentError.value(filter, 'filter', 'unsupported state filter');
    }
    final map = _asMap(
        await _send('POST', ep, body: {'filter': f}, timeout: const Duration(seconds: 20)), ep);
    if (map['result'] != 'ok') {
      throw OpnsenseException(ApiErrorKind.server, 'kill_states: ${map['result']}', endpoint: ep);
    }
    final n = map['dropped_states'];
    return n is num ? n.toInt() : int.tryParse('$n') ?? 0;
  }

  // ------------------------------------------------------------- WireGuard
  // Privilege "VPN: WireGuard" (api/wireguard/*). Only the server switcher
  // and the Tests page use these; everything else works without them.

  static final _uuidRe = RegExp(r'^[0-9a-fA-F-]{36}$');

  /// Configured peers. Private / pre-shared keys in the response are ignored.
  Future<List<WgPeer>> wgPeers() async {
    const ep = '/api/wireguard/client/search_client';
    final json = await _send('POST', ep, body: const {'current': 1, 'rowCount': -1, 'searchPhrase': ''});
    return [
      for (final r in _rows(_asMap(json, ep)))
        if (r is Map) WgPeer.fromJson(r.cast<String, dynamic>()),
    ];
  }

  /// Points a peer at another server: endpoint address, port and the
  /// server's public key. Nothing else (in particular no private key) is sent.
  ///
  /// OPNsense's set_client clears relation fields that are not posted, so the
  /// peer's instance link (`servers`) is read first and sent back unchanged.
  /// If the link is already missing, [instance] (an instance name) is used to
  /// restore it.
  Future<void> setWgPeerServer(String uuid,
      {required String address, required int port, required String publicKey, String? instance, String? name}) async {
    if (!_uuidRe.hasMatch(uuid)) throw ArgumentError.value(uuid, 'uuid', 'not a UUID');
    if (name != null && !RegExp(r'^[A-Za-z0-9._\-]{1,64}$').hasMatch(name)) {
      throw ArgumentError.value(name, 'name', 'not a valid peer name');
    }
    if (InternetAddress.tryParse(address.trim()) == null) {
      throw ArgumentError.value(address, 'address', 'not an IP address');
    }
    if (port < 1 || port > 65535) throw ArgumentError.value(port, 'port');
    if (!RegExp(r'^[A-Za-z0-9+/]{43}=$').hasMatch(publicKey.trim())) {
      throw ArgumentError.value('(key)', 'publicKey', 'not a WireGuard public key');
    }
    var servers = await _wgPeerInstanceUuids(uuid);
    if (servers.isEmpty && instance != null && instance.trim().isNotEmpty) {
      final want = instance.trim().toLowerCase();
      servers = [
        for (final i in await wgInstances())
          if (i.name.toLowerCase() == want) i.uuid,
      ];
    }
    final ep = '/api/wireguard/client/set_client/$uuid';
    final map = _asMap(
        await _send('POST', ep, body: {
          'client': {
            'serveraddress': address.trim(),
            'serverport': '$port',
            'pubkey': publicKey.trim(),
            if (name != null) 'name': name,
            if (servers.isNotEmpty) 'servers': servers.join(','),
          },
        }),
        ep);
    if (map['result'] != 'saved') {
      final v = map['validations'];
      throw OpnsenseException(ApiErrorKind.server,
          'Router did not save the peer${v is Map && v.isNotEmpty ? ': ${v.values.join('; ')}' : ''}',
          endpoint: ep);
    }
  }

  /// Adds a switched-off peer linked to no instance (the router-stored server
  /// list). The live tunnels are not reconfigured. Returns the new uuid.
  Future<String> addWgListPeer(
      {required String name, required String address, required int port, required String publicKey}) async {
    if (!RegExp(r'^[A-Za-z0-9._-]{1,64}$').hasMatch(name)) throw ArgumentError.value(name, 'name');
    if (InternetAddress.tryParse(address.trim()) == null) {
      throw ArgumentError.value(address, 'address', 'not an IP address');
    }
    if (port < 1 || port > 65535) throw ArgumentError.value(port, 'port');
    if (!RegExp(r'^[A-Za-z0-9+/]{43}=$').hasMatch(publicKey.trim())) {
      throw ArgumentError.value('(key)', 'publicKey', 'not a WireGuard public key');
    }
    const ep = '/api/wireguard/client/add_client';
    final map = _asMap(
        await _send('POST', ep, body: {
          'client': {
            'enabled': '0',
            'name': name,
            'pubkey': publicKey.trim(),
            'serveraddress': address.trim(),
            'serverport': '$port',
            'tunneladdress': '192.0.2.1/32',
            'servers': '',
          },
        }),
        ep);
    if (map['result'] != 'saved') {
      final v = map['validations'];
      throw OpnsenseException(ApiErrorKind.server,
          'Router did not save the server${v is Map && v.isNotEmpty ? ': ${v.values.join('; ')}' : ''}',
          endpoint: ep);
    }
    return '${map['uuid'] ?? ''}';
  }

  /// Deletes a peer. Callers only pass switched-off list peers.
  Future<void> deleteWgPeer(String uuid) async {
    if (!_uuidRe.hasMatch(uuid)) throw ArgumentError.value(uuid, 'uuid', 'not a UUID');
    final ep = '/api/wireguard/client/del_client/$uuid';
    final map = _asMap(await _send('POST', ep, body: const {}), ep);
    if (map['result'] != 'deleted') {
      throw OpnsenseException(ApiErrorKind.server, 'Router did not delete the server entry', endpoint: ep);
    }
  }

  /// UUIDs of the instances a peer is linked to (from get_client's option map).
  Future<List<String>> _wgPeerInstanceUuids(String uuid) async {
    final ep = '/api/wireguard/client/get_client/$uuid';
    final map = _asMap(await _send('GET', ep), ep);
    final c = map['client'];
    final s = c is Map ? c['servers'] : null;
    if (s is! Map) return const [];
    return [
      for (final e in s.entries)
        if (e.value is Map && _isSelected((e.value as Map)['selected']) && _uuidRe.hasMatch('${e.key}')) '${e.key}',
    ];
  }

  static bool _isSelected(Object? v) => v == 1 || v == '1' || v == true;

  /// WireGuard instances (local tunnels): uuid and name only - never keys.
  Future<List<({String uuid, String name})>> wgInstances() async {
    const ep = '/api/wireguard/server/search_server';
    final json = await _send('POST', ep, body: const {'current': 1, 'rowCount': -1, 'searchPhrase': ''});
    return [
      for (final r in _rows(_asMap(json, ep)))
        if (r is Map && _uuidRe.hasMatch('${r['uuid']}')) (uuid: '${r['uuid']}', name: '${r['name'] ?? ''}'),
    ];
  }

  /// Read-only probe: may this key use the static routes API?
  Future<void> routesProbe() async {
    const ep = '/api/routes/routes/searchroute';
    _asMap(await _send('POST', ep, body: const {'current': 1, 'rowCount': 1, 'searchPhrase': ''}), ep);
  }

  /// Read-only probe: may this key use the services API?
  Future<void> servicesProbe() async {
    const ep = '/api/core/service/search';
    _asMap(await _send('POST', ep, body: const {'current': 1, 'rowCount': 1, 'searchPhrase': ''}), ep);
  }

  /// Re-applies the router's routes, which include the gateway monitor's
  /// host route through each tunnel. Needs "System: Static Routes"; returns
  /// false (instead of throwing) when the API user lacks it.
  Future<bool> refreshRoutes() async {
    const ep = '/api/routes/routes/reconfigure';
    try {
      _expectDone(await _send('POST', ep, body: const {}, timeout: const Duration(seconds: 30)), ep);
      return true;
    } on OpnsenseException catch (e) {
      if (e.kind == ApiErrorKind.forbidden || e.kind == ApiErrorKind.notFound) return false;
      rethrow;
    }
  }

  /// Restarts the gateway monitor (dpinger) of [gateway] so its readings
  /// start fresh. Needs "Status: Services"; returns false when not allowed.
  Future<bool> restartGatewayMonitor(String gateway) async {
    if (!RegExp(r'^[A-Za-z0-9_.-]{1,64}$').hasMatch(gateway)) throw ArgumentError.value(gateway, 'gateway');
    final ep = '/api/core/service/restart/dpinger/$gateway';
    try {
      _expectDone(await _send('POST', ep, body: const {}, timeout: const Duration(seconds: 30)), ep);
      return true;
    } on OpnsenseException catch (e) {
      if (e.kind == ApiErrorKind.forbidden || e.kind == ApiErrorKind.notFound) return false;
      rethrow;
    }
  }

  /// Applies WireGuard changes (restarts the tunnels that changed).
  Future<void> wgReconfigure() async {
    const ep = '/api/wireguard/service/reconfigure';
    _expectDone(await _send('POST', ep, body: const {}, timeout: const Duration(seconds: 30)), ep);
  }

  /// Runtime interfaces and peers (handshakes, traffic).
  Future<List<WgRuntime>> wgShow() async {
    const ep = '/api/wireguard/service/show';
    return [
      for (final r in _rows(_asMap(await _send('GET', ep), ep)))
        if (r is Map) WgRuntime.fromJson(r.cast<String, dynamic>()),
    ];
  }

  // ------------------------------------------------------------ Shaper (v2.1)
  // Privilege "Firewall: Shaper" - optional, shaper card / auto-tune only.

  Future<List<ShaperPipe>> shaperPipes() async {
    const ep = '/api/trafficshaper/settings/search_pipes';
    final json = await _send('POST', ep, body: const {'current': 1, 'rowCount': -1, 'searchPhrase': ''});
    return [
      for (final r in _rows(_asMap(json, ep)))
        if (r is Map && _uuidRe.hasMatch('${r['uuid']}')) ShaperPipe.fromJson(r.cast<String, dynamic>()),
    ];
  }

  /// Sets one pipe's bandwidth in Mbit/s (nothing else changes).
  Future<void> setPipeBandwidth(String uuid, int mbit) async {
    if (!_uuidRe.hasMatch(uuid)) throw ArgumentError.value(uuid, 'uuid', 'not a UUID');
    if (mbit < 1 || mbit > 100000) throw ArgumentError.value(mbit, 'mbit');
    final ep = '/api/trafficshaper/settings/set_pipe/$uuid';
    final map = _asMap(
        await _send('POST', ep, body: {
          'pipe': {'bandwidth': '$mbit', 'bandwidthMetric': 'Mbit'},
        }),
        ep);
    if (map['result'] != 'saved') {
      throw OpnsenseException(ApiErrorKind.server, 'Router did not save the shaper limit', endpoint: ep);
    }
  }

  /// Switches one pipe on or off (nothing else changes).
  Future<void> setPipeEnabled(String uuid, bool enabled) async {
    if (!_uuidRe.hasMatch(uuid)) throw ArgumentError.value(uuid, 'uuid', 'not a UUID');
    final ep = '/api/trafficshaper/settings/set_pipe/$uuid';
    final map = _asMap(await _send('POST', ep, body: {'pipe': {'enabled': enabled ? '1' : '0'}}), ep);
    if (map['result'] != 'saved') {
      throw OpnsenseException(ApiErrorKind.server, 'Router did not save the shaper switch', endpoint: ep);
    }
  }

  Future<List<ShaperQueue>> shaperQueues() async {
    const ep = '/api/trafficshaper/settings/search_queues';
    final json = await _send('POST', ep, body: const {'current': 1, 'rowCount': -1, 'searchPhrase': ''});
    return [
      for (final r in _rows(_asMap(json, ep)))
        if (r is Map && _uuidRe.hasMatch('${r['uuid']}')) ShaperQueue.fromJson(r.cast<String, dynamic>()),
    ];
  }

  Future<List<ShaperRule>> shaperRules() async {
    const ep = '/api/trafficshaper/settings/search_rules';
    final json = await _send('POST', ep, body: const {'current': 1, 'rowCount': -1, 'searchPhrase': ''});
    return [
      for (final r in _rows(_asMap(json, ep)))
        if (r is Map && _uuidRe.hasMatch('${r['uuid']}')) ShaperRule.fromJson(r.cast<String, dynamic>()),
    ];
  }

  /// Interface keys the shaper accepts, with their names (wan -> "WAN").
  Future<Map<String, String>> shaperInterfaces() async {
    const ep = '/api/trafficshaper/settings/get_rule';
    final rule = _asMap(await _send('GET', ep), ep)['rule'];
    final iface = rule is Map ? rule['interface'] : null;
    if (iface is! Map) return const {};
    return {
      for (final e in iface.entries)
        if (e.value is Map) '${e.key}': '${(e.value as Map)['value'] ?? e.key}',
    };
  }

  /// Raw rows of `/api/interfaces/overview/interfaces_info` (v2.1.22: for
  /// the house networks the router has - see networksFromInterfaceRows).
  Future<List<Object?>> interfaceOverview() async {
    const ep = '/api/interfaces/overview/interfaces_info';
    return _rows(_asMap(await _send('GET', ep), ep)).toList();
  }

  /// Device -> interface name (igc0 -> "WAN", wg0 -> "WG_MAIN").
  Future<Map<String, String>> interfaceNames() async {
    const ep = '/api/diagnostics/interface/get_interface_names';
    return {for (final e in _asMap(await _send('GET', ep), ep).entries) e.key: '${e.value}'};
  }

  /// Device of each WireGuard instance by name (Proton_VPN_Main -> wg0).
  Future<Map<String, String>> wgInstanceDevices() async {
    const ep = '/api/wireguard/server/search_server';
    final json = await _send('POST', ep, body: const {'current': 1, 'rowCount': -1, 'searchPhrase': ''});
    return {
      for (final r in _rows(_asMap(json, ep)))
        if (r is Map && '${r['interface'] ?? ''}'.isNotEmpty) '${r['name'] ?? ''}': '${r['interface']}',
    };
  }

  /// Public key of each WireGuard instance by name (v2.1.22: notices a
  /// replaced tunnel key). Public keys only.
  Future<Map<String, String>> wgInstanceKeys() async {
    const ep = '/api/wireguard/server/search_server';
    final json = await _send('POST', ep, body: const {'current': 1, 'rowCount': -1, 'searchPhrase': ''});
    return {
      for (final r in _rows(_asMap(json, ep)))
        if (r is Map && '${r['name'] ?? ''}'.isNotEmpty) '${r['name']}': '${r['pubkey'] ?? ''}',
    };
  }

  /// Adds a shaper rule feeding queue [target]; returns its uuid.
  Future<String> addShaperRule({
    required int sequence,
    required String interface,
    required String direction,
    required String target,
    required String description,
  }) async {
    if (!_uuidRe.hasMatch(target)) throw ArgumentError.value(target, 'target', 'not a UUID');
    if (!RegExp(r'^[a-z0-9_]{1,32}$').hasMatch(interface)) throw ArgumentError.value(interface, 'interface');
    if (direction != 'in' && direction != 'out') throw ArgumentError.value(direction, 'direction');
    const ep = '/api/trafficshaper/settings/add_rule';
    final map = _asMap(
        await _send('POST', ep, body: {
          'rule': {
            'enabled': '1',
            'sequence': '$sequence',
            'interface': interface,
            'interface2': '',
            'proto': 'ip',
            'source': 'any',
            'source_not': '0',
            'src_port': 'any',
            'destination': 'any',
            'destination_not': '0',
            'dst_port': 'any',
            'direction': direction,
            'target': target,
            'description': description,
          },
        }),
        ep);
    final uuid = '${map['uuid'] ?? ''}';
    if (map['result'] != 'saved' || !_uuidRe.hasMatch(uuid)) {
      throw OpnsenseException(ApiErrorKind.server, 'Router did not save the shaper rule: ${map['validations'] ?? ''}',
          endpoint: ep);
    }
    return uuid;
  }

  Future<void> deleteShaperRule(String uuid) async {
    if (!_uuidRe.hasMatch(uuid)) throw ArgumentError.value(uuid, 'uuid', 'not a UUID');
    final ep = '/api/trafficshaper/settings/del_rule/$uuid';
    final map = _asMap(await _send('POST', ep, body: const {}), ep);
    if (map['result'] != 'deleted') {
      throw OpnsenseException(ApiErrorKind.server, 'Router did not delete the shaper rule', endpoint: ep);
    }
  }

  Future<void> shaperReconfigure() async {
    const ep = '/api/trafficshaper/service/reconfigure';
    _expectDone(await _send('POST', ep, body: const {}, timeout: const Duration(seconds: 30)), ep);
  }

  /// Bytes counted so far per pipe number (rules on the pipe and on its queues).
  Future<Map<int, int>> shaperBytes() async {
    const ep = '/api/trafficshaper/service/statistics';
    return shaperBytesFromStatistics(_asMap(await _send('GET', ep), ep));
  }

  // ------------------------------------------------------------ Unbound DNS
  // Privilege "Services: Unbound DNS: Settings" - optional, Tests page only.

  Future<List<DotServer>> dotServers() async {
    const ep = '/api/unbound/settings/search_dot';
    final json = await _send('POST', ep, body: const {'current': 1, 'rowCount': -1, 'searchPhrase': ''});
    return [
      for (final r in _rows(_asMap(json, ep)))
        if (r is Map) DotServer.fromJson(r.cast<String, dynamic>()),
    ];
  }

  /// Whether Unbound validates DNSSEC (null when not reported).
  Future<bool?> unboundDnssec() async {
    const ep = '/api/unbound/settings/get';
    final map = _asMap(await _send('GET', ep), ep);
    final u = map['unbound'];
    final g = u is Map ? u['general'] : null;
    final v = g is Map ? g['dnssec'] : null;
    return v == null ? null : (v == '1' || v == 1 || v == true);
  }

  void close() => _http.close();
}
