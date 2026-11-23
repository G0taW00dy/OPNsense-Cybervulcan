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

  /// `POST /api/wol/wol/set` with `wake: {interface, mac}` - sends the magic
  /// packet. (2.1.23 posted to set/{uuid}, which answers `[]` and sends
  /// nothing - checked on the router 23 Nov.)
  Future<void> wakeHost(WolHost host) async {
    const ep = '/api/wol/wol/set';
    if (!RegExp(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$').hasMatch(host.mac) ||
        !RegExp(r'^[A-Za-z0-9_]{1,32}$').hasMatch(host.interface)) {
      throw ArgumentError.value(host, 'host', 'bad interface or MAC');
    }
    final json = await _send('POST', ep, body: {
      'wake': {'interface': host.interface, 'mac': host.mac},
    });
    final st = json is Map ? '${json['status'] ?? ''}'.trim().toUpperCase() : '';
    if (st != 'OK') {
      throw OpnsenseException(ApiErrorKind.server, 'Router could not send the wake-up packet', endpoint: ep);
    }
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
