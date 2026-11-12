import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

import 'models.dart';

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
    final status = map['status']?.toString().toLowerCase();
    if (status != 'done' && status != 'ok') {
      final msg = map['status_msg']?.toString() ?? 'status: ${map['status']}';
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
    final map = _asMap(await _send('GET', ep), ep);
    return [
      for (final r in _rows(map))
        if (r is Map) DhcpLease.fromJson(r.cast<String, dynamic>()),
    ];
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

  void close() => _http.close();
}
