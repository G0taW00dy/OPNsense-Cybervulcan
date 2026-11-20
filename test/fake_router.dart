import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:opnsense_cybervulcan/src/api/opnsense_client.dart';

/// In-memory OPNsense stand-in that mimics the response shapes of
/// opnsense/core 26.x for the endpoints Cybervulcan uses.
class FakeRouter {
  FakeRouter({this.apiKey = 'k', this.apiSecret = 's'});

  final String apiKey;
  final String apiSecret;

  /// Runtime pf tables; only names listed here "exist" as aliases.
  final Map<String, List<String>> tables = {
    'BYPASS_ALL': [],
    'PCMODE_CLEAR': [],
  };

  /// Endpoints (path prefixes) that answer 403, to simulate missing privileges.
  final Set<String> forbidden = {};

  List<Map<String, dynamic>> gateways = [
    gw('WG_MAIN_GW', 'none', '18.2 ms', '0.0 %'),
    gw('WG_BACKUP_GW', 'none', '24.9 ms', '0.0 %'),
    gw('WAN_DHCP', 'none', '9.1 ms', '0.0 %'),
  ];

  List<Map<String, dynamic>> leases = [];

  // ---- v2.0 WireGuard (server switcher)
  static const keyA = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
  static const keyB = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';
  List<Map<String, dynamic>> wgClients = [
    {
      'uuid': '11111111-1111-4111-8111-111111111111',
      'enabled': '1',
      'name': 'Proton_446',
      'pubkey': keyA,
      'privkey': 'PRIVATE-MUST-NOT-LEAK',
      'psk': 'PSK-MUST-NOT-LEAK',
      'serveraddress': '149.36.48.154',
      'serverport': '51820',
      '%servers': 'Proton_VPN_Main',
    },
    {
      'uuid': '22222222-2222-4222-8222-222222222222',
      'enabled': '1',
      'name': 'Proton_1077',
      'pubkey': keyB,
      'privkey': 'PRIVATE-MUST-NOT-LEAK',
      'psk': '',
      'serveraddress': '149.34.251.130',
      'serverport': '51820',
      '%servers': 'Proton_VPN_Failover',
    },
  ];

  /// Gateway delay (ms) reported while a tunnel points at this server IP.
  Map<String, double> delayByServer = {};
  int wgReconfigures = 0;

  /// WireGuard instances (uuid -> name).
  Map<String, String> wgInstanceNames = {
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa': 'Proton_VPN_Main',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb': 'Proton_VPN_Failover',
  };

  /// Server IPs that never complete a handshake (key refused).
  Set<String> deadServers = {};
  int routeReconfigures = 0;
  final List<String> monitorRestarts = [];
  List<Map<String, dynamic>> dotRows = [];

  /// Filters received by kill_states, in order.
  final List<String> killedFilters = [];

  /// Simulate the router dropping the kill request's own connection.
  bool dropKillReply = false;
  List<Map<String, dynamic>> rules = [];
  final List<http.Request> requests = [];

  static Map<String, dynamic> gw(String name, String status, String delay, String loss) => {
        'name': name,
        'address': '10.2.0.1',
        'status': status,
        'loss': loss,
        'delay': delay,
        'stddev': '1.1 ms',
        'monitor': name == 'WG_MAIN_GW' ? '1.0.0.1' : '8.8.4.4',
        'status_translated': status == 'none' ? 'Online' : 'Offline',
      };

  OpnsenseClient client() => OpnsenseClient(
        baseUrl: Uri.parse('https://10.10.10.254/'),
        apiKey: apiKey,
        apiSecret: apiSecret,
        httpClient: MockClient(_handle),
      );

  Future<http.Response> _handle(http.Request r) async {
    requests.add(r);
    final expected = 'Basic ${base64Encode(utf8.encode('$apiKey:$apiSecret'))}';
    if (r.headers['Authorization'] != expected) return http.Response('', 401);
    final path = r.url.path;
    if (forbidden.any(path.startsWith)) return http.Response('{"status":403}', 403);

    http.Response json(Object o) =>
        http.Response(jsonEncode(o), 200, headers: {'content-type': 'application/json'});

    if (path == '/api/routes/gateway/status') {
      String? serverOf(String instance) {
        for (final c in wgClients) {
          if (c['%servers'] == instance) return c['serveraddress'] as String;
        }
        return null;
      }

      final items = [
        for (final g in gateways)
          {
            ...g,
            if (g['name'] == 'WG_MAIN_GW' && delayByServer.containsKey(serverOf('Proton_VPN_Main')))
              'delay': '${delayByServer[serverOf('Proton_VPN_Main')]} ms',
            if (g['name'] == 'WG_BACKUP_GW' && delayByServer.containsKey(serverOf('Proton_VPN_Failover')))
              'delay': '${delayByServer[serverOf('Proton_VPN_Failover')]} ms',
          },
      ];
      return json({'items': items, 'status': 'ok'});
    }
    if (path == '/api/wireguard/client/search_client') {
      return json({'total': wgClients.length, 'rowCount': wgClients.length, 'current': 1, 'rows': wgClients});
    }
    final setClient = RegExp(r'^/api/wireguard/client/set_client/([0-9a-f-]{36})$').firstMatch(path);
    if (setClient != null) {
      final c = wgClients.where((x) => x['uuid'] == setClient.group(1)).firstOrNull;
      if (c == null) return json({'result': 'failed'});
      final body = ((jsonDecode(r.body) as Map)['client'] as Map).cast<String, dynamic>();
      // Like the real router: a relation field that is not posted is cleared.
      final servers = '${body.remove('servers') ?? ''}';
      c['%servers'] = [
        for (final u in servers.split(','))
          if (wgInstanceNames.containsKey(u.trim())) wgInstanceNames[u.trim()],
      ].join(',');
      c.addAll(body);
      return json({'result': 'saved'});
    }
    final getClient = RegExp(r'^/api/wireguard/client/get_client/([0-9a-f-]{36})$').firstMatch(path);
    if (getClient != null) {
      final c = wgClients.where((x) => x['uuid'] == getClient.group(1)).firstOrNull;
      if (c == null) return json({});
      final linked = '${c['%servers'] ?? ''}'.split(',');
      return json({
        'client': {
          'servers': {
            for (final e in wgInstanceNames.entries)
              e.key: {'value': e.value, 'selected': linked.contains(e.value) ? 1 : 0},
          },
          'privkey': 'PRIVATE-MUST-NOT-LEAK',
        },
      });
    }
    if (path == '/api/wireguard/server/search_server') {
      return json({
        'rows': [
          for (final e in wgInstanceNames.entries) {'uuid': e.key, 'name': e.value, 'privkey': 'PRIVATE-MUST-NOT-LEAK'},
        ],
      });
    }
    if (path == '/api/wireguard/service/reconfigure') {
      wgReconfigures++;
      return json({'result': 'ok'});
    }
    if (path == '/api/routes/routes/reconfigure') {
      routeReconfigures++;
      return json({'status': 'ok'});
    }
    final dp = RegExp(r'^/api/core/service/restart/dpinger/([\w.-]+)$').firstMatch(path);
    if (dp != null) {
      monitorRestarts.add(dp.group(1)!);
      return json({'result': 'ok'});
    }
    if (path == '/api/wireguard/service/show') {
      return json({
        'rows': [
          for (final c in wgClients)
            {
              'type': 'peer',
              'name': c['name'],
              'ifname': c['%servers'],
              'endpoint': '${c['serveraddress']}:${c['serverport']}',
              'latest-handshake-age': deadServers.contains(c['serveraddress']) ? null : 12,
              'transfer-rx': deadServers.contains(c['serveraddress']) ? 0 : 4096,
              'peer-status': deadServers.contains(c['serveraddress']) ? 'stale' : 'online',
            },
        ],
      });
    }
    if (path == '/api/unbound/settings/search_dot') {
      return json({'rows': dotRows});
    }
    final alias = RegExp(r'^/api/firewall/alias_util/(list|add|delete|flush)/(\w+)$').firstMatch(path);
    if (alias != null) {
      final op = alias.group(1)!;
      final name = alias.group(2)!;
      final table = tables[name];
      if (op == 'list') {
        final rows = [for (final ip in table ?? <String>[]) {'ip': ip}];
        return json({'total': rows.length, 'rowCount': rows.length, 'current': 1, 'rows': rows});
      }
      if (r.method != 'POST') return json({'status': 'failed'});
      if (table == null) return json({'status': 'failed', 'status_msg': 'nonexistent alias $name'});
      final body = r.body.isEmpty ? <String, dynamic>{} : jsonDecode(r.body) as Map<String, dynamic>;
      // pf shows hosts without /32.
      String norm(String a) => a.endsWith('/32') ? a.substring(0, a.length - 3) : a;
      switch (op) {
        case 'add':
          final a = norm(body['address'] as String);
          if (!table.contains(a)) table.add(a);
        case 'delete':
          table.remove(norm(body['address'] as String));
        case 'flush':
          table.clear();
      }
      return json({'status': 'done'});
    }
    if (path == '/api/diagnostics/firewall/kill_states') {
      if (r.method != 'POST') return json({'result': 'failed'});
      killedFilters.add((jsonDecode(r.body) as Map)['filter'] as String);
      if (dropKillReply) throw http.ClientException('Connection reset by peer', r.url);
      return json({'result': 'ok', 'dropped_states': 3});
    }
    if (path == '/api/dnsmasq/leases/search') {
      return json({'total': leases.length, 'rowCount': leases.length, 'current': 1, 'rows': leases, 'interfaces': {}});
    }
    if (path == '/api/firewall/filter/search_rule') {
      final phrase = (jsonDecode(r.body) as Map)['searchPhrase'] as String;
      final rows = rules.where((x) => jsonEncode(x).contains(phrase)).toList();
      return json({'total': rows.length, 'rowCount': rows.length, 'current': 1, 'rows': rows});
    }
    if (path == '/api/firewall/filter_util/rule_stats') {
      return json({
        'status': 'ok',
        'stats': {
          for (final x in rules)
            if (x['enabled'] == '1') x['uuid']: {'pf_rules': 1, 'packets': 42},
        },
      });
    }
    return http.Response('not found', 404);
  }
}
