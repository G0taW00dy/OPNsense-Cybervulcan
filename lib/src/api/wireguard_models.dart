/// WireGuard / DNS models for the v2.0 features (server switcher, Tests).
///
/// Shapes verified against OPNsense 26.7 on the house router:
/// * `POST /api/wireguard/client/search_client` -> `{rows: [{uuid, enabled,
///   name, pubkey, serveraddress, serverport, servers, "%servers", ...}]}`.
///   The rows also carry `privkey` / `psk`: those are never read or kept.
/// * `GET /api/wireguard/service/show` -> `{rows: [{if, type: interface|peer,
///   name, ifname, endpoint, public-key, latest-handshake-age, peer-status,
///   transfer-rx, transfer-tx}]}`.
/// * `POST /api/unbound/settings/search_dot` -> `{rows: [{enabled, type,
///   server, port, verify, description}]}`.
library;

int? _int(Object? v) => v is num ? v.toInt() : int.tryParse('${v ?? ''}');
bool _on(Object? v) => v == true || v == 1 || v == '1';

/// A configured WireGuard peer (OPNsense calls them "clients"). Only public
/// data: the private and pre-shared keys in the API row are dropped here.
class WgPeer {
  const WgPeer({
    required this.uuid,
    required this.name,
    required this.enabled,
    required this.serverAddress,
    required this.serverPort,
    required this.publicKey,
    required this.instanceNames,
  });

  final String uuid;
  final String name;
  final bool enabled;
  final String serverAddress;
  final int serverPort;
  final String publicKey;

  /// Names of the instances this peer belongs to (`%servers`).
  final List<String> instanceNames;

  factory WgPeer.fromJson(Map<String, dynamic> j) => WgPeer(
        uuid: '${j['uuid'] ?? ''}',
        name: '${j['name'] ?? ''}',
        enabled: _on(j['enabled']),
        serverAddress: '${j['serveraddress'] ?? ''}'.trim(),
        serverPort: _int(j['serverport']) ?? 51820,
        publicKey: '${j['pubkey'] ?? ''}'.trim(),
        instanceNames: [
          for (final n in '${j['%servers'] ?? ''}'.split(','))
            if (n.trim().isNotEmpty) n.trim(),
        ],
      );

  bool belongsTo(String instance) =>
      instanceNames.any((n) => n.toLowerCase() == instance.trim().toLowerCase());
}

/// Runtime state of a WireGuard interface or peer (`wg show`).
class WgRuntime {
  const WgRuntime({
    required this.isPeer,
    required this.name,
    required this.interfaceName,
    this.endpoint,
    this.publicKey,
    this.handshakeAgeSeconds,
    this.online = false,
    this.rxBytes,
    this.txBytes,
  });

  final bool isPeer;
  final String name;
  final String interfaceName;
  final String? endpoint;
  final String? publicKey;
  final int? handshakeAgeSeconds;
  final bool online;
  final int? rxBytes;
  final int? txBytes;

  factory WgRuntime.fromJson(Map<String, dynamic> j) => WgRuntime(
        isPeer: j['type'] == 'peer',
        name: '${j['name'] ?? ''}',
        interfaceName: '${j['ifname'] ?? ''}',
        endpoint: j['endpoint']?.toString(),
        publicKey: j['public-key']?.toString(),
        handshakeAgeSeconds: _int(j['latest-handshake-age']),
        online: '${j['peer-status'] ?? j['status']}' == 'online',
        rxBytes: _int(j['transfer-rx']),
        txBytes: _int(j['transfer-tx']),
      );
}

/// An encrypted DNS forwarder configured in Unbound.
class DotServer {
  const DotServer({required this.enabled, required this.type, required this.server, this.port, this.verify});

  final bool enabled;
  final String type;
  final String server;
  final int? port;
  final String? verify;

  bool get isTls => type.toLowerCase() == 'dot';

  factory DotServer.fromJson(Map<String, dynamic> j) => DotServer(
        enabled: _on(j['enabled']),
        type: '${j['type'] ?? ''}',
        server: '${j['server'] ?? ''}',
        port: _int(j['port']),
        verify: (j['verify']?.toString().trim().isEmpty ?? true) ? null : j['verify'].toString(),
      );
}
