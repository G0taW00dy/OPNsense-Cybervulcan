import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';
import 'package:path_provider/path_provider.dart';

import 'tunnel.dart';

/// What the app asks the built-in Tailscale engine for: a node (state folder,
/// device name) and the one TCP destination its loopback forwarder may reach.
class TailscaleSpec {
  const TailscaleSpec({
    required this.stateDir,
    required this.hostname,
    required this.target,
    required this.token,
    this.controlUrl,
  });

  /// App-private folder; the node key and login live in `<stateDir>/tsnet`.
  final String stateDir;

  /// Name in the Tailscale admin console (cleaned up to a DNS label natively).
  final String hostname;

  /// `ip:port` (router LAN IP through its subnet route, or its 100.x address)
  /// or `magicdns-name:port`.
  final String target;

  /// Access token (base64, 32 bytes) the forwarder demands first, as for WireGuard.
  final String token;

  /// Coordination server; null = Tailscale's own.
  final String? controlUrl;

  Map<String, Object?> toJson() => {
        'stateDir': stateDir,
        'hostname': hostname,
        'target': target,
        'token': token,
        if (controlUrl != null && controlUrl!.isNotEmpty) 'controlURL': controlUrl,
      };

  /// For logs: no token.
  @override
  String toString() => 'TailscaleSpec($hostname -> $target)';
}

enum TailscaleState { stopped, starting, needsLogin, needsApproval, running, error }

TailscaleState _parseState(Object? s) => switch (s) {
      'starting' => TailscaleState.starting,
      'needs_login' => TailscaleState.needsLogin,
      'needs_approval' => TailscaleState.needsApproval,
      'running' => TailscaleState.running,
      'error' => TailscaleState.error,
      _ => TailscaleState.stopped,
    };

class TailscaleStatus {
  const TailscaleStatus({
    this.up = false,
    this.state = TailscaleState.stopped,
    this.port,
    this.authUrl,
    this.tailnetIp,
    this.peerOnline,
    this.peerFound = false,
    this.direct = false,
    this.derp,
    this.keyExpiry,
    this.health = const [],
    this.lastError,
  });

  final bool up;
  final TailscaleState state;

  /// Loopback forwarder port.
  final int? port;

  /// Open in a browser to sign in (while [state] is needsLogin).
  final String? authUrl;

  /// This device's 100.x address.
  final String? tailnetIp;

  /// The node carrying the router (router itself / its subnet route) is
  /// online; null when no such node is visible (route not approved?).
  final bool? peerOnline;
  final bool peerFound;

  /// Peer-to-peer path (false = through a Tailscale relay, see [derp]).
  final bool direct;

  /// Relay region code (e.g. "syd") while there is no direct path.
  final String? derp;

  /// When this device's Tailscale key expires (null = never / unknown).
  final DateTime? keyExpiry;
  final List<String> health;
  final String? lastError;

  bool get running => state == TailscaleState.running;

  factory TailscaleStatus.fromJson(Map<String, dynamic> j) {
    String? s(String k) => j[k] is String && (j[k] as String).isNotEmpty ? j[k] as String : null;
    final exp = j['keyExpiry'] is num ? (j['keyExpiry'] as num).toInt() : 0;
    return TailscaleStatus(
      up: j['up'] == true,
      state: _parseState(j['state']),
      port: j['port'] is num && (j['port'] as num) > 0 ? (j['port'] as num).toInt() : null,
      authUrl: s('authUrl'),
      tailnetIp: s('tailnetIp'),
      peerOnline: j['peerOnline'] is bool ? j['peerOnline'] as bool : null,
      peerFound: j['peerFound'] == true,
      direct: j['direct'] == true,
      derp: s('derp'),
      keyExpiry: exp > 0 ? DateTime.fromMillisecondsSinceEpoch(exp * 1000, isUtc: true) : null,
      health: [for (final h in (j['health'] is List ? j['health'] as List : const [])) '$h'],
      lastError: s('lastError'),
    );
  }

  /// One plain-English line for Settings / diagnostics.
  String describe() => switch (state) {
        TailscaleState.stopped => 'Off',
        TailscaleState.starting => 'Starting...',
        TailscaleState.needsLogin => 'Not signed in - tap "Sign in to Tailscale"',
        TailscaleState.needsApproval =>
          'Signed in - waiting for approval in the Tailscale admin console (Machines)',
        TailscaleState.error => 'Problem: ${lastError ?? 'the engine stopped'}',
        TailscaleState.running => [
            'Connected${tailnetIp != null ? ' as $tailnetIp' : ''}',
            if (!peerFound)
              'router not visible - approve its subnet route in the admin console'
            else if (peerOnline == false)
              'router offline'
            else if (direct)
              'router reachable directly'
            else if (derp != null)
              'router reachable via relay ($derp)',
          ].join(' - '),
      };
}

class TailscaleException implements Exception {
  TailscaleException(this.message);
  final String message;
  @override
  String toString() => 'TailscaleException: $message';
}

/// Tailscale built into the app (tsnet in the native library): user space,
/// no TUN, no VpnService, no admin rights, no separate Tailscale app.
abstract class TailscaleEngine {
  /// False when the native library is missing or too old.
  bool get isAvailable;

  /// Why [isAvailable] is false (for Settings).
  String? get unavailableReason;

  /// True between a successful [start] and [down]/[logout].
  bool get isUp;

  /// Starts (or keeps, when [spec] is unchanged) the engine. Returns at once;
  /// poll [status] until running / needsLogin.
  Future<TailscaleStatus> start(TailscaleSpec spec);

  TailscaleStatus status();

  /// Stops the engine; the login is kept.
  Future<void> down();

  /// Signs out (the device key is expired at Tailscale when the engine is
  /// running), stops and deletes the saved login in [stateDir].
  Future<void> logout(String stateDir);
}

/// Used where no native library exists (unit tests, unsupported platforms).
class UnavailableTailscale implements TailscaleEngine {
  const UnavailableTailscale([this.unavailableReason = 'Built-in Tailscale is not available on this platform.']);

  @override
  final String? unavailableReason;
  @override
  bool get isAvailable => false;
  @override
  bool get isUp => false;
  @override
  Future<TailscaleStatus> start(TailscaleSpec spec) async => throw TailscaleException(unavailableReason ?? 'unavailable');
  @override
  TailscaleStatus status() => const TailscaleStatus();
  @override
  Future<void> down() async {}
  @override
  Future<void> logout(String stateDir) async {}
}

typedef _StrArgC = Pointer<Utf8> Function(Pointer<Utf8>);
typedef _StrC = Pointer<Utf8> Function();
typedef _VoidC = Void Function();
typedef _VoidD = void Function();
typedef _FreeC = Void Function(Pointer<Utf8>);
typedef _FreeD = void Function(Pointer<Utf8>);

/// The cvts_* exports of the same native library as [NativeTunnel] (one Go
/// runtime per process). Calls that can take a while (start, down, logout)
/// run on a helper isolate so the UI never freezes; status is quick.
class NativeTailscale implements TailscaleEngine {
  NativeTailscale._(DynamicLibrary lib)
      : _startAddr = lib.lookup<NativeFunction<_StrArgC>>('cvts_start').address,
        _logoutAddr = lib.lookup<NativeFunction<_StrArgC>>('cvts_logout').address,
        _downAddr = lib.lookup<NativeFunction<_VoidC>>('cvts_down').address,
        _freeAddr = lib.lookup<NativeFunction<_FreeC>>('cvwg_free').address,
        _status = lib.lookupFunction<_StrC, _StrC>('cvts_status'),
        _free = lib.lookupFunction<_FreeC, _FreeD>('cvwg_free');

  final int _startAddr;
  final int _logoutAddr;
  final int _downAddr;
  final int _freeAddr;
  final Pointer<Utf8> Function() _status;
  final void Function(Pointer<Utf8>) _free;
  bool _isUp = false;

  /// Uses the library [tunnel] already loaded, or explains why not.
  static TailscaleEngine fromTunnel(AppTunnel tunnel) {
    if (tunnel is! NativeTunnel) {
      return UnavailableTailscale(tunnel.unavailableReason ?? 'Built-in Tailscale is not available on this platform.');
    }
    try {
      return NativeTailscale._(tunnel.library);
    } on Object {
      return const UnavailableTailscale(
          'This build\'s remote-access library has no built-in Tailscale - update the app.');
    }
  }

  /// Calls `char* fn(const char*)` by address (usable from any isolate) and
  /// wipes the argument (it holds the access token) before freeing it.
  static String _callStr(int fnAddr, int freeAddr, String? arg) {
    final fn = Pointer<NativeFunction<_StrArgC>>.fromAddress(fnAddr).asFunction<_StrArgC>();
    final free = Pointer<NativeFunction<_FreeC>>.fromAddress(freeAddr).asFunction<_FreeD>();
    final a = arg?.toNativeUtf8() ?? nullptr;
    try {
      final r = fn(a);
      try {
        return r.toDartString();
      } finally {
        free(r);
      }
    } finally {
      if (a != nullptr) {
        final bytes = a.cast<Uint8>();
        var i = 0;
        while (bytes[i] != 0) {
          bytes[i++] = 0;
        }
        malloc.free(a);
      }
    }
  }

  // Static so the isolate closures capture only these primitives.
  static Future<String> _runStr(int fn, int free, String? arg) => Isolate.run(() => _callStr(fn, free, arg));
  static Future<void> _runVoid(int fn) =>
      Isolate.run(() => Pointer<NativeFunction<_VoidC>>.fromAddress(fn).asFunction<_VoidD>()());

  static Map<String, dynamic> _decode(String s) {
    try {
      final j = jsonDecode(s);
      return j is Map<String, dynamic> ? j : const {'error': 'bad answer from the engine'};
    } on FormatException {
      return const {'error': 'bad answer from the engine'};
    }
  }

  @override
  bool get isAvailable => true;
  @override
  String? get unavailableReason => null;
  @override
  bool get isUp => _isUp;

  @override
  Future<TailscaleStatus> start(TailscaleSpec spec) async {
    final j = _decode(await _runStr(_startAddr, _freeAddr, jsonEncode(spec.toJson())));
    if (j['error'] != null) {
      _isUp = false;
      throw TailscaleException('${j['error']}');
    }
    _isUp = true;
    return TailscaleStatus.fromJson(j);
  }

  @override
  TailscaleStatus status() {
    final p = _status();
    final String s;
    try {
      s = p.toDartString();
    } finally {
      _free(p);
    }
    final j = _decode(s);
    return j['error'] != null ? const TailscaleStatus() : TailscaleStatus.fromJson(j);
  }

  @override
  Future<void> down() async {
    _isUp = false;
    await _runVoid(_downAddr);
  }

  @override
  Future<void> logout(String stateDir) async {
    _isUp = false;
    final j = _decode(await _runStr(_logoutAddr, _freeAddr, jsonEncode({'stateDir': stateDir})));
    if (j['error'] != null) throw TailscaleException('${j['error']}');
  }
}

/// `<app support folder>/tailscale` (private to the app, kept across updates).
Future<String> defaultTailscaleStateDir() async {
  final base = await getApplicationSupportDirectory();
  return '${base.path}${Platform.pathSeparator}tailscale';
}

/// Name shown in the Tailscale admin console: `cybervulcan-<computer name>`
/// on Windows, `cybervulcan-android` on phones (Tailscale adds -1, -2 ...
/// when several devices share a name).
String defaultTailscaleHostname() {
  if (Platform.isWindows) {
    try {
      return 'cybervulcan-${Platform.localHostname}';
    } on Object {
      return 'cybervulcan-windows';
    }
  }
  return Platform.isAndroid ? 'cybervulcan-android' : 'cybervulcan';
}
