import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

/// What the app asks the native tunnel for: one WireGuard peer (the home
/// router) and one TCP destination behind it.
class TunnelSpec {
  const TunnelSpec({
    required this.privateKey,
    required this.peerPublicKey,
    this.presharedKey,
    required this.endpoint,
    required this.address,
    required this.allowedIps,
    required this.keepalive,
    required this.target,
    required this.token,
    this.mtu = 1280,
  });

  final String privateKey;
  final String peerPublicKey;
  final String? presharedKey;

  /// Resolved `ip:port` (`[v6]:port`).
  final String endpoint;
  final String address;
  final List<String> allowedIps;
  final int keepalive;

  /// `ip:port` of the router's web/API port.
  final String target;

  /// Access token (base64, 32 bytes) the forwarder demands first on every connection.
  final String token;
  final int mtu;

  Map<String, Object?> toJson() => {
        'privateKey': privateKey,
        'peerPublicKey': peerPublicKey,
        if (presharedKey != null && presharedKey!.isNotEmpty) 'presharedKey': presharedKey,
        'endpoint': endpoint,
        'address': address,
        'allowedIPs': allowedIps,
        'keepalive': keepalive,
        'target': target,
        'token': token,
        'mtu': mtu,
      };

  /// For logs and error messages: no keys, no token.
  @override
  String toString() => 'TunnelSpec($endpoint, $address -> $target)';
}

class TunnelStatus {
  const TunnelStatus({this.up = false, this.port, this.lastHandshake, this.rxBytes = 0, this.txBytes = 0, this.lastError});

  final bool up;
  final int? port;
  final DateTime? lastHandshake;
  final int rxBytes;
  final int txBytes;
  final String? lastError;

  factory TunnelStatus.fromJson(Map<String, dynamic> j) {
    int n(String k) => (j[k] is num) ? (j[k] as num).toInt() : 0;
    final hs = n('lastHandshake');
    return TunnelStatus(
      up: j['up'] == true,
      port: j['port'] is num ? (j['port'] as num).toInt() : null,
      lastHandshake: hs > 0 ? DateTime.fromMillisecondsSinceEpoch(hs * 1000, isUtc: true) : null,
      rxBytes: n('rx'),
      txBytes: n('tx'),
      lastError: j['lastError'] is String && (j['lastError'] as String).isNotEmpty
          ? j['lastError'] as String
          : null,
    );
  }
}

class TunnelException implements Exception {
  TunnelException(this.message);
  final String message;
  @override
  String toString() => 'TunnelException: $message';
}

/// App-only (user-space) WireGuard tunnel. It does not use Android's
/// VpnService or a Windows network adapter, so a system VPN app (Proton) can
/// stay on.
abstract class AppTunnel {
  /// False when the native library is missing on this platform/build.
  bool get isAvailable;

  /// Why [isAvailable] is false (for Settings).
  String? get unavailableReason;

  bool get isUp;

  /// Starts (or replaces) the tunnel. Returns the loopback forwarder port.
  Future<int> up(TunnelSpec spec);

  Future<void> down();

  TunnelStatus status();
}

/// Used where no native library exists (unit tests, unsupported platforms).
class UnavailableTunnel implements AppTunnel {
  const UnavailableTunnel([this.unavailableReason = 'Remote access is not available on this platform.']);

  @override
  final String? unavailableReason;
  @override
  bool get isAvailable => false;
  @override
  bool get isUp => false;
  @override
  Future<int> up(TunnelSpec spec) async => throw TunnelException(unavailableReason ?? 'unavailable');
  @override
  Future<void> down() async {}
  @override
  TunnelStatus status() => const TunnelStatus();
}

typedef _StrFn = Pointer<Utf8> Function();
typedef _UpFn = Pointer<Utf8> Function(Pointer<Utf8>);
typedef _VoidC = Void Function();
typedef _VoidD = void Function();
typedef _FreeC = Void Function(Pointer<Utf8>);
typedef _FreeD = void Function(Pointer<Utf8>);

/// wireguard-go + gVisor netstack, built from native/cvwg as libcvwg.so
/// (Android) / cvwg.dll (Windows) and called through dart:ffi.
class NativeTunnel implements AppTunnel {
  NativeTunnel._(this._lib)
      : _version = _lib.lookupFunction<_StrFn, _StrFn>('cvwg_version'),
        _up = _lib.lookupFunction<_UpFn, _UpFn>('cvwg_up'),
        _status = _lib.lookupFunction<_StrFn, _StrFn>('cvwg_status'),
        _down = _lib.lookupFunction<_VoidC, _VoidD>('cvwg_down'),
        _free = _lib.lookupFunction<_FreeC, _FreeD>('cvwg_free');

  // Kept alive for the lifetime of the process.
  // ignore: unused_field
  final DynamicLibrary _lib;
  final Pointer<Utf8> Function() _version;
  final Pointer<Utf8> Function(Pointer<Utf8>) _up;
  final Pointer<Utf8> Function() _status;
  final void Function() _down;
  final void Function(Pointer<Utf8>) _free;
  bool _isUp = false;

  static String get libraryName => Platform.isWindows ? 'cvwg.dll' : 'libcvwg.so';

  /// Loads the native library, or returns an [UnavailableTunnel] saying why not.
  static AppTunnel load() {
    if (!(Platform.isAndroid || Platform.isWindows)) {
      return const UnavailableTunnel();
    }
    try {
      return NativeTunnel._(DynamicLibrary.open(libraryName));
    } on Object catch (e) {
      return UnavailableTunnel('The remote-access library ($libraryName) is missing from this build: $e');
    }
  }

  String _take(Pointer<Utf8> p) {
    try {
      return p.toDartString();
    } finally {
      _free(p);
    }
  }

  String get version => _take(_version());

  @override
  bool get isAvailable => true;
  @override
  String? get unavailableReason => null;
  @override
  bool get isUp => _isUp;

  @override
  Future<int> up(TunnelSpec spec) async {
    final arg = jsonEncode(spec.toJson()).toNativeUtf8();
    final String out;
    try {
      out = _take(_up(arg));
    } finally {
      // The JSON holds the private key: wipe it before freeing.
      final bytes = arg.cast<Uint8>();
      var i = 0;
      while (bytes[i] != 0) {
        bytes[i++] = 0;
      }
      malloc.free(arg);
    }
    final j = jsonDecode(out);
    if (j is Map && j['port'] is num) {
      _isUp = true;
      return (j['port'] as num).toInt();
    }
    _isUp = false;
    throw TunnelException(j is Map && j['error'] != null ? '${j['error']}' : 'tunnel did not start');
  }

  @override
  Future<void> down() async {
    _down();
    _isUp = false;
  }

  @override
  TunnelStatus status() {
    try {
      final j = jsonDecode(_take(_status()));
      return j is Map<String, dynamic> ? TunnelStatus.fromJson(j) : const TunnelStatus();
    } on FormatException {
      return const TunnelStatus();
    }
  }
}
