import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

import '../core/config.dart';
import '../core/storage.dart';

// Windows "home link": the remote access modes `home` (home devices such as
// the NAS) and `everything` (all PC traffic via the house) through a Wintun
// network adapter named "Cybervulcan".
//
// The adapter needs admin rights, so cvwg.dll starts a small elevated helper
// (this app's exe with --vpn-helper) through the UAC prompt the first time a
// mode is turned on, and talks to it over a named pipe only this Windows
// user can open. Turning the mode off removes the adapter, its routes and
// DNS and ends the helper; the next turn-on asks again. Mode `app` (the
// default) never comes here: it is the user-space tunnel in net/tunnel.dart.

/// Modes that use the adapter.
const homeLinkModes = {'home', 'everything'};

/// What cvvpn_start receives. Field names match winvpn.StartRequest (Go);
/// test/fixtures/home_link_request.json pins the contract on both sides.
class HomeLinkRequest {
  const HomeLinkRequest({
    required this.mode,
    required this.privateKey,
    required this.peerPublicKey,
    this.presharedKey,
    required this.endpoint,
    required this.address,
    required this.routerIp,
    this.homeCidrs = const [],
    required this.keepalive,
    this.mtu = 1280,
  });

  /// `home` or `everything`.
  final String mode;
  final String privateKey;
  final String peerPublicKey;
  final String? presharedKey;

  /// Resolved `ip:port` (`[v6]:port`) of the router's WireGuard port.
  final String endpoint;

  /// This PC's tunnel address, e.g. 10.10.99.2/32.
  final String address;

  /// Router LAN IPv4: always reachable; the DNS server in `everything`.
  final String routerIp;

  /// Home devices for `home` mode (canonical CIDRs).
  final List<String> homeCidrs;
  final int keepalive;
  final int mtu;

  /// Builds the request from the settings, or null when [AppConfig.mode] is
  /// `app` (no adapter). [endpoint] is the resolved `ip:port`.
  static HomeLinkRequest? fromConfig(AppConfig cfg, WireGuardSecrets secrets, String endpoint) {
    final mode = cfg.mode;
    if (!homeLinkModes.contains(mode)) return null;
    return HomeLinkRequest(
      mode: mode,
      privateKey: secrets.privateKey ?? '',
      peerPublicKey: (cfg.wgServerPublicKey ?? '').trim(),
      presharedKey: secrets.presharedKey,
      endpoint: endpoint,
      address: cfg.wgAddress.trim(),
      routerIp: cfg.routerTunnelIp ?? '',
      homeCidrs: mode == 'home' ? cfg.homeDeviceCidrs : const [],
      keepalive: cfg.wgKeepalive,
    );
  }

  Map<String, Object?> toJson() => {
        'mode': mode,
        'privateKey': privateKey,
        'peerPublicKey': peerPublicKey,
        if (presharedKey != null && presharedKey!.isNotEmpty) 'presharedKey': presharedKey,
        'endpoint': endpoint,
        'address': address,
        'routerIp': routerIp,
        if (homeCidrs.isNotEmpty) 'homeCidrs': homeCidrs,
        'keepalive': keepalive,
        'mtu': mtu,
      };

  /// For logs and errors: no keys.
  @override
  String toString() => 'HomeLinkRequest($mode, $address via $endpoint)';
}

/// State of the adapter session (winvpn.Status).
enum HomeLinkState { off, starting, on, error }

class HomeLinkStatus {
  const HomeLinkStatus({
    this.state = HomeLinkState.off,
    this.mode,
    this.lastHandshake,
    this.rxBytes = 0,
    this.txBytes = 0,
    this.error,
  });

  final HomeLinkState state;
  final String? mode;
  final DateTime? lastHandshake;
  final int rxBytes;
  final int txBytes;

  /// Plain English, set when [state] is [HomeLinkState.error].
  final String? error;

  bool get on => state == HomeLinkState.on;

  static const off = HomeLinkStatus();

  factory HomeLinkStatus.fromJson(Map<String, dynamic> j) {
    int n(String k) => (j[k] is num) ? (j[k] as num).toInt() : 0;
    final hs = n('lastHandshake');
    final s = j['state'];
    final err = j['error'];
    return HomeLinkStatus(
      state: switch (s) {
        'starting' => HomeLinkState.starting,
        'on' => HomeLinkState.on,
        'error' => HomeLinkState.error,
        _ => HomeLinkState.off,
      },
      mode: j['mode'] is String && (j['mode'] as String).isNotEmpty ? j['mode'] as String : null,
      lastHandshake: hs > 0 ? DateTime.fromMillisecondsSinceEpoch(hs * 1000, isUtc: true) : null,
      rxBytes: n('rx'),
      txBytes: n('tx'),
      error: err is String && err.isNotEmpty ? err : null,
    );
  }

  /// One line for Settings / the status card.
  String describe() => switch (state) {
        HomeLinkState.off => 'Off',
        HomeLinkState.starting => 'Waiting for the admin prompt...',
        HomeLinkState.on => mode == 'everything'
            ? 'On - all of this PC\'s traffic goes via the house'
            : 'On - home devices reachable',
        HomeLinkState.error => error ?? 'The home link could not be turned on.',
      };
}

class HomeLinkException implements Exception {
  HomeLinkException(this.message);

  /// Plain English.
  final String message;
  @override
  String toString() => message;
}

/// The three C functions of cvwg.dll (exports_vpn_windows.go). An interface
/// so tests can fake the DLL.
abstract class HomeLinkNative {
  /// Returns `{"ok":true}` or `{"error":"..."}`.
  String start(String requestJson);
  String status();
  void stop();
}

/// Windows implementation of the remote access modes `home` / `everything`.
///
/// Merge note: implements the platform-neutral vpn-modes interface
/// (lib/src/platform/vpn_modes.dart, agent/android-vpn) once that lands;
/// the controller calls [start] when remote access is on, the mode is not
/// `app` and the PC is away from home, and [stop] when back home, when the
/// mode goes back to `app` or when remote access is turned off.
class WindowsVpnModes {
  WindowsVpnModes(this._native, {this.pollInterval = const Duration(milliseconds: 300)});

  final HomeLinkNative? _native;
  final Duration pollInterval;

  /// Loads cvwg.dll's home link functions (Windows only).
  static WindowsVpnModes load() {
    if (!Platform.isWindows) return WindowsVpnModes(null);
    try {
      return WindowsVpnModes(_FfiHomeLink(DynamicLibrary.open('cvwg.dll')));
    } on Object {
      return WindowsVpnModes(null);
    }
  }

  bool get isAvailable => _native != null;

  /// Why [isAvailable] is false (for Settings).
  String? get unavailableReason => isAvailable
      ? null
      : Platform.isWindows
          ? 'This build has no home link library (cvwg.dll) - reinstall Cybervulcan.'
          : '"Home devices" and "Everything" on this device are handled by the phone app.';

  /// Turns the adapter on for [r]: shows the UAC prompt (first time), then
  /// waits until the helper reports on / error, at most [timeout] (the
  /// prompt waits for the user). Throws [HomeLinkException] with a
  /// plain-English message.
  Future<HomeLinkStatus> start(HomeLinkRequest r, {Duration timeout = const Duration(minutes: 3)}) async {
    final native = _native;
    if (native == null) throw HomeLinkException(unavailableReason!);
    final out = native.start(jsonEncode(r.toJson()));
    final j = _decode(out);
    if (j['ok'] != true) {
      throw HomeLinkException(friendlyHomeLinkError(j['error'] is String ? j['error'] as String : null));
    }
    final deadline = DateTime.now().add(timeout);
    while (true) {
      final s = status();
      if (s.state == HomeLinkState.on) return s;
      if (s.state == HomeLinkState.error) throw HomeLinkException(friendlyHomeLinkError(s.error));
      if (s.state == HomeLinkState.off) throw HomeLinkException(friendlyHomeLinkError(null));
      if (DateTime.now().isAfter(deadline)) {
        native.stop();
        throw HomeLinkException('The admin prompt was not answered in time.');
      }
      await Future<void>.delayed(pollInterval);
    }
  }

  /// Removes the adapter, routes and DNS; ends the helper.
  Future<void> stop() async => _native?.stop();

  HomeLinkStatus status() {
    final native = _native;
    if (native == null) return HomeLinkStatus.off;
    return HomeLinkStatus.fromJson(_decode(native.status()));
  }

  static Map<String, dynamic> _decode(String s) {
    try {
      final j = jsonDecode(s);
      return j is Map<String, dynamic> ? j : const {};
    } on FormatException {
      return const {};
    }
  }
}

/// Plain-English text for errors from the native side (which are already
/// worded for users; this covers missing / unexpected ones).
String friendlyHomeLinkError(String? raw) {
  final s = (raw ?? '').trim();
  if (s.isEmpty) return 'The home link could not be turned on.';
  final low = s.toLowerCase();
  if (low.contains('canceled by the user') || low.contains('cancelled by the user')) {
    return 'The admin prompt was cancelled, so the home link was not turned on.';
  }
  if (low.contains('exception') || low.contains('panic') || low.contains('0x')) {
    return 'The home link could not be turned on (Windows reported an unexpected error).';
  }
  return s;
}

typedef _StrFn = Pointer<Utf8> Function();
typedef _StartFn = Pointer<Utf8> Function(Pointer<Utf8>);
typedef _VoidC = Void Function();
typedef _VoidD = void Function();
typedef _FreeC = Void Function(Pointer<Utf8>);
typedef _FreeD = void Function(Pointer<Utf8>);

class _FfiHomeLink implements HomeLinkNative {
  _FfiHomeLink(this._lib)
      : _start = _lib.lookupFunction<_StartFn, _StartFn>('cvvpn_start'),
        _status = _lib.lookupFunction<_StrFn, _StrFn>('cvvpn_status'),
        _stop = _lib.lookupFunction<_VoidC, _VoidD>('cvvpn_stop'),
        _free = _lib.lookupFunction<_FreeC, _FreeD>('cvwg_free');

  // Kept alive for the lifetime of the process.
  // ignore: unused_field
  final DynamicLibrary _lib;
  final Pointer<Utf8> Function(Pointer<Utf8>) _start;
  final Pointer<Utf8> Function() _status;
  final void Function() _stop;
  final void Function(Pointer<Utf8>) _free;

  String _take(Pointer<Utf8> p) {
    try {
      return p.toDartString();
    } finally {
      _free(p);
    }
  }

  @override
  String start(String requestJson) {
    final arg = requestJson.toNativeUtf8();
    try {
      return _take(_start(arg));
    } finally {
      // The JSON holds the private key: wipe it before freeing.
      final bytes = arg.cast<Uint8>();
      var i = 0;
      while (bytes[i] != 0) {
        bytes[i++] = 0;
      }
      malloc.free(arg);
    }
  }

  @override
  String status() => _take(_status());

  @override
  void stop() => _stop();
}
