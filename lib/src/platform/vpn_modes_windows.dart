import 'dart:convert';
import 'dart:ffi';
import 'dart:io' show Platform;

import 'package:ffi/ffi.dart';

import '../core/config.dart';
import '../core/updater.dart' show appVersion;
import '../net/router_link.dart' show EndpointResolver, resolveEndpoint;
import 'vpn_modes.dart';

// Windows "home link": the remote modes `home` (home devices such as the
// NAS) and `everything` (all PC traffic via the house) through a Wintun
// network adapter named "Cybervulcan".
//
// The adapter needs admin rights, so cvwg.dll starts a small elevated helper
// (this app's exe with --vpn-helper) through the UAC prompt when a mode is
// turned on. The helper only creates the adapter and sets its routes / DNS;
// it talks to this process over two named pipes that only this Windows user
// can open (start / stop / status, and the adapter's packets). The packets
// are handled here by the same VPN core and remote-access tunnel as on
// Android, so no key ever reaches the helper. Turning the mode off (or
// closing the app) removes the adapter, routes and DNS and ends the helper;
// the next turn-on asks again.

/// What the elevated helper gets (winvpn.StartRequest in Go).
/// test/fixtures/home_link_request.json pins the contract on both sides.
class HomeLinkHelperRequest {
  const HomeLinkHelperRequest({
    required this.mode,
    required this.endpoint,
    required this.address,
    required this.routerIp,
    this.homeCidrs = const [],
    this.mtu = 1280,
  });

  /// `home` or `everything`.
  final String mode;

  /// Resolved `ip:port` (`[v6]:port`) of the router's WireGuard port: kept
  /// on the real network when the adapter's routes would cover it.
  final String endpoint;

  /// This PC's tunnel address (the adapter's own address), e.g. 10.10.99.2/32.
  final String address;

  /// Router LAN IPv4: kept off the adapter (the app reaches the router
  /// through its own tunnel).
  final String routerIp;

  /// Home devices for `home` mode (canonical CIDRs).
  final List<String> homeCidrs;
  final int mtu;

  static HomeLinkHelperRequest fromConfig(AppConfig cfg, String mode, String endpoint, {int mtu = 1280}) =>
      HomeLinkHelperRequest(
        mode: mode,
        endpoint: endpoint,
        address: cfg.wgAddress.trim(),
        routerIp: cfg.routerTunnelIp ?? '',
        homeCidrs: mode == 'home' ? cfg.homeDeviceCidrs : const [],
        mtu: mtu,
      );

  Map<String, Object?> toJson() => {
        'mode': mode,
        'endpoint': endpoint,
        'address': address,
        'routerIp': routerIp,
        if (homeCidrs.isNotEmpty) 'homeCidrs': homeCidrs,
        'mtu': mtu,
      };
}

/// The JSON for cvvpn_start: the helper's part and the VPN core's part
/// (vpn_glue.go vpnStartConfig, same fields as on Android).
String homeLinkStartJson(SystemVpnRequest req, HomeLinkHelperRequest helper) => jsonEncode({
      'helper': helper.toJson(),
      'vpn': {
        'mode': req.mode,
        'transport': req.transport,
        'mtu': req.mtu,
        if (req.dns != null && req.dns!.isNotEmpty) 'dns': req.dns,
        'allowed': req.allowed,
      },
    });

/// Parses cvvpn_status: `{"helper": winvpn.Status, "vpn": vpnStatus}`.
SystemVpnStatus homeLinkStatusFromJson(String s) {
  Map<String, dynamic> obj(Object? o) => o is Map<String, dynamic> ? o : const {};
  Map<String, dynamic> j;
  try {
    j = obj(jsonDecode(s));
  } on FormatException {
    j = const {};
  }
  final h = obj(j['helper']);
  final v = obj(j['vpn']);
  int i(String k) => v[k] is num ? (v[k] as num).toInt() : 0;
  String? str(Object? o) => o is String && o.isNotEmpty ? o : null;
  final helperState = str(h['state']) ?? 'off';
  final running = v['up'] == true && helperState == 'on';
  return SystemVpnStatus(
    running: running,
    mode: str(v['mode']) ?? str(h['mode']) ?? '',
    transportUp: v['transportUp'] == true,
    lastError: running ? null : friendlyHomeLinkError(str(h['error']) ?? str(v['error']), quietWhenEmpty: true),
    tcpActive: i('tcpActive'),
    udpActive: i('udpActive'),
    rxBytes: i('rx'),
    txBytes: i('tx'),
  );
}

/// Plain-English text for errors from the native side (which are already
/// worded for users; this covers missing / unexpected ones).
String? friendlyHomeLinkError(String? raw, {bool quietWhenEmpty = false}) {
  final s = (raw ?? '').trim();
  if (s.isEmpty) return quietWhenEmpty ? null : 'The home link could not be turned on.';
  final low = s.toLowerCase();
  if (low.contains('canceled by the user') || low.contains('cancelled by the user')) {
    return 'The admin prompt was cancelled, so the home link was not turned on.';
  }
  if (low.contains('exception') || low.contains('panic') || low.contains('0x')) {
    return 'The home link could not be turned on (Windows reported an unexpected error).';
  }
  return s;
}

/// The three C functions of cvwg.dll (exports_vpn_windows.go). An interface
/// so tests can fake the DLL.
abstract class HomeLinkNative {
  /// Returns `{"ok":true}` or `{"error":"..."}`.
  String start(String requestJson);
  String status();
  void stop();
}

/// Windows [SystemVpn]: the Cybervulcan Wintun adapter.
class WindowsSystemVpn implements SystemVpn {
  WindowsSystemVpn(this._native,
      {EndpointResolver? resolver, this.pollInterval = const Duration(milliseconds: 300), this.startTimeout = const Duration(minutes: 3)})
      : _resolve = resolver ?? resolveEndpoint;

  final HomeLinkNative? _native;
  final EndpointResolver _resolve;
  final Duration pollInterval;

  /// The UAC prompt waits for the user; give up after this long.
  final Duration startTimeout;

  /// Loads cvwg.dll's home link functions.
  static WindowsSystemVpn load() {
    try {
      return WindowsSystemVpn(_FfiHomeLink(DynamicLibrary.open('cvwg.dll')));
    } on Object {
      return WindowsSystemVpn(null);
    }
  }

  @override
  bool get isSupported => _native != null;

  @override
  String? get unsupportedReason =>
      isSupported ? null : 'This build has no home link library (cvwg.dll) - reinstall Cybervulcan.';

  // A start that failed (prompt cancelled, error) is not retried by the
  // poll loop with the same settings - that would show the admin prompt
  // again every few seconds. [prepare] (Settings: picking the mode, "Try
  // again") clears it.
  String? _failedSig;
  String? _failedMsg;

  /// Nothing to ask up front: the admin prompt comes with [start]. Re-arms
  /// a start that failed before.
  @override
  Future<bool> prepare() async {
    _failedSig = null;
    _failedMsg = null;
    return isSupported;
  }

  /// Shows the UAC prompt (each turn-on), then waits until the adapter is
  /// up. Throws [SystemVpnException] with a plain-English message.
  @override
  Future<void> start(SystemVpnRequest request) async {
    if (_failedSig != null && _failedSig == request.signature) {
      throw SystemVpnException(_failedMsg ?? friendlyHomeLinkError(null)!);
    }
    try {
      await _start(request);
      _failedSig = null;
    } on SystemVpnException catch (e) {
      _failedSig = request.signature;
      _failedMsg = e.message;
      rethrow;
    }
  }

  Future<void> _start(SystemVpnRequest request) async {
    final native = _native;
    if (native == null) throw SystemVpnException(unsupportedReason!);
    final cfg = request.config;
    if (cfg == null) throw SystemVpnException('The home link needs the remote access settings.');
    // v2.2.1: "Everything via home" on Windows - the helper now locks DNS to
    // the adapter (NRPT rule) and re-pins the endpoint route when the PC's
    // network changes; a reconnect stops the session first, so the endpoint
    // name is always looked up with the lock off.
    if (Platform.isWindows && !installedForAllUsers(Platform.resolvedExecutable)) {
      // The elevated helper runs this exe and its DLLs; from a per-user
      // folder any program could swap a DLL and gain admin rights.
      // v2.1.22: a re-run keeps the earlier "just me" choice without asking.
      throw SystemVpnException('The home link needs the app installed for all users (Program Files). '
          'An upgrade keeps the earlier "just me" choice, so run the setup from a terminal with /ALLUSERS, '
          'e.g.  Cybervulcan-Setup-$appVersion.exe /ALLUSERS  (the old copy is removed).');
    }
    final String endpoint;
    try {
      endpoint = await _resolve(cfg.wgEndpointHost, cfg.wgEndpointPort);
    } on Object {
      throw SystemVpnException('Cannot look up ${cfg.wgEndpointHost} (the WireGuard endpoint).');
    }
    final helper = HomeLinkHelperRequest.fromConfig(cfg, request.mode, endpoint, mtu: request.mtu);
    Map<String, dynamic> reply;
    try {
      final j = jsonDecode(native.start(homeLinkStartJson(request, helper)));
      reply = j is Map<String, dynamic> ? j : const {};
    } on FormatException {
      reply = const {};
    }
    if (reply['ok'] != true) {
      throw SystemVpnException(friendlyHomeLinkError(reply['error'] is String ? reply['error'] as String : null)!);
    }
    final deadline = DateTime.now().add(startTimeout);
    while (true) {
      final raw = native.status();
      final h = _helperState(raw);
      if (h == 'on') return;
      if (h == 'error' || h == 'off') {
        throw SystemVpnException(
            homeLinkStatusFromJson(raw).lastError ?? friendlyHomeLinkError(null)!);
      }
      if (DateTime.now().isAfter(deadline)) {
        native.stop();
        throw SystemVpnException('The admin prompt was not answered in time.');
      }
      await Future<void>.delayed(pollInterval);
    }
  }

  static String _helperState(String raw) {
    try {
      final j = jsonDecode(raw);
      final h = j is Map ? j['helper'] : null;
      final s = h is Map ? h['state'] : null;
      return s is String ? s : 'off';
    } on FormatException {
      return 'off';
    }
  }

  /// Removes the adapter, routes and DNS; ends the helper.
  @override
  Future<void> stop() async => _native?.stop();

  @override
  Future<SystemVpnStatus> status() async {
    final native = _native;
    return native == null ? SystemVpnStatus.off : homeLinkStatusFromJson(native.status());
  }

  /// Windows cannot tell cheaply whether a provider's VPN app is on.
  @override
  Future<bool> otherVpnActive() async => false;
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
      malloc.free(arg);
    }
  }

  @override
  String status() => _take(_status());

  @override
  void stop() => _stop();
}

/// Whether [exePath] is under Program Files (only admins can change it).
bool installedForAllUsers(String exePath, {Map<String, String>? env}) {
  final e = env ?? Platform.environment;
  final p = exePath.toLowerCase().replaceAll('/', '\\');
  return [e['ProgramFiles'], e['ProgramW6432'], e['ProgramFiles(x86)']]
      .whereType<String>()
      .where((d) => d.isNotEmpty)
      .any((d) => p.startsWith('${d.toLowerCase().replaceAll('/', '\\')}\\'));
}
