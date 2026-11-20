import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

import '../core/config.dart';
import '../core/remote_modes.dart';
import '../net/router_link.dart' show LinkStatus;
import 'vpn_modes_windows.dart';

/// What the platform VPN is asked to carry.
class SystemVpnRequest {
  const SystemVpnRequest({
    required this.mode,
    required this.routes,
    required this.allowed,
    this.dns,
    this.mtu = 1280,
    this.transport = 'wireguard',
    this.config,
  });

  /// From [AppConfig]: routes, allowed destinations and DNS for its mode.
  factory SystemVpnRequest.fromConfig(AppConfig cfg, {String transport = 'wireguard'}) => SystemVpnRequest(
        mode: cfg.mode,
        routes: systemVpnRoutes(cfg),
        allowed: systemVpnAllowed(cfg),
        dns: systemVpnDns(cfg),
        transport: transport,
        config: cfg,
      );

  /// The settings this request came from (Windows needs the endpoint and
  /// router address for its adapter routes). Not part of [toArgs].
  final AppConfig? config;

  final String mode;
  final List<String> routes;
  final List<String> allowed;
  final String? dns;
  final int mtu;

  /// Native dialer name (vpn_glue.go vpnDialers): `wireguard`, later `tailscale`.
  final String transport;

  Map<String, Object?> toArgs() => {
        'mode': mode,
        'routes': routes,
        'allowed': allowed,
        'dns': dns ?? '',
        'mtu': mtu,
        'transport': transport,
      };

  /// Same request? (restart only when something changed)
  String get signature => jsonEncode(toArgs());
}

class SystemVpnStatus {
  const SystemVpnStatus({
    this.running = false,
    this.mode = '',
    this.transportUp = false,
    this.lastError,
    this.tcpActive = 0,
    this.udpActive = 0,
    this.rxBytes = 0,
    this.txBytes = 0,
  });

  final bool running;
  final String mode;

  /// The tunnel to the house is connected (traffic can flow).
  final bool transportUp;

  /// Plain-English reason the VPN stopped or could not start.
  final String? lastError;
  final int tcpActive;
  final int udpActive;
  final int rxBytes;
  final int txBytes;

  static const off = SystemVpnStatus();

  /// Parses the Android channel's map (native = Go status JSON).
  factory SystemVpnStatus.fromChannel(Map<Object?, Object?> m) {
    Map<String, dynamic> n = const {};
    final raw = m['native'];
    if (raw is String) {
      try {
        final j = jsonDecode(raw);
        if (j is Map<String, dynamic>) n = j;
      } on FormatException {
        // keep empty
      }
    }
    int i(String k) => n[k] is num ? (n[k] as num).toInt() : 0;
    final err = m['lastError'];
    return SystemVpnStatus(
      running: m['running'] == true,
      mode: m['mode'] is String ? m['mode'] as String : '',
      transportUp: n['transportUp'] == true,
      lastError: err is String && err.isNotEmpty ? err : null,
      tcpActive: i('tcpActive'),
      udpActive: i('udpActive'),
      rxBytes: i('rx'),
      txBytes: i('tx'),
    );
  }
}

class SystemVpnException implements Exception {
  SystemVpnException(this.message);

  /// Plain English, safe to show.
  final String message;
  @override
  String toString() => message;
}

/// The device's VPN slot, per platform. Android: [AndroidSystemVpn]
/// (VpnService). Windows implements the same interface (Wintun) and is
/// returned by [systemVpnForPlatform].
abstract class SystemVpn {
  /// False where the modes cannot work (then [unsupportedReason] says why).
  bool get isSupported;
  String? get unsupportedReason;

  /// Asks the user once for permission to run a VPN (Android consent
  /// screen). True when allowed. Call from a user action.
  Future<bool> prepare();

  /// Starts or reconfigures the VPN. Throws [SystemVpnException].
  Future<void> start(SystemVpnRequest request);
  Future<void> stop();
  Future<SystemVpnStatus> status();

  /// Whether some other VPN (e.g. the provider's app) is active right now.
  /// Our own VPN does not count. False where it cannot be told.
  Future<bool> otherVpnActive();
}

class UnsupportedSystemVpn implements SystemVpn {
  const UnsupportedSystemVpn([this.unsupportedReason = 'Not available on this device yet.']);
  @override
  final String? unsupportedReason;
  @override
  bool get isSupported => false;
  @override
  Future<bool> prepare() async => false;
  @override
  Future<void> start(SystemVpnRequest request) async => throw SystemVpnException(unsupportedReason!);
  @override
  Future<void> stop() async {}
  @override
  Future<SystemVpnStatus> status() async => SystemVpnStatus.off;
  @override
  Future<bool> otherVpnActive() async => false;
}

/// Android VpnService through MethodChannel `cybervulcan/vpn`
/// (android/.../VpnChannel.kt + CybervulcanVpnService.kt). The service talks
/// to the Go library directly (JNI), so the VPN outlives the Flutter engine.
class AndroidSystemVpn implements SystemVpn {
  AndroidSystemVpn([MethodChannel? channel]) : _ch = channel ?? const MethodChannel('cybervulcan/vpn');
  final MethodChannel _ch;

  @override
  bool get isSupported => true;
  @override
  String? get unsupportedReason => null;

  @override
  Future<bool> prepare() async {
    try {
      return await _ch.invokeMethod<bool>('prepare') ?? false;
    } on PlatformException {
      return false;
    } on MissingPluginException {
      return false;
    }
  }

  @override
  Future<void> start(SystemVpnRequest request) async {
    try {
      await _ch.invokeMethod<void>('start', request.toArgs());
    } on PlatformException catch (e) {
      throw SystemVpnException(e.message ?? 'The VPN could not start.');
    } on MissingPluginException {
      throw SystemVpnException('The VPN is not available in this build.');
    }
  }

  @override
  Future<void> stop() async {
    try {
      await _ch.invokeMethod<void>('stop');
    } on PlatformException {
      // Already stopped.
    } on MissingPluginException {
      // Nothing to stop.
    }
  }

  @override
  Future<SystemVpnStatus> status() async {
    try {
      final m = await _ch.invokeMethod<Map<Object?, Object?>>('status');
      return m == null ? SystemVpnStatus.off : SystemVpnStatus.fromChannel(m);
    } on PlatformException {
      return SystemVpnStatus.off;
    } on MissingPluginException {
      return SystemVpnStatus.off;
    }
  }

  @override
  Future<bool> otherVpnActive() async {
    try {
      return await _ch.invokeMethod<bool>('otherVpnActive') ?? false;
    } on PlatformException {
      return false;
    } on MissingPluginException {
      return false;
    }
  }
}

/// The platform's [SystemVpn]: Android VpnService, Windows Wintun adapter
/// (vpn_modes_windows.dart).
SystemVpn systemVpnForPlatform() => Platform.isAndroid
    ? AndroidSystemVpn()
    : Platform.isWindows
        ? WindowsSystemVpn.load()
        : const UnsupportedSystemVpn('"Home devices" and "Everything" are not available on this platform yet.');

/// What the Status page shows about the system VPN.
enum HomeLinkState { off, connecting, connected, waiting, error }

/// Keeps the system VPN in line with the settings and the router link, and
/// runs the phone's VPN-app reminder. Driven by the controller after every
/// router check ([onLink]).
class HomeLink {
  HomeLink(this.vpn, {DateTime Function()? clock}) : _clock = clock ?? DateTime.now;

  final SystemVpn vpn;
  final DateTime Function() _clock;

  HomeLinkState state = HomeLinkState.off;
  String mode = '';

  /// Plain-English problem to show (null = none).
  String? error;

  String? _runningSig;
  bool _busy = false;
  ReminderState _reminder = const ReminderState();

  /// While a VPN mode is in use the remote tunnel must stay up in the
  /// background too (the VPN carries other apps' traffic through it).
  bool keepTunnelInBackground(AppConfig cfg) => vpn.isSupported && cfg.remoteEnabled && cfg.mode != 'app';

  /// After each router check: start / reconfigure / stop the VPN, and the
  /// reminder. [notify] shows a notification (title, body). Never throws.
  /// Returns true when the status line changed.
  Future<bool> onLink(AppConfig cfg, LinkStatus? link, {void Function(String title, String body)? notify}) async {
    if (_busy) return false;
    _busy = true;
    final before = describe();
    try {
      await _syncVpn(cfg, link);
      if (cfg.protonReminder && Platform.isAndroid && notify != null) {
        await _remind(cfg, link, notify);
      }
    } on Object catch (_) {
      // Must never break polling.
    } finally {
      _busy = false;
    }
    return describe() != before;
  }

  Future<void> _syncVpn(AppConfig cfg, LinkStatus? link) async {
    if (!vpn.isSupported) {
      state = HomeLinkState.off;
      return;
    }
    if (!wantsSystemVpn(cfg, link)) {
      if (_runningSig != null || state != HomeLinkState.off) {
        await vpn.stop();
        _runningSig = null;
      }
      state = HomeLinkState.off;
      mode = '';
      error = null;
      return;
    }
    final req = SystemVpnRequest.fromConfig(cfg);
    if (req.signature != _runningSig) {
      state = HomeLinkState.connecting;
      try {
        await vpn.start(req);
        _runningSig = req.signature;
        mode = req.mode;
        error = null;
      } on SystemVpnException catch (e) {
        _runningSig = null;
        state = HomeLinkState.error;
        error = e.message;
        return;
      }
    }
    final st = await vpn.status();
    if (st.running) {
      state = st.transportUp ? HomeLinkState.connected : HomeLinkState.waiting;
      error = null;
    } else if (_runningSig != null && st.lastError != null) {
      // Stopped underneath us (revoked by Android, another VPN app):
      // don't fight it on every poll - the user restarts it from Settings.
      state = HomeLinkState.error;
      error = st.lastError;
    } else {
      state = HomeLinkState.connecting; // service still starting
    }
  }

  /// Settings / Status: try again after an error (also re-asks permission).
  Future<void> retry(AppConfig cfg, LinkStatus? link) async {
    if (!await vpn.prepare()) {
      state = HomeLinkState.error;
      error = 'VPN permission was not given.';
      return;
    }
    _runningSig = null;
    error = null;
    state = HomeLinkState.off;
    await onLink(cfg, link);
  }

  /// Stops the VPN now (mode changed to app only, remote access off).
  Future<void> stop() async {
    await vpn.stop();
    _runningSig = null;
    state = HomeLinkState.off;
    mode = '';
  }

  Future<void> _remind(AppConfig cfg, LinkStatus? link, void Function(String, String) notify) async {
    final place = placeFromLink(link);
    if (place == Place.unknown) return;
    // Only ask the platform when the place may be changing (cheap anyway).
    final other = await vpn.otherVpnActive();
    final (next, kind) = reminderStep(_reminder, now: place, otherVpnActive: other, at: _clock());
    _reminder = next;
    if (kind != null) {
      final (title, body) = reminderText(kind, cfg);
      notify(title, body);
    }
  }

  /// One line for the Status page, or null when no VPN mode is in use.
  String? describe() => switch (state) {
        HomeLinkState.off => null,
        HomeLinkState.connecting => 'Home link: ${homeLinkLabel(mode)} - connecting',
        HomeLinkState.connected => 'Home link: ${homeLinkLabel(mode)} - connected',
        HomeLinkState.waiting => 'Home link: ${homeLinkLabel(mode)} - waiting for remote access',
        HomeLinkState.error => 'Home link: ${error ?? 'stopped'}',
      };
}
