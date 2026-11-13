import 'dart:async';

import 'package:flutter/foundation.dart';

import '../api/models.dart';
import '../api/opnsense_client.dart';
import '../net/router_link.dart';
import '../net/tunnel.dart';
import 'bypass.dart';
import 'client_factory.dart';
import 'config.dart';
import 'events.dart';
import 'house_state.dart';
import 'pc_mode.dart';
import 'storage.dart';
import 'wg_keys.dart' as wg;

/// Central app state: polls the router, enforces bypass expiry, exposes
/// actions, and emits [AlertEvent]s for the notification layer.
class CybervulcanController extends ChangeNotifier {
  CybervulcanController({
    required this.prefs,
    required this.secrets,
    required this.supportsPcMode,
    DateTime Function()? clock,
    RouterLink? link,
  })  : clock = clock ?? DateTime.now,
        link = link ?? RouterLink(tunnel: NativeTunnel.load());

  final PrefsStore prefs;
  final SecretStore secrets;

  /// True on Windows: PC mode only makes sense for the PC itself.
  final bool supportsPcMode;
  final DateTime Function() clock;

  /// Direct vs. remote (in-app WireGuard) connection to the router.
  final RouterLink link;

  AppConfig config = const AppConfig();
  ApiCredentials? _creds;
  WireGuardSecrets _wg = const WireGuardSecrets();

  /// False while the Android app is in the background: no remote tunnel then.
  bool _foreground = true;
  OpnsenseClient? _client;
  HouseSnapshot snapshot = HouseSnapshot.unconfigured(DateTime.now());
  String? lastActionError;
  String? lastActionInfo;

  final _events = StreamController<AlertEvent>.broadcast();
  Stream<AlertEvent> get events => _events.stream;

  Timer? _timer;
  Future<void>? _inflight;
  int _pollCount = 0;
  bool? _cachedArmed;
  String? _cachedArmedDetail;
  bool _disposed = false;

  /// Next reminder while a no-time-limit bypass is on.
  DateTime? _noLimitRemindAt;
  static const noLimitReminderEvery = Duration(hours: 4);

  bool get isConfigured => _client != null;
  bool get hasCredentials => _creds?.isComplete ?? false;

  /// This device's WireGuard public key (to give to the router admin), or
  /// null before one was generated.
  String? get wireGuardPublicKey => _wgPublic;
  String? _wgPublic;

  Future<void> _loadWireGuard() async {
    _wg = await secrets.readWireGuard();
    final k = _wg.privateKey;
    _wgPublic = k != null && wg.isWireGuardKey(k) ? wg.wireGuardPublicKey(k) : null;
  }

  bool get hasPresharedKey => (_wg.presharedKey ?? '').isNotEmpty;

  /// Reasons remote access can't be used yet (empty = ready).
  List<String> get remoteAccessIssues => [
        if (!link.tunnel.isAvailable) link.tunnel.unavailableReason ?? 'Remote access is not available.',
        ...remoteAccessProblems(config, _wg),
      ];

  Future<void> init() async {
    config = prefs.loadConfig();
    _creds = await secrets.read();
    await _loadWireGuard();
    _rebuildClient();
    await refresh();
    _schedule();
  }

  void _rebuildClient() {
    final old = _client;
    _client = buildRouterClient(config, _creds, route: link.routeFor);
    // Let an in-flight poll finish on the old client before closing it.
    unawaited((_inflight ?? Future<void>.value()).whenComplete(() => old?.close()));
    _cachedArmed = null;
    _cachedArmedDetail = null;
  }

  void _schedule() {
    _timer?.cancel();
    _timer = Timer.periodic(config.pollInterval, (_) => unawaited(refresh()));
  }

  BypassManager? _bypass() {
    final c = _client;
    return c == null ? null : BypassManager(client: c, config: config, store: prefs, clock: clock);
  }

  /// Polls once. Concurrent callers share the in-flight poll.
  Future<void> refresh() {
    if (_disposed) return Future.value();
    return _inflight ??= _safePoll().then(_apply).whenComplete(() => _inflight = null);
  }

  /// Waits for any in-flight poll, then polls again (after a change).
  Future<void> _refreshAfterChange() async {
    final pending = _inflight;
    if (pending != null) await pending;
    await refresh();
  }

  void _apply(HouseSnapshot next) {
    final prev = snapshot;
    snapshot = next;
    if (_disposed) return;
    for (final e in diffSnapshots(prev.configured ? prev : null, next, config)) {
      _events.add(e);
    }
    notifyListeners();
  }

  Future<HouseSnapshot> _safePoll() async {
    try {
      return await _poll();
    } on Object catch (e) {
      return HouseSnapshot(
        fetchedAt: clock(),
        error: OpnsenseException(ApiErrorKind.badResponse, 'Unexpected error: $e'),
        bypassActive: snapshot.bypassActive,
      );
    }
  }

  Future<HouseSnapshot> _poll() async {
    final now = clock();
    final client = _client;
    if (client == null) return HouseSnapshot.unconfigured(now);

    // Reach the router directly, or through the in-app tunnel when away.
    // This is a TLS handshake only: if the certificate is wrong nothing -
    // in particular not the API key - is sent.
    final ls = await link.check(
        _foreground ? config : config.copyWith(remoteEnabled: false), _wg);
    if (!ls.connected) {
      return HouseSnapshot(
        fetchedAt: now,
        error: OpnsenseException(
          ls.state == LinkState.wrongCertificate
              ? ApiErrorKind.untrustedCertificate
              : ApiErrorKind.network,
          ls.describe(config),
        ),
        link: ls,
        bypassActive: snapshot.bypassActive,
      );
    }

    // Gateway status is read first but a failure must NOT skip the bypass
    // expiry enforcement below (otherwise a missing "System: Gateways"
    // privilege, a 404 after an upgrade or a dpinger hiccup would keep the
    // whole house off the VPN past its deadline).
    List<GatewayStatus> gws = const [];
    OpnsenseException? gwError;
    try {
      gws = await client.gatewayStatus();
    } on OpnsenseException catch (e) {
      gwError = e;
    }

    // Bypass + expiry enforcement.
    bool? bypassActive;
    DateTime? bypassExpiry;
    var noRouterDeadline = false;
    final bm = _bypass()!;
    // Skip only when the router itself is unreachable/untrusted/rejecting us.
    final routerDown = gwError != null &&
        (gwError.kind == ApiErrorKind.network ||
            gwError.kind == ApiErrorKind.untrustedCertificate ||
            gwError.kind == ApiErrorKind.unauthorized);
    if (!routerDown) {
      try {
        var state = await bm.read();
        final (action, enforced) = await bm.enforce(state);
        state = enforced;
        if (action == EnforceAction.expiredTurnedOff) {
          lastActionInfo = 'Bypass expired and was turned off'
              '${bm.lastKill != null ? ' (${bm.lastKill!.describe()})' : ''}.';
        }
        bypassActive = state.active;
        bypassExpiry = state.expiresAt;
        noRouterDeadline = bypassLacksRouterDeadline(state);
        _remindIfNoLimit(state.active, state.expiresAt, now);
      } on OpnsenseException catch (e) {
        // Surface every failure: if the bypass table cannot be read, expiry
        // cannot be enforced either, and the user must know.
        lastActionError = 'Bypass check failed (expiry not enforced): ${e.message}';
      }
    }

    if (gwError != null) {
      return HouseSnapshot(
        fetchedAt: now,
        error: gwError,
        bypassActive: bypassActive ?? snapshot.bypassActive,
        bypassExpiresAt: bypassExpiry,
        link: ls,
        bypassNoRouterDeadline: noRouterDeadline,
      );
    }

    // PC mode (Windows).
    String? pcIp;
    bool? pcClear;
    if (supportsPcMode) {
      pcIp = await detectPcIp(config);
      if (pcIp != null) {
        try {
          pcClear = isPcInClearAlias(await client.aliasList(config.pcModeAlias), pcIp);
        } on OpnsenseException {
          pcClear = null;
        }
      }
    }

    // Kill switch armed check: every 4th poll (rule stats run pfctl).
    if (_pollCount++ % 4 == 0 || _cachedArmedDetail == null) {
      await _checkKillSwitch(client);
    }

    return HouseSnapshot(
      fetchedAt: now,
      main: findGateway(gws, config.mainGateway),
      backup: findGateway(gws, config.backupGateway),
      bypassActive: bypassActive,
      bypassExpiresAt: bypassExpiry,
      pcIp: pcIp,
      pcClear: pcClear,
      killSwitchArmed: _cachedArmed,
      killSwitchDetail: _cachedArmedDetail,
      link: ls,
      bypassNoRouterDeadline: noRouterDeadline,
    );
  }

  /// A bypass with no time limit is easy to forget: nudge every 4 hours.
  void _remindIfNoLimit(bool active, DateTime? expiry, DateTime now) {
    if (!active || !isNoLimitExpiry(expiry)) {
      _noLimitRemindAt = null;
      return;
    }
    final at = _noLimitRemindAt ??= now.add(noLimitReminderEvery);
    if (!now.isBefore(at)) {
      _noLimitRemindAt = now.add(noLimitReminderEvery);
      if (config.notifyOnBypass && !_disposed) {
        _events.add(const AlertEvent(AlertKind.bypassReminder, 'VPN bypass is still on',
            'The whole house is still off the VPN (no time limit). Turn it off in Cybervulcan when you\'re done.'));
      }
    }
  }

  Future<void> _checkKillSwitch(OpnsenseClient client) async {
    try {
      final rules = await client.searchRules(config.killSwitchTag);
      final r = evaluateKillSwitchRules(rules, config.killSwitchTag);
      _cachedArmed = r.armed;
      _cachedArmedDetail = r.detail;
      return;
    } on OpnsenseException catch (e) {
      if (e.kind != ApiErrorKind.forbidden && e.kind != ApiErrorKind.notFound) {
        _cachedArmed = null;
        _cachedArmedDetail = 'Rule check failed: ${e.message}';
        return;
      }
    }
    final uuid = config.killSwitchRuleUuid;
    if (uuid != null) {
      try {
        final stats = await client.ruleStats();
        final s = stats[uuid] ?? stats[uuid.toLowerCase()];
        _cachedArmed = s != null;
        _cachedArmedDetail = s != null
            ? 'Rule loaded in pf (${s['packets'] ?? 0} packets blocked)'
            : 'Rule $uuid is not loaded in pf (disabled or deleted)';
        return;
      } on OpnsenseException catch (_) {
        // fall through
      }
    }
    _cachedArmed = null;
    _cachedArmedDetail =
        'Unknown - grant "Firewall: Rules [new]" (or "Firewall: Rules" + rule UUID) to verify';
  }

  // ------------------------------------------------------------- actions

  Future<T?> _action<T>(Future<T> Function(OpnsenseClient c) run,
      {String? done, String? Function(T result)? detail}) async {
    final c = _client;
    if (c == null) {
      lastActionError = 'Router not configured';
      notifyListeners();
      return null;
    }
    lastActionError = null;
    lastActionInfo = null;
    snapshot = snapshot.copyWith(busy: true);
    notifyListeners();
    try {
      final r = await run(c);
      final extra = detail?.call(r);
      lastActionInfo = extra == null ? done : '$done - $extra';
      return r;
    } on OpnsenseException catch (e) {
      lastActionError = e.kind == ApiErrorKind.forbidden
          ? 'Permission denied: the API user needs the privilege for ${e.endpoint}'
          : e.message;
      return null;
    } on ArgumentError catch (e) {
      lastActionError = '${e.message}';
      return null;
    } finally {
      snapshot = snapshot.copyWith(busy: false);
      await _refreshAfterChange();
    }
  }

  Future<void> setBypass(bool on, {Duration? duration}) {
    final bm = _bypass();
    return _action(
      (c) => on ? bm!.turnOn(duration: duration) : bm!.turnOff(),
      done: on ? 'VPN bypass is ON for the whole house' : 'VPN bypass is OFF',
      detail: (_) => bm?.lastKill?.describe(),
    );
  }

  Future<void> toggleBypass() => setBypass(!(snapshot.bypassActive ?? false));

  /// Stores the running bypass's deadline on the router, so the router-side
  /// timer can end it even when no app is running.
  Future<void> addRouterDeadline() {
    final bm = _bypass();
    return _action((c) => bm!.addRouterDeadline(),
        done: 'Deadline stored on the router - it can now end the bypass by itself');
  }

  Future<void> setPcClear(bool clear) async {
    if (!supportsPcMode) return;
    final ip = snapshot.pcIp ?? await detectPcIp(config);
    if (ip == null) {
      lastActionError = 'Could not detect this PC\'s house IP - set it in Settings';
      notifyListeners();
      return;
    }
    await _action((c) => setPcMode(client: c, cfg: config, pcIp: ip, clear: clear),
        done: clear ? 'PC is now CLEAR (direct internet)' : 'PC is back on the VPN',
        detail: (r) => r.$2.describe());
  }

  Future<List<DhcpLease>> leases() async {
    final c = _client;
    if (c == null) throw OpnsenseException(ApiErrorKind.network, 'Router not configured');
    return c.dnsmasqLeases();
  }

  // ------------------------------------------------------------ settings

  Future<void> saveSettings(AppConfig cfg, {ApiCredentials? credentials}) async {
    final pollChanged = cfg.pollInterval != config.pollInterval;
    config = cfg;
    await prefs.saveConfig(cfg);
    if (credentials != null) {
      await secrets.write(credentials);
      _creds = credentials;
    }
    _rebuildClient();
    await link.close();
    if (pollChanged) _schedule();
    await _refreshAfterChange();
  }

  /// Makes a new WireGuard keypair for this device. The private key goes
  /// to secure storage only; returns the public key for the router admin.
  Future<String> generateWireGuardKey() async {
    final priv = wg.generateWireGuardPrivateKey();
    await secrets.writeWireGuardPrivateKey(priv);
    await _loadWireGuard();
    await link.close();
    notifyListeners();
    return _wgPublic!;
  }

  /// Stores keys from an imported wg-quick file (secure storage only).
  Future<void> storeWireGuardSecrets({String? privateKey, String? presharedKey, bool setPsk = false}) async {
    if (privateKey != null && wg.isWireGuardKey(privateKey)) {
      await secrets.writeWireGuardPrivateKey(privateKey);
    }
    if (setPsk) await secrets.writeWireGuardPresharedKey(presharedKey);
    await _loadWireGuard();
    await link.close();
    notifyListeners();
  }

  /// Called by the platform layer: no remote tunnel while in the background.
  void setForeground(bool foreground) {
    if (_foreground == foreground) return;
    _foreground = foreground;
    if (!foreground) {
      unawaited(link.close());
    } else {
      unawaited(refresh());
    }
  }

  Future<void> forgetCredentials() async {
    await secrets.clear();
    _creds = null;
    _rebuildClient();
    await _refreshAfterChange();
  }

  @override
  void dispose() {
    _disposed = true;
    _timer?.cancel();
    _client?.close();
    unawaited(link.close());
    unawaited(_events.close());
    super.dispose();
  }
}
