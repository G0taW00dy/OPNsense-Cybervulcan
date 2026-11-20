import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform;

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
import 'network_map.dart';
import 'pc_mode.dart';
import 'schedule.dart';
import 'server_switcher.dart';
import 'storage.dart';
import 'wg_keys.dart' as wg;

/// Start of the poll-time bypass failure message (cleared by the next good poll).
const bypassCheckFailedPrefix = 'Bypass check failed (expiry not enforced): ';

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

  /// Per-device CLEAR (Windows PC, Android phone).
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

  /// Set by the UI: asks for fingerprint / face / PIN (system, then the
  /// app's backup PIN). Returns true when the person proved it is them.
  Future<bool> Function(String reason)? authorizer;

  // ---- App lock session (v2.0.2): unlock once when the app opens; it locks
  // again after [AppConfig.lockAfterMinutes] in the background. Turning the
  // lock off and changing VPN servers always ask. Going back on the VPN never
  // asks.
  bool _unlocked = false;
  DateTime? _backgroundSince;

  Duration get _lockAfter => Duration(minutes: config.lockAfterMinutes.clamp(1, 240));

  bool get _sessionValid {
    if (!_unlocked) return false;
    final b = _backgroundSince;
    if (b != null && clock().difference(b) >= _lockAfter) {
      _unlocked = false;
      return false;
    }
    return true;
  }

  /// The app lock is on and nobody has unlocked this session.
  bool get locked => config.appLock && !_sessionValid;

  /// The window was hidden / the app went to the background.
  void appBackgrounded() {
    // A file picker / browser the app opened itself is not "leaving the app".
    if (_externalUi > 0) return;
    _backgroundSince ??= clock();
  }

  int _externalUi = 0;

  /// Runs [action] (which opens another app: a file picker, the browser, the
  /// camera) without the app lock counting that time as being away.
  Future<T> whileExternal<T>(Future<T> Function() action) async {
    _externalUi++;
    try {
      return await action();
    } finally {
      _externalUi--;
    }
  }

  /// Back in the foreground: locks if it was away long enough.
  void appForegrounded() {
    final wasLocked = locked;
    final b = _backgroundSince;
    _backgroundSince = null;
    if (b != null && clock().difference(b) >= _lockAfter) _unlocked = false;
    if (wasLocked != locked) notifyListeners();
  }

  /// Locks now (e.g. a "Lock" button).
  void lockNow() {
    _unlocked = false;
    notifyListeners();
  }

  Future<bool> _prompt(String reason) async {
    final a = authorizer;
    return a == null ? true : await a(reason);
  }

  /// Unlocks the app session (lock screen).
  Future<bool> unlock() async {
    final ok = await _prompt('Unlock Cybervulcan');
    if (ok) {
      _unlocked = true;
      _backgroundSince = null;
      notifyListeners();
    }
    return ok;
  }

  /// Checks the person before a risky action. Inside an unlocked session it
  /// passes straight away unless [always] (lock off, server changes).
  Future<bool> authorize(String reason, {bool always = false}) async {
    if (!config.appLock) return true;
    if (!always && _sessionValid) return true;
    final ok = await _prompt(reason);
    if (ok) {
      _unlocked = true;
    } else {
      lastActionError = 'Not unlocked - nothing was changed.';
    }
    notifyListeners();
    return ok;
  }

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

  /// The router API client (null until configured). For the Tests page and
  /// the server switcher; regular actions go through [_action].
  OpnsenseClient? get routerClient => _client;

  /// How the router is identified (address, certificate name, pin).
  RouterTarget? get routerTarget => RouterTarget.fromConfig(config);

  /// Where router sockets go right now (direct, tunnel or Tailscale).
  RouterRoute? get routerRoute {
    final t = routerTarget;
    return t == null ? null : link.routeFor(t);
  }

  /// Router reached directly, i.e. this device is at home.
  bool get atHome => (snapshot.link?.connected ?? false) && !(snapshot.link?.remote ?? false);
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
    // After the poll has finished (actions below refresh again themselves).
    if (next.reachable) Timer.run(() => unawaited(_afterPoll()));
  }

  // ------------------------------------------------- v2.0 background jobs

  bool _afterPollRunning = false;
  int _afterPollCount = 0;
  static const _knownMacsKey = 'known_macs_v1';
  static const _schedFiredKey = 'sched_bypass_fired_day';
  static const backupAckKey = 'router_backup_ack_at';
  static const _backupRemindedKey = 'router_backup_reminded_at';
  static const _bestRunKey = 'server_best_last_run';
  static const serverCacheKey = 'proton_servers_v1';

  Future<void> _afterPoll() async {
    if (_afterPollRunning || _disposed) return;
    _afterPollRunning = true;
    try {
      final now = clock();
      // Scheduled whole-house bypass (no app lock: it was set up on purpose).
      final due = scheduledBypassDue(config, now.toLocal(), prefs.getString(_schedFiredKey));
      if (due != null && snapshot.bypassActive == false) {
        await prefs.setString(_schedFiredKey, dayKey(now.toLocal()));
        await setBypass(true, duration: due, skipLock: true);
        _events.add(AlertEvent(AlertKind.scheduledBypass, 'Scheduled VPN bypass started',
            'The whole house goes direct for ${due.inMinutes} min (${describeSchedule(config)}).'));
      }

      // New devices on the network (every 8th good poll, ~2 min).
      if (config.alertNewDevices && _afterPollCount++ % 8 == 0) await _checkNewDevices();

      // Router backup reminder.
      if (config.backupReminderDays > 0) {
        var ack = DateTime.tryParse(prefs.getString(backupAckKey) ?? '');
        if (ack == null) {
          ack = now;
          await prefs.setString(backupAckKey, now.toUtc().toIso8601String());
        }
        final reminded = DateTime.tryParse(prefs.getString(_backupRemindedKey) ?? '');
        if (backupReminderDue(config, now, ack, reminded)) {
          await prefs.setString(_backupRemindedKey, now.toUtc().toIso8601String());
          _events.add(AlertEvent(AlertKind.backupReminder, 'Time for a router backup',
              'Last confirmed backup ${now.difference(ack).inDays} days ago. Save an encrypted config '
              'backup (System > Configuration > Backups) somewhere safe off the router, then tap "I saved a backup".'));
          notifyListeners();
        }
      }

      // Provider key expiry (30 / 7 / 1 day(s) before, and when expired).
      for (final (which, label, date) in [
        ('main', config.mainLabel, config.mainKeyExpiry),
        ('backup', config.backupLabel, config.backupKeyExpiry),
      ]) {
        final exp = parseIsoDate(date);
        if (exp == null) continue;
        final key = 'key_expiry_warned_$which:$date';
        final stage = keyExpiryStage(exp, now.toLocal(), prefs.getInt(key));
        if (stage == null) continue;
        await prefs.setInt(key, stage);
        _events.add(AlertEvent(
            AlertKind.keyExpiry,
            stage == 0 ? 'VPN key for $label has expired' : 'VPN key for $label expires in $stage day${stage == 1 ? '' : 's'}',
            stage == 0
                ? 'That tunnel stops working. Make a new router config at your VPN provider, put its key on the '
                    'router (VPN > WireGuard), then update the date in Settings.'
                : 'Make a new router config at your VPN provider before $date and put its key on the router '
                    '(VPN > WireGuard). If both tunnels expire, the kill switch blocks the VPN network.'));
        notifyListeners();
      }

      // Nightly "find best server".
      final lastBest = DateTime.tryParse(prefs.getString(_bestRunKey) ?? '');
      if (nightlyBestDue(config, now.toLocal(), lastBest?.toLocal()) && !serverBusy) {
        final cached = cachedServers();
        if (cached.isNotEmpty) {
          await prefs.setString(_bestRunKey, now.toUtc().toIso8601String());
          unawaited(findBestServer(pickCandidates(cached, config.serverCityList), (_) {}, skipLock: true));
        }
      }
    } on Object catch (_) {
      // Background jobs must never break polling.
    } finally {
      _afterPollRunning = false;
    }
  }

  /// Days since the user last confirmed a router backup (null = never asked).
  int? get daysSinceBackup {
    final ack = DateTime.tryParse(prefs.getString(backupAckKey) ?? '');
    return ack == null ? null : clock().difference(ack).inDays;
  }

  bool get backupOverdue {
    final d = daysSinceBackup;
    return config.backupReminderDays > 0 && d != null && d >= config.backupReminderDays;
  }

  Future<void> acknowledgeBackup() async {
    await prefs.setString(backupAckKey, clock().toUtc().toIso8601String());
    notifyListeners();
  }

  Future<void> _checkNewDevices() async {
    final c = _client;
    if (c == null) return;
    final List<DhcpLease> leases;
    try {
      leases = await c.dnsmasqLeases();
    } on OpnsenseException {
      return;
    }
    final known = <String>{
      for (final m in (jsonDecode(prefs.getString(_knownMacsKey) ?? '[]') as List)) '$m',
    };
    final fresh = newMacs(leases.map((l) => l.mac), known);
    final all = {...known, ...leases.map((l) => l.mac.toLowerCase()).where((m) => m.isNotEmpty)};
    if (all.length != known.length) await prefs.setString(_knownMacsKey, jsonEncode(all.toList()));
    for (final mac in fresh.take(5)) {
      final l = leases.firstWhere((x) => x.mac.toLowerCase() == mac);
      final net = networkNameFor(l.address, config.networks);
      _events.add(AlertEvent(AlertKind.newDevice, 'New device: ${l.hostname ?? l.vendor ?? mac}',
          '${l.address}${net != null ? ' on $net' : ''} ($mac) joined the network.'));
    }
  }

  /// Forgets the known-device list (next check re-learns it silently).
  Future<void> resetKnownDevices() => prefs.remove(_knownMacsKey);

  // ------------------------------------------------------ server switcher

  bool serverBusy = false;
  ServerSwitcher? _switcher;

  List<ProtonServer> cachedServers() {
    try {
      final j = jsonDecode(prefs.getString(serverCacheKey) ?? '[]');
      return [
        if (j is List)
          for (final s in j) ?ProtonServer.fromJson(s),
      ];
    } on FormatException {
      return [];
    }
  }

  Future<void> saveServers(List<ProtonServer> servers) =>
      prefs.setString(serverCacheKey, jsonEncode([for (final s in servers) s.toJson()]));

  ServerSwitcher? _newSwitcher() {
    final c = _client;
    return c == null ? null : ServerSwitcher(client: c, config: config);
  }

  /// Current main / backup peers (public data only).
  Future<(WgPeerInfo, WgPeerInfo)> tunnelPeers() async {
    final sw = _newSwitcher();
    if (sw == null) throw OpnsenseException(ApiErrorKind.network, 'Router not configured');
    final (m, b) = await sw.peers();
    return (WgPeerInfo(m.serverAddress, m.serverPort, m.publicKey), WgPeerInfo(b.serverAddress, b.serverPort, b.publicKey));
  }

  /// Points the main or backup tunnel at [server].
  Future<bool> moveTunnel({required bool main, required ProtonServer server}) async {
    if (serverBusy) return false;
    if (!await authorize('Change the ${main ? 'main' : 'backup'} VPN server', always: true)) return false;
    final sw = _newSwitcher();
    if (sw == null) return false;
    serverBusy = true;
    notifyListeners();
    final r = await _action((c) async {
      final (m, b) = await sw.peers();
      final peer = main ? m : b;
      final old = ProtonServer(
          name: '${main ? config.mainLabel : config.backupLabel} (${peer.serverAddress})',
          entryIp: peer.serverAddress,
          publicKey: peer.publicKey,
          port: peer.serverPort);
      try {
        await sw.apply(peer, server, main: main);
      } on ServerSwitchException catch (e) {
        // Put the old server back so the tunnel keeps working.
        try {
          await sw.apply(peer, old, main: main);
        } on Object {
          throw ServerSwitchException('${e.message} Putting the old server back also failed - '
              'check VPN > WireGuard on the router.');
        }
        throw ServerSwitchException('${e.message} The old server was put back.');
      }
      return true;
    },
        done: '${main ? config.mainLabel : config.backupLabel} tunnel now uses ${server.name} (handshake confirmed)',
        detail: (_) => sw.monitorWarning);
    serverBusy = false;
    notifyListeners();
    return r ?? false;
  }

  /// Tests [candidates] on the backup tunnel and moves the best to main.
  Future<BestServerPlan?> findBestServer(List<ProtonServer> candidates, void Function(String) log,
      {bool skipLock = false}) async {
    if (serverBusy || candidates.isEmpty) return null;
    if (!skipLock && !await authorize('Find and switch to the best VPN server', always: true)) return null;
    final sw = _switcher = _newSwitcher();
    if (sw == null) return null;
    serverBusy = true;
    notifyListeners();
    try {
      final plan = await sw.findBest(candidates, log);
      if (plan != null && config.notifyOnFailover) {
        _events.add(AlertEvent(AlertKind.serverChanged,
            plan.changeMain ? 'VPN moved to ${plan.newMain.server.name}' : 'VPN server check done',
            '${plan.reason} ${plan.newMain.describe()}'));
      }
      return plan;
    } on OpnsenseException catch (e) {
      log('Stopped: ${e.message}');
      lastActionError = 'Server switch failed: ${e.message}';
      return null;
    } on ArgumentError catch (e) {
      log('Stopped: ${e.message}');
      return null;
    } on ServerSwitchException catch (e) {
      log('Stopped: ${e.message}');
      lastActionError = 'Server switch failed: ${e.message}';
      return null;
    } finally {
      serverBusy = false;
      _switcher = null;
      notifyListeners();
      unawaited(_refreshAfterChange());
    }
  }

  void cancelFindBest() => _switcher?.cancel();

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
        // A good read means expiry is enforced again: drop a stale failure
        // banner from an earlier poll (e.g. before the URL was fixed).
        if (lastActionError?.startsWith(bypassCheckFailedPrefix) ?? false) lastActionError = null;
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
        lastActionError = '$bypassCheckFailedPrefix${e.message}';
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
    } on ServerSwitchException catch (e) {
      lastActionError = e.message;
      return null;
    } finally {
      snapshot = snapshot.copyWith(busy: false);
      await _refreshAfterChange();
    }
  }

  Future<void> setBypass(bool on, {Duration? duration, bool skipLock = false}) async {
    if (on && !skipLock && !await authorize('Turn the whole-house VPN bypass on')) return;
    final bm = _bypass();
    await _action(
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

  /// Key-expiry lines for the Status banner (within 30 days or expired).
  List<String> get keyExpiryWarnings {
    final now = clock().toLocal();
    return [
      for (final (label, date) in [(config.mainLabel, config.mainKeyExpiry), (config.backupLabel, config.backupKeyExpiry)])
        if (parseIsoDate(date) case final exp?)
          if (daysUntil(exp, now) <= 30)
            daysUntil(exp, now) <= 0
                ? '$label tunnel key expired on $date - renew it at your VPN provider.'
                : '$label tunnel key expires in ${daysUntil(exp, now)} days ($date).',
    ];
  }

  /// "This phone" / "This PC" in messages (overridable in tests).
  String deviceWord = Platform.isAndroid ? 'This phone' : 'This PC';

  Future<void> setPcClear(bool clear) async {
    if (!supportsPcMode) return;
    if (clear && !await authorize('Take this device off the VPN (CLEAR)')) return;
    final ip = snapshot.pcIp ?? await detectPcIp(config);
    if (ip == null) {
      lastActionError = 'Could not detect this device\'s house IP - at home? (or set it in Settings)';
      notifyListeners();
      return;
    }
    await _action((c) => setPcMode(client: c, cfg: config, pcIp: ip, clear: clear),
        done: clear ? '$deviceWord is now CLEAR (direct internet)' : '$deviceWord is back on the VPN',
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
