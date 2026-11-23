import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import '../api/models.dart';
import '../api/opnsense_client.dart';
import '../api/shaper_models.dart';
import '../api/wireguard_models.dart';
import '../net/router_link.dart';
import '../net/tailscale_engine.dart';
import '../net/tunnel.dart';
import '../platform/vpn_modes.dart';
import 'bypass.dart';
import 'client_factory.dart';
import 'config.dart';
import 'events.dart';
import 'house_state.dart';
import 'line_speed.dart';
import 'network_map.dart';
import 'pc_mode.dart';
import 'schedule.dart';
import 'shaper_presets.dart';
import 'shaper_tuner.dart';
import 'change_journal.dart';
import 'diagnostics.dart';
import 'updater.dart' show appVersion;
import 'router_server_list.dart';
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
    SystemVpn? systemVpn,
  })  : clock = clock ?? DateTime.now,
        link = link ?? RouterLink(tunnel: NativeTunnel.load()),
        homeLink = HomeLink(systemVpn ?? systemVpnForPlatform(), clock: clock);

  final PrefsStore prefs;
  final SecretStore secrets;

  /// Per-device CLEAR (Windows PC, Android phone).
  final bool supportsPcMode;
  final DateTime Function() clock;

  /// Direct vs. remote (in-app WireGuard) connection to the router.
  final RouterLink link;

  /// v2.1: system VPN for the "home devices" / "everything" remote modes,
  /// and the phone's VPN-app reminder (lib/src/platform/vpn_modes.dart).
  final HomeLink homeLink;

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
    // v2.1 hook: system VPN on/off with remote access + VPN-app reminder.
    unawaited(homeLink
        .onLink(config, next.link,
            notify: (title, body) => _events.add(AlertEvent(AlertKind.vpnReminder, title, body)))
        .then((changed) {
      if (changed && !_disposed) notifyListeners();
    }));
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

      _retryShaperRead();

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
        final stage = keyExpiryStage(exp, now.toLocal(), int.tryParse(prefs.getString(key) ?? ''));
        if (stage == null) continue;
        await prefs.setString(key, '$stage');
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

      // v2.1.13: no continuous auto-tune any more (a quiet line shows no lag,
      // so it kept raising the limits - 22 Nov). Limits are set by hand or
      // from a speed test; the shown limits are re-read about every minute so
      // a change made elsewhere shows up.
      if (shaperPipes != null && ++_shaperPolls % 4 == 0) unawaited(refreshShaperInfo());

      // Nightly "find best server".
      final lastBest = DateTime.tryParse(prefs.getString(_bestRunKey) ?? '');
      if (nightlyBestDue(config, now.toLocal(), lastBest?.toLocal()) && !serverBusy) {
        final cached = cachedServers();
        if (cached.isNotEmpty) {
          await prefs.setString(_bestRunKey, now.toUtc().toIso8601String());
          unawaited(findBestServer(
              pickCandidates(cached, config.serverCityList, max: 5, lastTested: serverLastTested), (_) {},
              skipLock: true));
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

  Future<void> _saveLocalServers(List<ProtonServer> servers) =>
      prefs.setString(serverCacheKey, jsonEncode([for (final s in servers) s.toJson()]));

  static const _listSeededKey = 'server_list_seeded_v1';
  static const _listAutoKey = 'server_list_auto_checked_v1';

  /// Why the router-stored list was not used last time (shown on the page).
  String? serverListNote;

  String _listError(OpnsenseException e) => e.kind == ApiErrorKind.forbidden
      ? 'needs the "VPN: WireGuard" privilege on your app user'
      : e.message;

  /// The server list: from the router when [AppConfig.serverListOnRouter] is
  /// on (the router is the master copy; this device keeps a copy for when the
  /// router can't be reached), else this device's own list. The first time
  /// after switching it on, this device's servers are added to the router.
  Future<List<ProtonServer>> loadServerList() async {
    final local = cachedServers();
    final c = _client;
    if (c == null) return local;
    // A new device on a router that already has the shared list turns the
    // list on by itself, once (22 Nov: the new desktop install showed only the
    // two tunnel servers). Turning it off later sticks.
    if (!config.serverListOnRouter && !prefs.flag(_listAutoKey)) {
      try {
        final found = (await c.wgPeers()).any(isListPeer);
        await prefs.setFlag(_listAutoKey);
        if (found) {
          config = config.copyWith(serverListOnRouter: true);
          await prefs.saveConfig(config);
          lastActionInfo = 'Found the shared server list on the router - switched "Keep the server list on the router" on.';
        }
      } on Object {
        // Try again next time.
      }
    }
    if (!config.serverListOnRouter) return local;
    try {
      final peers = await c.wgPeers();
      var list = <ProtonServer>[
        for (final p in peers) ?serverFromListPeer(p),
        // Servers a tunnel uses now live in that tunnel's peer, not the list:
        // named by the app on a switch (CVT_), else this device's own copy.
        for (final p in peers)
          if (!isListPeer(p))
            ?serverFromTunnelPeer(name: p.name, address: p.serverAddress, publicKey: p.publicKey, port: p.serverPort),
      ];
      for (final s in inUseByTunnels(peers, local)) {
        if (!list.any((r) => r.sameEndpoint(s.entryIp, s.publicKey))) list.add(s);
      }
      // Tunnel names follow their server's city on EVERY device, not only on
      // the one that switched (23 Nov: the phone still said San Jose).
      for (final p in peers) {
        if (isListPeer(p)) continue;
        final main = p.belongsTo(config.mainWgInstance);
        if (!main && !p.belongsTo(config.backupWgInstance)) continue;
        final s = list.where((x) => x.sameEndpoint(p.serverAddress, p.publicKey)).firstOrNull;
        if (s != null) await _followCity(main, s);
      }
      if (!prefs.flag(_listSeededKey)) {
        list = [
          ...list,
          for (final s in local)
            if (!list.any((r) => r.sameEndpoint(s.entryIp, s.publicKey))) s,
        ];
        await _syncRouterList(c, peers, list);
        await prefs.setFlag(_listSeededKey);
      }
      await _saveLocalServers(list);
      serverListNote = null;
      return list;
    } on OpnsenseException catch (e) {
      serverListNote = 'Showing this device\'s copy - the router\'s list could not be read (${_listError(e)}).';
      return local;
    } on Object catch (e) {
      serverListNote = 'Showing this device\'s copy - $e';
      return local;
    }
  }

  /// Saves the list on this device and, when switched on, adds / updates
  /// its servers in the router list. Never deletes another device's entries
  /// (review 22 Nov: a stale copy could wipe them) - use [removeServer].
  Future<void> saveServers(List<ProtonServer> servers) async {
    await _saveLocalServers(servers);
    if (!config.serverListOnRouter || _client == null) return;
    serverListNote = null;
    await _addToRouterList(servers, replace: true);
  }

  /// Removes [server] from this device's list and from the router list.
  Future<void> removeServer(ProtonServer server) async {
    await _saveLocalServers(
        [for (final s in cachedServers()) if (!s.sameEndpoint(server.entryIp, server.publicKey)) s]);
    final c = _client;
    if (!config.serverListOnRouter || c == null) return;
    try {
      for (final p in await c.wgPeers()) {
        if (isListPeer(p) && p.publicKey == server.publicKey.trim()) await c.deleteWgPeer(p.uuid);
      }
      serverListNote = null;
    } on Object catch (e) {
      serverListNote = 'Removed on this device only - ${e is OpnsenseException ? _listError(e) : e}';
    }
  }

  /// Adds [servers] to the router list (and this device's copy) without
  /// removing anything: for background saves (after a switch, Find best).
  /// Servers a tunnel uses are skipped by [planListSync].
  Future<void> _addToRouterList(List<ProtonServer> servers, {bool replace = false}) async {
    final c = _client;
    if (!config.serverListOnRouter || c == null || servers.isEmpty) return;
    try {
      final peers = await c.wgPeers();
      final onRouter = [for (final p in peers) ?serverFromListPeer(p)];
      // Everything already on the router stays. With [replace] (an edit on
      // the VPN servers page) a server given here replaces its own entry (new
      // city or name); background adds never overwrite a better-named entry.
      final merged = replace
          ? [
              for (final r in onRouter)
                if (!servers.any((s) => s.sameEndpoint(r.entryIp, r.publicKey))) r,
              ...servers,
            ]
          : [
              ...onRouter,
              for (final s in servers)
                if (!onRouter.any((r) => r.sameEndpoint(s.entryIp, s.publicKey))) s,
            ];
      await _syncRouterList(c, peers, merged);
      final local = cachedServers();
      final add = [for (final s in merged) if (!local.any((x) => x.sameEndpoint(s.entryIp, s.publicKey))) s];
      if (add.isNotEmpty) await _saveLocalServers([...local, ...add]);
    } on Object catch (e) {
      serverListNote = 'Server list on the router not updated: ${e is OpnsenseException ? _listError(e) : e}';
    }
  }

  /// Makes the router's list peers match [wanted]. Only switched-off,
  /// unlinked CVL_ peers are ever deleted; the live tunnels are not touched.
  /// Deleting is only right after a fresh read (the VPN servers page).
  Future<void> _syncRouterList(OpnsenseClient c, List<WgPeer> peers, List<ProtonServer> wanted) async {
    final plan = planListSync(peers, wanted);
    final failed = <String>[];
    for (final uuid in plan.delete) {
      try {
        await c.deleteWgPeer(uuid);
      } on OpnsenseException catch (e) {
        failed.add('remove: ${e.message}');
      }
    }
    var added = 0;
    for (final s in plan.add) {
      // One rejected entry must not stop the rest.
      try {
        await c.addWgListPeer(name: listPeerName(s), address: s.entryIp, port: s.port, publicKey: s.publicKey);
        added++;
      } on OpnsenseException catch (e) {
        failed.add('${s.name}: ${e.message}');
      } on ArgumentError catch (e) {
        // e.g. a hand-made peer with a host name endpoint: skip it, keep going.
        failed.add('${s.name}: ${e.message}');
      }
    }
    if (plan.delete.isNotEmpty || plan.add.isNotEmpty) {
      await journal.add('Server list on the router: $added added, ${plan.delete.length} removed',
          ok: failed.isEmpty,
          detail: failed.isEmpty ? 'Switched-off entries only - the tunnels were not changed.' : failed.join('; '));
    }
    if (failed.isNotEmpty) {
      throw OpnsenseException(ApiErrorKind.server, 'some servers were not saved (${failed.join('; ')})');
    }
  }

  ServerSwitcher? _newSwitcher() {
    final c = _client;
    return c == null ? null : ServerSwitcher(client: c, config: config);
  }

  /// Writes [server]'s name and city into the name of the live tunnel peer
  /// that uses it (CVT_...), so other devices can show it. Label only: no
  /// tunnel restart. Best effort.
  Future<void> nameTunnelPeer(ProtonServer server) async {
    final c = _client;
    if (c == null) return;
    try {
      for (final p in await c.wgPeers()) {
        if (isListPeer(p) || !server.sameEndpoint(p.serverAddress, p.publicKey)) continue;
        final name = tunnelPeerName(server);
        if (p.name == name) continue;
        await c.setWgPeerServer(p.uuid,
            address: p.serverAddress, port: p.serverPort, publicKey: p.publicKey, name: name);
      }
    } on Object {
      // The list still has the name on this device.
    }
  }

  /// Current main / backup peers (public data only).
  Future<(WgPeerInfo, WgPeerInfo)> tunnelPeers() async {
    final sw = _newSwitcher();
    if (sw == null) throw OpnsenseException(ApiErrorKind.network, 'Router not configured');
    final (m, b) = await sw.peers();
    return (
      WgPeerInfo(m.serverAddress, m.serverPort, m.publicKey, name: m.name),
      WgPeerInfo(b.serverAddress, b.serverPort, b.publicKey, name: b.name),
    );
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
      final label = main ? config.mainLabel : config.backupLabel;
      final known = cachedServers().where((x) => x.sameEndpoint(peer.serverAddress, peer.publicKey)).firstOrNull;
      final old = known ?? ProtonServer(
          name: 'Former $label server',
          entryIp: peer.serverAddress,
          publicKey: peer.publicKey,
          port: peer.serverPort,
          // With "names follow city" on, the tunnel's name is its city;
          // otherwise it may be a custom name ("Gaming"), not a city.
          city: !config.namesFollowCity || label == 'Main' || label == 'Backup' ? null : label);
      try {
        await sw.apply(peer, server, main: main);
      } on Object catch (err) {
        // apply() may already have removed the target's list entry: put it
        // back (review 22 Nov), whatever happens next.
        if (config.serverListOnRouter) unawaited(_addToRouterList([server]));
        // Any failure after the save (reconfigure timeout, lost router...)
        // leaves the peer on an unverified server: roll back for all of them.
        final e = err is ServerSwitchException
            ? err
            : ServerSwitchException(err is OpnsenseException ? 'Router: ${err.message}.' : 'The switch failed ($err).');
        await journal.add('${main ? 'Main' : 'Backup'} tunnel -> ${server.name}', ok: false, detail: e.message);
        if (!config.routerSafetyNet) rethrow;
        // Safety net: put the old server back so the tunnel keeps working.
        try {
          await sw.apply(peer, old, main: main);
        } on Object {
          throw ServerSwitchException('${e.message} Putting the old server back also failed - '
              'check VPN > WireGuard on the router.');
        }
        await journal.add('${main ? 'Main' : 'Backup'} tunnel back on ${peer.serverAddress}', ok: true,
            detail: 'Safety net: restored after the failed switch');
        throw ServerSwitchException('${e.message} The old server was put back.');
      }
      await journal.add('${main ? 'Main' : 'Backup'} tunnel -> ${server.name}', ok: true,
          detail: 'Handshake confirmed${sw.monitorWarning == null ? '' : '; monitor not refreshed'}');
      tuner.pathChanged();
      await _followCity(main, server);
      if (main) await _applyCityLimits(server);
      // The server the tunnel left goes (back) into the list - also on a
      // device that never had it - and so into the router list.
      final cached = cachedServers();
      if (!cached.any((s) => s.sameEndpoint(old.entryIp, old.publicKey))) {
        await _saveLocalServers([...cached, old]);
      }
      if (config.serverListOnRouter) unawaited(_addToRouterList([old]));
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
    sw.onTested = (s, m) => unawaited(_markTested(s, m));
    serverBusy = true;
    notifyListeners();
    final before = <ProtonServer>[];
    try {
      final (m0, b0) = await sw.peers();
      for (final (label, p) in [(config.mainLabel, m0), (config.backupLabel, b0)]) {
        before.add(cachedServers().where((x) => x.sameEndpoint(p.serverAddress, p.publicKey)).firstOrNull ??
            ProtonServer(name: 'Former $label server', entryIp: p.serverAddress, publicKey: p.publicKey,
                port: p.serverPort));
      }
    } on Object {
      // Only used to keep the list complete afterwards.
    }
    try {
      final plan = await sw.findBest(candidates, log, known: cachedServers());
      if (plan != null) {
        await journal.add('Find best server', ok: true, detail: plan.reason);
        tuner.pathChanged();
        if (plan.changeMain) {
          await _followCity(true, plan.newMain.server);
          await _applyCityLimits(plan.newMain.server);
        }
        final nb = plan.newBackup?.server;
        if (nb != null) await _followCity(false, nb);
      }
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
      // Candidates tried on the backup (and the servers the tunnels used
      // before) go back into the router list - ADD only: a background save of
      // this device's older copy must never delete what another device added
      // (review 22 Nov).
      if (config.serverListOnRouter) unawaited(_addToRouterList([...candidates, ...before]));
    }
  }

  /// After a switch the tunnel's name follows the new server's city (the
  /// Status title, widget, tray and alerts use it) - but only when the name is
  /// a city or the default, never a name the person chose ("Streaming").
  Future<void> _followCity(bool main, ProtonServer server) async {
    // 21 Nov: guessing whether the old name "was a city" failed on a device
    // that never had that city in its list - now a plain setting (default on).
    if (!config.namesFollowCity) return;
    final city = server.city?.trim();
    if (city == null || city.isEmpty) return;
    final old = (main ? config.mainLabel : config.backupLabel).trim();
    if (old.toLowerCase() == city.toLowerCase()) return;
    config = main ? config.copyWith(mainLabel: city) : config.copyWith(backupLabel: city);
    await prefs.saveConfig(config);
    notifyListeners();
  }

  /// Cities ticked in the VPN servers dropdown ("Cities to choose from").
  Future<void> setServerCities(List<String> cities) async {
    config = config.copyWith(serverCities: cities.join(', '));
    await prefs.saveConfig(config);
    notifyListeners();
  }

  /// Swaps the servers of the main and backup tunnels (v2.1.16). The router
  /// allows one peer per key, so: backup parks on a spare server from the
  /// list, main takes the old backup server, backup takes the old main one.
  Future<bool> swapTunnels() async {
    if (serverBusy) return false;
    if (!await authorize('Swap the main and backup VPN servers', always: true)) return false;
    final sw = _newSwitcher();
    if (sw == null) return false;
    serverBusy = true;
    notifyListeners();
    String done = '';
    final r = await _action((c) async {
      final (m, b) = await sw.peers();
      final list = cachedServers();
      ProtonServer asServer(WgPeer p, String label) =>
          list.where((x) => x.sameEndpoint(p.serverAddress, p.publicKey)).firstOrNull ??
          serverFromTunnelPeer(name: p.name, address: p.serverAddress, publicKey: p.publicKey, port: p.serverPort) ??
          ProtonServer(name: 'Former $label server', entryIp: p.serverAddress, publicKey: p.publicKey, port: p.serverPort);
      final oldMain = asServer(m, config.mainLabel);
      final oldBackup = asServer(b, config.backupLabel);
      final spare = list
          .where((x) => !x.sameEndpoint(m.serverAddress, m.publicKey) && !x.sameEndpoint(b.serverAddress, b.publicKey))
          .firstOrNull;
      if (spare == null) {
        throw ServerSwitchException('Swapping needs one more server in the list - the backup waits on it for a '
            'moment (the router allows each server on one tunnel at a time). Add one with Scan QR or Paste config.');
      }
      await sw.apply(b, spare, main: false);
      await journal.add('Swap 1/3: backup parked on ${spare.name}', ok: true);
      try {
        final (m2, _) = await sw.peers();
        await sw.apply(m2, oldBackup, main: true);
        await journal.add('Swap 2/3: main -> ${oldBackup.name}', ok: true);
        final (_, b3) = await sw.peers();
        await sw.apply(b3, oldMain, main: false);
        await journal.add('Swap 3/3: backup -> ${oldMain.name}', ok: true);
      } finally {
        // The spare goes back into the router list whatever happened.
        if (config.serverListOnRouter) unawaited(_addToRouterList([spare]));
      }
      tuner.pathChanged();
      await _followCity(true, oldBackup);
      await _followCity(false, oldMain);
      await _applyCityLimits(oldBackup);
      done = 'Swapped: main now uses ${oldBackup.name}, backup ${oldMain.name} (handshakes confirmed)';
      return true;
    }, done: 'Main and backup swapped (handshakes confirmed)');
    if (r == true && done.isNotEmpty) lastActionInfo = done;
    serverBusy = false;
    notifyListeners();
    return r ?? false;
  }

  static const _testedKey = 'server_tested_v1';

  /// When each server (by address) was last tried by Find best, seconds.
  Map<String, int> get serverLastTested {
    try {
      final j = jsonDecode(prefs.getString(_testedKey) ?? '{}');
      if (j is! Map) return const {};
      return {for (final e in j.entries) if (e.value is num) '${e.key}': (e.value as num).toInt()};
    } on Object {
      return const {};
    }
  }

  Future<void> _markTested(ProtonServer s, ServerMeasurement r) async {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final m = {...serverLastTested, s.entryIp: now};
    await prefs.setString(_testedKey, jsonEncode(m));
    final scores = {...serverScores, s.entryIp: (at: now, ms: r.delayMs, jitter: r.jitterMs, loss: r.lossPercent)};
    await prefs.setString(_scoresKey, jsonEncode({
      for (final e in scores.entries)
        e.key: {'t': e.value.at, 'ms': e.value.ms, 'j': e.value.jitter, 'l': e.value.loss},
    }));
  }

  static const _scoresKey = 'server_scores_v1';

  /// Last Find best result per server address (v2.1.19). ms null = failed.
  Map<String, ({int at, double? ms, double? jitter, double? loss})> get serverScores {
    try {
      final j = jsonDecode(prefs.getString(_scoresKey) ?? '{}');
      if (j is! Map) return const {};
      double? d(Object? v) => v is num ? v.toDouble() : null;
      return {
        for (final e in j.entries)
          if (e.value is Map && (e.value as Map)['t'] is num)
            '${e.key}': (
              at: ((e.value as Map)['t'] as num).toInt(),
              ms: d((e.value as Map)['ms']),
              jitter: d((e.value as Map)['j']),
              loss: d((e.value as Map)['l']),
            ),
      };
    } on Object {
      return const {};
    }
  }

  /// Cities from the dropdown that have servers in [servers] (empty = all).
  List<String> activeServerCities(List<ProtonServer> servers) {
    final have = {for (final s in servers) (s.city ?? '').toLowerCase()};
    return [for (final c in config.serverCityList) if (have.contains(c.toLowerCase())) c];
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
    // In the background (Android) no in-app engine is started (v2.1: the
    // device's own Tailscale app may still be used, as in v2.0) - unless a
    // system-VPN mode needs the tunnel kept up.
    final ls = await link.check(config, _wg,
        background: !_foreground && !homeLink.keepTunnelInBackground(config));
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
      allGateways = gws;
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
      wanDown: wanDownFrom(gws, config),
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

  // ----------------------------------------------------- v2.1 shaper

  late final ChangeJournal journal = ChangeJournal(prefs);
  late final ErrorLog errorLog = ErrorLog(prefs);

  /// Redacted diagnostics text for bug reports (Settings > App).
  String diagnostics() => buildDiagnostics(
        appVersion: appVersion,
        config: config,
        snapshot: snapshot,
        changes: journal.entries,
        errors: errorLog.entries,
        linkStatus: '${link.status.state.name}${link.status.viaTunnel ? ' via WireGuard' : ''}'
            '${link.status.viaTailscale ? ' via Tailscale' : ''}${link.status.detail == null ? '' : ' (${link.status.detail})'}',
        lastError: lastActionError,
      );
  late final ShaperTuner tuner = ShaperTuner(clock: clock);
  late final ShaperTuner clearTuner = ShaperTuner.clear(clock: clock);

  /// Every router gateway from the last good poll (WAN included).
  List<GatewayStatus> allGateways = const [];

  /// Saves [pipes]' limits as "original" unless already saved (merged, so
  /// VPN and CLEAR originals live side by side).
  Future<void> _saveOriginal(({ShaperPipe down, ShaperPipe up}) pipes) async {
    final orig = shaperOriginal ?? {};
    if (orig.containsKey(pipes.down.uuid) && orig.containsKey(pipes.up.uuid)) return;
    orig.putIfAbsent(pipes.down.uuid, () => pipes.down.mbit.round());
    orig.putIfAbsent(pipes.up.uuid, () => pipes.up.mbit.round());
    await prefs.setString(shaperOriginalKey, jsonEncode(orig));
  }


  static const shaperOriginalKey = 'shaper_original_v1';

  /// Original VPN limits saved before the first auto-tune change, or null.
  Map<String, int>? get shaperOriginal {
    try {
      final m = jsonDecode(prefs.getString(shaperOriginalKey) ?? '');
      return m is Map ? {for (final e in m.entries) '${e.key}': (e.value as num).toInt()} : null;
    } on Object {
      return null;
    }
  }


  /// All enabled shaper pipes as last read (Settings shows them), or null.
  List<ShaperPipe>? shaperPipes;

  /// Reads the shaper limits for the Settings card (needs "Firewall: Shaper").
  Future<void> refreshShaperInfo() async {
    final c = _client;
    if (c == null) return;
    _shaperTriedAt = clock();
    try {
      final all = await c.shaperPipes();
      allShaperPipes = all;
      shaperMainCity = await mainTunnelCity();
      final pipes = all.where((p) => p.enabled).toList();
      shaperPipes = pipes;
      if (tuner.lastReason == _shaperReadError) tuner.lastReason = null;
      _shaperReadError = null;
      final vpn = findVpnPipes(pipes);
      if (vpn != null) {
        tuner.currentDown = vpn.down.mbit.round();
        tuner.currentUp = vpn.up.mbit.round();
      }
    } on OpnsenseException catch (e) {
      shaperPipes = null;
      tuner.lastReason = _shaperReadError = e.kind == ApiErrorKind.forbidden
          ? 'Can\'t read the shaper - the app user needs "Firewall: Shaper".'
          : 'Router: ${e.message} - trying again shortly';
    }
    notifyListeners();
  }

  /// City of the main tunnel's server as of the last shaper read.
  String? shaperMainCity;

  /// Every pipe as last read, switched on or off (v2.1.13).
  List<ShaperPipe>? allShaperPipes;
  int _shaperPolls = 0;

  /// The tunnel (VPN pipes) or direct line (CLEAR pipes) limits as last read.
  ({ShaperPipe down, ShaperPipe up})? shaperPath({required bool tunnel}) {
    final all = allShaperPipes;
    if (all == null) return null;
    return tunnel ? findVpnPipesAny(all) : findClearPipesAny(all);
  }

  /// Sets the limits and/or switches the shaper on or off for one path.
  Future<bool> setShaperPath({required bool tunnel, int? down, int? up, bool? enabled}) async {
    final c = _client;
    if (c == null) return false;
    final word = tunnel ? 'tunnel' : 'direct line';
    if (!await authorize('Change the $word shaper')) return false;
    try {
      final p = (tunnel ? findVpnPipesAny : findClearPipesAny)(await c.shaperPipes());
      if (p == null) {
        throw OpnsenseException(ApiErrorKind.notFound,
            'No ${tunnel ? 'VPN' : 'CLEAR'} download/upload pipes on the router (Firewall > Shaper > Pipes)');
      }
      if (down != null) await c.setPipeBandwidth(p.down.uuid, down);
      if (up != null) await c.setPipeBandwidth(p.up.uuid, up);
      if (enabled != null) {
        await c.setPipeEnabled(p.down.uuid, enabled);
        await c.setPipeEnabled(p.up.uuid, enabled);
      }
      await c.shaperReconfigure();
      final what = [
        if (down != null || up != null) '${down ?? p.down.mbit.round()}/${up ?? p.up.mbit.round()} Mbit/s',
        if (enabled != null) enabled ? 'on' : 'off',
      ].join(', ');
      await journal.add('Shaper ($word): $what', ok: true);
      lastActionInfo = 'Shaper ($word): $what.';
      await refreshShaperInfo();
      return true;
    } on OpnsenseException catch (e) {
      lastActionError = 'Could not change the $word shaper: ${e.message}';
      notifyListeners();
      return false;
    }
  }

  /// Speed test of one path with its shaper switched off for the test, then
  /// put back as it was. Returns Mbit/s, or null on failure.
  Future<({double down, double up})?> measureShaperPath({required bool tunnel, required http.Client web}) async {
    final c = _client;
    if (c == null) return null;
    final word = tunnel ? 'tunnel' : 'direct line';
    if (!await authorize('Measure the $word speed (shaper off for about 25 seconds)')) return null;
    ({ShaperPipe down, ShaperPipe up})? p;
    try {
      p = (tunnel ? findVpnPipesAny : findClearPipesAny)(await c.shaperPipes());
      final wasOn = p != null && p.down.enabled && p.up.enabled;
      if (p != null && wasOn) {
        await c.setPipeEnabled(p.down.uuid, false);
        await c.setPipeEnabled(p.up.uuid, false);
        await c.shaperReconfigure();
        await Future<void>.delayed(const Duration(seconds: 2));
      }
      try {
        final r = await measureSpeed(web);
        await journal.add('Speed test ($word, shaper off): ${r.down.toStringAsFixed(0)}/${r.up.toStringAsFixed(1)} Mbit/s',
            ok: true);
        return r;
      } finally {
        if (p != null && wasOn) {
          await c.setPipeEnabled(p.down.uuid, true);
          await c.setPipeEnabled(p.up.uuid, true);
          await c.shaperReconfigure();
          await refreshShaperInfo();
        }
      }
    } on OpnsenseException catch (e) {
      lastActionError = 'Speed test failed: ${e.message}';
      notifyListeners();
      return null;
    } on Object catch (e) {
      lastActionError = 'Speed test failed: $e';
      notifyListeners();
      return null;
    }
  }

  // ---------------------------------------------- shaper presets (v2.1.13)

  List<ShaperPreset> get shaperPresets => decodePresets(prefs.getString(shaperPresetsKey));

  Future<void> saveShaperPreset(ShaperPreset p) async {
    await prefs.setString(shaperPresetsKey, encodePresets(upsertPreset(shaperPresets, p)));
    notifyListeners();
  }

  Future<void> deleteShaperPreset(String name) async {
    await prefs.setString(
        shaperPresetsKey, encodePresets([for (final x in shaperPresets) if (x.name.toLowerCase() != name.toLowerCase()) x]));
    notifyListeners();
  }

  /// Puts a preset's limits on the router (only the paths it holds).
  Future<bool> applyShaperPreset(ShaperPreset p) async {
    var ok = true;
    if (p.hasTunnel) ok = await setShaperPath(tunnel: true, down: p.tunnelDown, up: p.tunnelUp) && ok;
    if (p.hasLine) ok = await setShaperPath(tunnel: false, down: p.lineDown, up: p.lineUp) && ok;
    if (ok) {
      lastActionInfo = 'Shaper preset "${p.name}" is on the router (${p.summary}).';
      await journal.add('Shaper preset "${p.name}"', ok: true, detail: p.summary);
      notifyListeners();
    }
    return ok;
  }

  Map<String, ({int down, int up})> get cityTunnelLimits => decodeCityLimits(prefs.getString(shaperCityLimitsKey));

  Future<void> rememberCityTunnelLimits(String city, int down, int up) async {
    final m = {...cityTunnelLimits, cityKey(city): (down: down, up: up)};
    await prefs.setString(shaperCityLimitsKey, encodeCityLimits(m));
    notifyListeners();
  }

  Future<void> forgetCityTunnelLimits(String city) async {
    final m = {...cityTunnelLimits}..remove(cityKey(city));
    await prefs.setString(shaperCityLimitsKey, encodeCityLimits(m));
    notifyListeners();
  }

  /// City of the server the main tunnel uses now, if known.
  Future<String?> mainTunnelCity() async {
    try {
      final (m, _) = await tunnelPeers();
      final s = m.match(cachedServers()) ??
          serverFromTunnelPeer(name: m.name, address: m.address, publicKey: m.publicKey, port: m.port);
      final city = s?.city?.trim();
      if (city != null && city.isNotEmpty) return city;
    } on Object {
      // Fall through.
    }
    final label = config.mainLabel.trim();
    return config.namesFollowCity && label != 'Main' && label.isNotEmpty ? label : null;
  }

  /// After the main tunnel moves: the tunnel limits saved for the new city
  /// go on the router. No lock prompt - the switch itself was authorised.
  Future<void> _applyCityLimits(ProtonServer server) async {
    final city = server.city;
    if (city == null) return;
    final l = cityTunnelLimits[cityKey(city)];
    final c = _client;
    if (l == null || c == null) return;
    try {
      final p = findVpnPipesAny(await c.shaperPipes());
      if (p == null) return;
      await c.setPipeBandwidth(p.down.uuid, l.down);
      await c.setPipeBandwidth(p.up.uuid, l.up);
      await c.shaperReconfigure();
      await journal.add('Shaper (tunnel): ${l.down}/${l.up} Mbit/s for $city', ok: true);
      await refreshShaperInfo();
    } on Object catch (e) {
      await journal.add('Shaper limits for $city not applied', ok: false, detail: '$e');
    }
  }

  /// How the router's shaper rules are laid out, or null when unreadable.
  ShaperLayout? shaperLayout;
  String? shaperLayoutNote;

  /// Interface keys of the main and backup tunnels (e.g. opt5, opt6).
  Future<Set<String>> _tunnelIfaces(OpnsenseClient c) async {
    final devices = await c.wgInstanceDevices();
    Map<String, String> names;
    try {
      names = await c.interfaceNames();
    } on OpnsenseException {
      // Without "Diagnostics: Interface": match by name below.
      names = const {};
    }
    final keys = await c.shaperInterfaces();
    final out = <String>{};
    for (final (inst, gw) in [(config.mainWgInstance, config.mainGateway), (config.backupWgInstance, config.backupGateway)]) {
      final dev = devices[inst];
      final label = dev == null ? null : names[dev];
      // Fallback: the interface whose name starts the gateway's (WG_MAIN for WG_MAIN_GW).
      final key = keys.entries.where((e) => e.value == label).firstOrNull?.key ??
          (keys.entries.where((e) => e.value.length >= 3 && gw.toUpperCase().startsWith(e.value.toUpperCase())).toList()
                ..sort((a, b) => b.value.length.compareTo(a.value.length)))
              .firstOrNull
              ?.key;
      if (key == null) {
        throw OpnsenseException(ApiErrorKind.notFound,
            'The tunnel "$inst" has no assigned interface (Interfaces > Assignments) - the shaper needs one');
      }
      out.add(key);
    }
    return out;
  }

  Future<void> checkShaperLayout() async {
    final c = _client;
    if (c == null) return;
    try {
      shaperLayout = classifyShaperLayout(
        rules: await c.shaperRules(),
        queues: await c.shaperQueues(),
        pipes: await c.shaperPipes(),
        tunnelIfaces: await _tunnelIfaces(c),
      );
      shaperLayoutNote = null;
    } on OpnsenseException catch (e) {
      shaperLayout = null;
      shaperLayoutNote = e.kind == ApiErrorKind.forbidden
          ? 'Can\'t check the shaper rules - the app user needs "Firewall: Shaper" and "Diagnostics: Interface".'
          : e.message;
    }
    notifyListeners();
  }

  /// Replaces the shaper rules that feed the VPN / CLEAR pipes with rules by
  /// exit path: tunnel interfaces -> VPN pipes, WAN -> CLEAR pipes. Other
  /// rules are not touched.
  Future<bool> setupExitPathShaper() async {
    final c = _client;
    if (c == null) return false;
    if (!await authorize('Set up the shaper rules by exit path', always: true)) return false;
    try {
      final pipes = await c.shaperPipes();
      final vpn = findVpnPipesAny(pipes);
      final line = findClearPipesAny(pipes);
      if (vpn == null || line == null) {
        throw OpnsenseException(ApiErrorKind.notFound,
            'Needs pipes named "VPN download", "VPN upload", "CLEAR download", "CLEAR upload" (Firewall > Shaper > Pipes)');
      }
      final queues = await c.shaperQueues();
      String queueFor(ShaperPipe p) {
        final q = queues.where((q) => q.pipe == p.uuid).firstOrNull;
        if (q == null) {
          throw OpnsenseException(ApiErrorKind.notFound, 'No queue on the pipe "${p.description}" (Firewall > Shaper > Queues)');
        }
        return q.uuid;
      }

      final ifaces = (await _tunnelIfaces(c)).toList();
      final used = {vpn.down.uuid, vpn.up.uuid, line.down.uuid, line.up.uuid};
      final old = [
        for (final r in await c.shaperRules())
          if (used.contains(queues.where((q) => q.uuid == r.target).firstOrNull?.pipe ?? r.target)) r.uuid,
      ];
      final names = [config.mainLabel, config.backupLabel];
      var seq = 50;
      for (var i = 0; i < ifaces.length; i++) {
        await c.addShaperRule(
            sequence: seq++, interface: ifaces[i], direction: 'in', target: queueFor(vpn.down),
            description: 'Tunnel download - ${names[i]}');
        await c.addShaperRule(
            sequence: seq++, interface: ifaces[i], direction: 'out', target: queueFor(vpn.up),
            description: 'Tunnel upload - ${names[i]}');
      }
      await c.addShaperRule(
          sequence: 60, interface: 'wan', direction: 'in', target: queueFor(line.down),
          description: 'Line download - WAN (direct, CLEAR, bypass)');
      await c.addShaperRule(
          sequence: 61, interface: 'wan', direction: 'out', target: queueFor(line.up),
          description: 'Line upload - WAN (direct, CLEAR, bypass)');
      for (final u in old) {
        await c.deleteShaperRule(u);
      }
      await c.shaperReconfigure();
      await journal.add('Shaper rules set up by exit path', ok: true, detail: '${old.length} old rule(s) replaced');
      lastActionInfo = 'Shaper rules now follow the exit path (tunnel / direct line).';
      await checkShaperLayout();
      return true;
    } on OpnsenseException catch (e) {
      lastActionError = 'Could not set up the shaper rules: ${e.message}';
      notifyListeners();
      return false;
    }
  }

  /// The last shaper read failure shown in Settings (cleared when a read works).
  String? _shaperReadError;
  DateTime? _shaperTriedAt;

  /// After a good router check: a failed shaper read (e.g. Settings opened
  /// while remote access was still reconnecting) is retried, at most every 30 s.
  void _retryShaperRead() {
    if (_shaperReadError == null || _shaperReadError!.startsWith('Can\'t')) return;
    final t = _shaperTriedAt;
    if (t != null && clock().difference(t) < const Duration(seconds: 30)) return;
    unawaited(refreshShaperInfo());
  }

  /// Puts the limits from before auto-tune back on the router.
  Future<bool> restoreShaperOriginal({String reason = 'restored by you'}) async {
    final c = _client;
    final orig = shaperOriginal;
    if (c == null || orig == null) return false;
    try {
      for (final e in orig.entries) {
        await c.setPipeBandwidth(e.key, e.value);
      }
      await c.shaperReconfigure();
      await prefs.remove(shaperOriginalKey);
      for (final t in [tuner, clearTuner]) {
        t.pathChanged();
        t.currentDown = null;
        t.currentUp = null;
      }
      await journal.add('Shaper back to the original limits', ok: true, detail: reason);
      lastActionInfo = 'Shaper limits restored (${orig.values.join(' / ')} Mbit/s).';
      notifyListeners();
      return true;
    } on OpnsenseException catch (e) {
      lastActionError = 'Could not restore the shaper limits: ${e.message}';
      notifyListeners();
      return false;
    }
  }

  /// Starts tuning afresh: new baseline, limits to the middle of the range.
  Future<void> retuneShaper() async {
    final c = _client;
    if (c == null) return;
    if (!await authorize('Re-tune the router shaper')) return;
    await _action((c) async {
      final p = findVpnPipes(await c.shaperPipes());
      if (p == null) throw OpnsenseException(ApiErrorKind.notFound, 'No VPN shaper pipes found on the router');
      await _saveOriginal(p);
      final down = ((config.shaperMinDown + config.shaperMaxDown) / 2).round();
      final up = ((config.shaperMinUp + config.shaperMaxUp) / 2).round();
      await c.setPipeBandwidth(p.down.uuid, down);
      await c.setPipeBandwidth(p.up.uuid, up);
      await c.shaperReconfigure();
      tuner.pathChanged();
      tuner.currentDown = down;
      tuner.currentUp = up;
      await journal.add('Shaper re-tune from $down/$up Mbit/s', ok: true);
      final cp = config.shaperClearAutoTune ? findClearPipes(await c.shaperPipes()) : null;
      if (cp != null) {
        await _saveOriginal(cp);
        final cd = ((config.shaperClearMinDown + config.shaperClearMaxDown) / 2).round();
        final cu = ((config.shaperClearMinUp + config.shaperClearMaxUp) / 2).round();
        await c.setPipeBandwidth(cp.down.uuid, cd);
        await c.setPipeBandwidth(cp.up.uuid, cu);
        await c.shaperReconfigure();
        clearTuner.pathChanged();
        clearTuner.currentDown = cd;
        clearTuner.currentUp = cu;
        await journal.add('CLEAR shaper re-tune from $cd/$cu Mbit/s', ok: true);
      }
      return true;
    }, done: 'Shaper re-tune started - auto-tune adjusts it under load');
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
    // Switching the router list off and on again later merges this device's
    // list into the router's once more.
    if (config.serverListOnRouter && !cfg.serverListOnRouter) await prefs.remove(_listSeededKey);
    final listTurnedOn = !config.serverListOnRouter && cfg.serverListOnRouter;
    config = cfg;
    await prefs.saveConfig(cfg);
    if (credentials != null) {
      await secrets.write(credentials);
      _creds = credentials;
    }
    _rebuildClient();
    await link.pause(); // keeps a Tailscale sign-in in progress
    if (pollChanged) _schedule();
    await _refreshAfterChange();
    // Switching the shared list on copies this device's list to the router
    // straight away (not only when the VPN servers page opens).
    if (listTurnedOn) {
      await loadServerList();
      lastActionInfo = serverListNote == null
          ? 'Server list copied to the router - your other devices see it too.'
          : null;
      if (serverListNote != null) lastActionError = 'Server list: $serverListNote';
      notifyListeners();
    }
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

  // ---- v2.1 built-in Tailscale (tailscale agent). The logic lives in
  // RouterLink / TailscaleEngine; these are the hooks for the UI.

  /// State of the Tailscale engine built into the app.
  TailscaleStatus get tailscaleStatus => link.tailscaleStatus;
  bool get tailscaleAvailable => link.tailscale.isAvailable;
  String? get tailscaleUnavailableReason => link.tailscale.unavailableReason;

  /// Starts the built-in Tailscale engine so this device can sign in (works
  /// at home too). Returns the sign-in URL to open in a browser, or null when
  /// no sign-in is needed (already signed in) or it failed ([lastActionError]).
  /// [cfg]: settings being edited (default: the saved ones).
  Future<String?> logInTailscale([AppConfig? cfg]) async {
    try {
      final st = await link.startTailscale(cfg ?? config);
      lastActionError = st.state == TailscaleState.error
          ? 'Tailscale: ${st.lastError ?? 'the engine stopped'}'
          : st.state == TailscaleState.starting
              ? 'Tailscale is still starting - no Internet connection? Try again in a moment.'
              : null;
      notifyListeners();
      return st.state == TailscaleState.needsLogin ? st.authUrl : null;
    } on TailscaleException catch (e) {
      lastActionError = 'Tailscale could not start: ${e.message}';
      notifyListeners();
      return null;
    }
  }

  /// Signs this device out of the built-in Tailscale and forgets its login.
  Future<void> logOutTailscale() async {
    try {
      await link.logoutTailscale();
      lastActionInfo = 'Signed out of Tailscale. You can remove the device in the Tailscale admin console.';
    } on TailscaleException catch (e) {
      lastActionError = 'Tailscale sign-out failed: ${e.message}';
    }
    notifyListeners();
  }

  /// Called by the platform layer: no remote tunnel while in the background.
  ///
  /// Going to the background is acted on only after [backgroundGrace]: the
  /// fingerprint prompt, the notification shade or a quick app switch briefly
  /// report "paused" too, and stopping Tailscale then broke the connection
  /// right after unlocking.
  void setForeground(bool foreground) {
    if (foreground) {
      _backgroundTimer?.cancel();
      _backgroundTimer = null;
      if (_foreground) return;
      _foreground = true;
      unawaited(refresh());
      return;
    }
    if (!_foreground || _backgroundTimer != null) return;
    _backgroundTimer = Timer(backgroundGrace, () {
      _backgroundTimer = null;
      if (_disposed) return;
      _foreground = false;
      if (homeLink.keepTunnelInBackground(config)) return; // v2.1: the VPN needs the tunnel
      unawaited(link.pause());
    });
  }

  Timer? _backgroundTimer;

  /// How long the app must stay in the background before remote access stops.
  Duration backgroundGrace = const Duration(seconds: 15);

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
    _backgroundTimer?.cancel();
    _client?.close();
    unawaited(link.close());
    unawaited(_events.close());
    super.dispose();
  }
}
