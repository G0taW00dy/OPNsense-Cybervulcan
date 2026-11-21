import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:home_widget/home_widget.dart';

import '../core/bypass.dart';
import '../core/client_factory.dart';
import '../core/events.dart';
import '../core/house_state.dart';
import '../core/config.dart';
import '../core/storage.dart';
import '../net/router_link.dart';
import '../ui/format.dart';
import 'notifications.dart';

/// Keys shared with the Kotlin side (ExitWidgetProvider / BypassTileService).
/// Everything is stored as a String to avoid type ambiguity across versions.
class WidgetKeys {
  static const exit = 'cv_exit';
  static const health = 'cv_health';
  static const bypass = 'cv_bypass'; // "1" | "0" | "?"
  static const bypassUntil = 'cv_bypass_until'; // "HH:MM" or ""
  static const updated = 'cv_updated'; // "HH:MM"
  static const status = 'cv_status'; // "PROTECTED", "LAST KNOWN", ...
  static const title = 'cv_title'; // big line: exit city
  static const detail = 'cv_detail'; // "VPN OK - 247 ms - backup online"
  static const where = 'cv_where'; // "Away - via Tailscale - 15:13"
  static const lastGood = 'cv_last_good'; // "HH:MM" of the last fresh status
}

const androidWidgetProvider = 'ExitWidgetProvider';

/// Deep links used by the widget / Quick Settings tile.
const bypassConfirmUri = 'cybervulcan://bypass/confirm';
const bypassOffUri = 'cybervulcan://bypass/off';
const refreshUri = 'cybervulcan://refresh';

Future<void> pushWidgetState(HouseSnapshot s, AppConfig cfg) async {
  if (!s.configured) {
    await _save({
      WidgetKeys.status: 'NOT SET UP',
      WidgetKeys.title: 'Cybervulcan',
      WidgetKeys.detail: 'Open the app to connect it to your router.',
      WidgetKeys.where: '',
      WidgetKeys.health: 'notConfigured',
      WidgetKeys.bypass: '?',
    });
    return;
  }
  // Router out of reach (away with the app paused, or no remote access): keep
  // the last real status on the widget, greyed, instead of a red "unreachable".
  final outOfReach = !s.reachable && (s.link == null || s.link!.state == LinkState.notHome);
  if (outOfReach) {
    await markWidgetOutOfReach();
    return;
  }
  final bypass = s.bypassActive;
  final g = s.activeGateway;
  final backupUp = s.backup?.health.isUp;
  final detail = !s.reachable
      ? headline(s, cfg)
      : (bypass ?? false)
          ? headline(s, cfg)
          : [
              switch (s.exit) {
                ProtonExit.main => 'VPN OK',
                ProtonExit.backup => 'On the backup tunnel',
                ProtonExit.none => 'Both tunnels down',
                ProtonExit.unknown => 'Tunnels unknown',
              },
              if (g?.delayMs != null) '${g!.delayMs!.toStringAsFixed(0)} ms',
              if (s.exit == ProtonExit.main && backupUp != null) backupUp ? 'backup ready' : 'backup down',
            ].join('  ·  ');
  final link = s.link;
  final where = [
    if (link == null || !link.remote)
      'Home'
    else
      'Away · ${link.viaTailscale ? 'via Tailscale' : 'via remote tunnel'}',
    formatClock(s.fetchedAt),
  ].join('  ·  ');
  await _save({
    WidgetKeys.status: heroLabel(s).toUpperCase(),
    WidgetKeys.title: heroTitle(s, cfg),
    WidgetKeys.detail: detail,
    WidgetKeys.where: where,
    WidgetKeys.health: s.health.name,
    WidgetKeys.bypass: bypass == null ? '?' : (bypass ? '1' : '0'),
    WidgetKeys.bypassUntil: s.bypassExpiresAt != null && (bypass ?? false) && !isNoLimitExpiry(s.bypassExpiresAt)
        ? formatClock(s.bypassExpiresAt!)
        : '',
    WidgetKeys.updated: formatClock(s.fetchedAt),
    WidgetKeys.lastGood: s.reachable ? formatClock(s.fetchedAt) : '',
    // The Quick Settings tile still reads this one.
    WidgetKeys.exit: s.error != null
        ? 'Router unreachable'
        : (bypass ?? false)
            ? 'Direct (bypass)'
            : exitLabel(s.exit, cfg),
  });
}

/// Greys the widget out with the last real status ("last seen 15:13").
Future<void> markWidgetOutOfReach() async {
  final last = await HomeWidget.getWidgetData<String>(WidgetKeys.lastGood);
  final hadStatus = last != null && last.isNotEmpty;
  await _save({
    WidgetKeys.status: 'LAST KNOWN',
    if (!hadStatus) WidgetKeys.title: 'Out of reach',
    if (!hadStatus) WidgetKeys.detail: 'The router has not answered yet.',
    WidgetKeys.where: hadStatus
        ? 'Router out of reach · last seen $last · open the app to refresh'
        : 'Open the app to connect',
    WidgetKeys.health: 'stale',
    WidgetKeys.bypass: '?', // no bypass button while the router can't be reached
  });
}

Future<void> _save(Map<String, String> values) async {
  for (final e in values.entries) {
    await HomeWidget.saveWidgetData<String>(e.key, e.value);
  }
  await HomeWidget.updateWidget(androidName: androidWidgetProvider);
}

/// Runs in a background isolate started by home_widget when the widget's
/// "bypass off" / "refresh" buttons or the Quick Settings tile are used.
/// Turning bypass ON always goes through the app's confirmation dialog.
@pragma('vm:entry-point')
Future<void> widgetBackgroundCallback(Uri? uri) async {
  WidgetsFlutterBinding.ensureInitialized();
  final prefs = await PrefsStore.open();
  final cfg = prefs.loadConfig();
  final client = buildRouterClient(cfg, await SecretStore().read());
  if (client == null) return;
  final bm = BypassManager(client: client, config: cfg, store: prefs);
  final notifier = Notifier();
  await notifier.init(requestPermission: false);
  try {
    var state = await bm.read();
    if (uri?.toString() == bypassOffUri && state.active) {
      state = await bm.turnOff();
      if (cfg.notifyOnBypass) {
        await notifier.show(AlertEvent(AlertKind.bypassEnded, 'VPN bypass ended',
            'The VPN network is back on ${cfg.vpnName}.'));
      }
    } else {
      state = (await bm.enforce(state)).$2;
    }
    final gws = await client.gatewayStatus();
    await pushWidgetState(
      HouseSnapshot(
        fetchedAt: DateTime.now(),
        main: findGateway(gws, cfg.mainGateway),
        backup: findGateway(gws, cfg.backupGateway),
        bypassActive: state.active,
        bypassExpiresAt: state.expiresAt,
      ),
      cfg,
    );
  } on Exception catch (_) {
    // The widget's refresh can only try the home address (no Tailscale in
    // the background): away, that is expected - show the last known status.
    await markWidgetOutOfReach();
  } finally {
    client.close();
  }
}

/// Wires the main-isolate side: callback registration and deep links.
class AndroidWidgetBridge {
  AndroidWidgetBridge({required this.onConfirmBypass});

  final VoidCallback onConfirmBypass;
  StreamSubscription<Uri?>? _sub;

  Future<void> init() async {
    await HomeWidget.registerInteractivityCallback(widgetBackgroundCallback);
    _handle(await HomeWidget.initiallyLaunchedFromHomeWidget());
    _sub = HomeWidget.widgetClicked.listen(_handle);
  }

  void _handle(Uri? uri) {
    if (uri?.toString() == bypassConfirmUri) onConfirmBypass();
  }

  void dispose() => unawaited(_sub?.cancel());
}
