import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:home_widget/home_widget.dart';

import '../core/bypass.dart';
import '../core/client_factory.dart';
import '../core/events.dart';
import '../core/house_state.dart';
import '../core/config.dart';
import '../core/storage.dart';
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
}

const androidWidgetProvider = 'ExitWidgetProvider';

/// Deep links used by the widget / Quick Settings tile.
const bypassConfirmUri = 'cybervulcan://bypass/confirm';
const bypassOffUri = 'cybervulcan://bypass/off';
const refreshUri = 'cybervulcan://refresh';

Future<void> pushWidgetState(HouseSnapshot s, AppConfig cfg) async {
  final bypass = s.bypassActive;
  final exit = s.error != null
      ? 'Router unreachable'
      : (bypass ?? false)
          ? 'Direct (bypass)'
          : exitLabel(s.exit, cfg);
  await HomeWidget.saveWidgetData<String>(WidgetKeys.exit, exit);
  await HomeWidget.saveWidgetData<String>(WidgetKeys.health, s.health.name);
  await HomeWidget.saveWidgetData<String>(
      WidgetKeys.bypass, bypass == null ? '?' : (bypass ? '1' : '0'));
  await HomeWidget.saveWidgetData<String>(WidgetKeys.bypassUntil,
      s.bypassExpiresAt != null && (bypass ?? false) ? formatClock(s.bypassExpiresAt!) : '');
  await HomeWidget.saveWidgetData<String>(WidgetKeys.updated, formatClock(s.fetchedAt));
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
        await notifier.show(const AlertEvent(AlertKind.bypassEnded, 'VPN bypass ended',
            'The VPN network is back on Proton.'));
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
    await HomeWidget.saveWidgetData<String>(WidgetKeys.exit, 'Router unreachable');
    await HomeWidget.saveWidgetData<String>(WidgetKeys.health, Health.problem.name);
    await HomeWidget.updateWidget(androidName: androidWidgetProvider);
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
