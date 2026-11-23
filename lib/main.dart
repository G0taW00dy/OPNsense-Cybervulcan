import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import 'src/core/controller.dart';
import 'src/core/events.dart';
import 'src/core/storage.dart';
import 'src/core/updater.dart';
import 'src/net/tailscale_engine.dart';
import 'src/platform/android_widget.dart';
import 'src/platform/app_lock.dart';
import 'src/platform/notifications.dart';
import 'src/platform/tray.dart';
import 'src/ui/app.dart';
import 'src/ui/bypass_dialog.dart';
import 'src/ui/remote_access.dart';

AppLifecycleListener? appLifecycle;

Future<void> main(List<String> args) async {
  WidgetsFlutterBinding.ensureInitialized();
  final startMinimized = args.contains('--minimized');

  if (Platform.isWindows) {
    await windowManager.ensureInitialized();
    const options = WindowOptions(
      size: Size(1000, 740),
      minimumSize: Size(420, 560),
      center: true,
      title: 'OPNsense Cybervulcan',
    );
    unawaited(windowManager.waitUntilReadyToShow(options, () async {
      if (!startMinimized) {
        await windowManager.show();
        await windowManager.focus();
      }
    }));
  }

  final controller = CybervulcanController(
    prefs: await PrefsStore.open(),
    secrets: SecretStore(),
    // Per-device CLEAR: the PC, and (v2.0) the phone on house Wi-Fi.
    supportsPcMode: Platform.isWindows || Platform.isAndroid,
  );

  // v2.1.3: a native crash from the last run (built-in Tailscale) goes into
  // the diagnostics, and a start that took the app down pauses the engine.
  TailscaleCrashGuard.store = controller.prefs;
  final nativeCrash = await takeNativeCrash();
  if (nativeCrash != null) {
    await controller.errorLog.add('Native crash on the last run', StackTrace.fromString(nativeCrash));
  }
  if (await TailscaleCrashGuard.checkAtLaunch(nativeCrash: nativeCrash != null)) {
    controller.lastActionError = 'The built-in Tailscale engine closed the app last time, so it is paused. '
        'Settings > Remote access > "Sign in to Tailscale" tries again; Copy diagnostics shows the details.';
  }

  // Diagnostics (v2.1): remember recent uncaught errors (redacted) so
  // "Copy diagnostics" can include them.
  final previousOnError = FlutterError.onError;
  FlutterError.onError = (details) {
    unawaited(controller.errorLog.add(details.exception, details.stack));
    previousOnError?.call(details);
  };
  WidgetsBinding.instance.platformDispatcher.onError = (error, stack) {
    unawaited(controller.errorLog.add(error, stack));
    return false;
  };

  final appLock = AppLock(store: controller.secrets, context: () => lockDialogContext(controller));
  runExternal = controller.whileExternal;
  controller.authorizer = appLock.authorize;

  final notifier = Notifier();
  await notifier.init();
  controller.events.listen((e) => unawaited(notifier.show(e)));

  void requestBypassConfirm() {
    final ctx = navigatorKey.currentContext;
    if (ctx != null) unawaited(confirmAndStartBypass(ctx, controller));
  }

  final updates = UpdateService(
    target: Platform.isWindows ? UpdateTarget.windows : UpdateTarget.android,
    autoCheck: () => controller.config.checkUpdates,
    testBuilds: () => controller.config.testBuilds,
  );
  updates.found.listen((r) => unawaited(notifier.show(AlertEvent(
        AlertKind.updateAvailable,
        'Cybervulcan ${r.version} is available',
        'Open the app to install it.',
      ))));

  runApp(CybervulcanApp(controller: controller, updates: updates));

  if (Platform.isWindows) {
    final tray = TrayController(controller, onRequestBypassOn: requestBypassConfirm);
    await tray.init();
    updates.quitApp = tray.quit;
  }
  if (Platform.isAndroid) {
    // No remote-access tunnel while the app is in the background.
    appLifecycle = AppLifecycleListener(
      onStateChange: (st) => controller.setForeground(
          st == AppLifecycleState.resumed || st == AppLifecycleState.inactive),
    );
    controller.addListener(() => unawaited(pushWidgetState(controller.snapshot, controller.config)));
    // Defer until the first frame so the navigator exists for the dialog.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      unawaited(AndroidWidgetBridge(onConfirmBypass: requestBypassConfirm).init());
    });
  }

  await controller.init();
  updates.start(); // after init, so the saved "check automatically" setting is loaded
}
