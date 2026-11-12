import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import 'src/core/controller.dart';
import 'src/core/events.dart';
import 'src/core/storage.dart';
import 'src/core/updater.dart';
import 'src/platform/android_widget.dart';
import 'src/platform/notifications.dart';
import 'src/platform/tray.dart';
import 'src/ui/app.dart';
import 'src/ui/bypass_dialog.dart';

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
    supportsPcMode: Platform.isWindows,
  );

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
    controller.addListener(() => unawaited(pushWidgetState(controller.snapshot, controller.config)));
    // Defer until the first frame so the navigator exists for the dialog.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      unawaited(AndroidWidgetBridge(onConfirmBypass: requestBypassConfirm).init());
    });
  }

  await controller.init();
  updates.start(); // after init, so the saved "check automatically" setting is loaded
}
