import 'dart:io';

import 'package:flutter_local_notifications/flutter_local_notifications.dart';

import '../core/events.dart';

/// Windows toast identity. The installer registers the same AppUserModelID
/// (with DisplayName "Cybervulcan") on the Start-menu shortcut, so toasts show
/// "Cybervulcan" as the sender instead of "Windows PowerShell".
const windowsAppUserModelId = 'Cybervulcan.OPNsenseCybervulcan';
const windowsToastGuid = '6f0e6a8c-3b0e-4d7e-9a7c-0c7b1e5a2d41';
const notificationSenderName = 'Cybervulcan';

class Notifier {
  final _plugin = FlutterLocalNotificationsPlugin();
  bool _ready = false;

  static const _channelId = 'house_alerts';

  Future<void> init({bool requestPermission = true}) async {
    const settings = InitializationSettings(
      android: AndroidInitializationSettings('ic_stat_opn'),
      windows: WindowsInitializationSettings(
        appName: notificationSenderName,
        appUserModelId: windowsAppUserModelId,
        guid: windowsToastGuid,
      ),
    );
    try {
      _ready = await _plugin.initialize(settings) ?? false;
      if (Platform.isAndroid && requestPermission) {
        await _plugin
            .resolvePlatformSpecificImplementation<AndroidFlutterLocalNotificationsPlugin>()
            ?.requestNotificationsPermission();
      }
    } on Exception {
      _ready = false;
    }
  }

  Future<void> show(AlertEvent e) async {
    if (!_ready) return;
    final urgent = e.kind == AlertKind.bothDown;
    final details = NotificationDetails(
      android: AndroidNotificationDetails(
        _channelId,
        'House network alerts',
        channelDescription: 'VPN failover, kill switch and bypass changes',
        importance: urgent ? Importance.max : Importance.high,
        priority: urgent ? Priority.max : Priority.high,
        icon: 'ic_stat_opn',
      ),
      windows: const WindowsNotificationDetails(),
    );
    await _plugin.show(e.kind.index, e.title, e.body, details);
  }
}
