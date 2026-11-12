import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

import '../core/bypass.dart';
import '../core/controller.dart';
import '../core/house_state.dart';
import '../ui/format.dart';

String trayIconAsset(Health h) {
  final name = switch (h) {
    Health.ok => 'green',
    Health.warning => 'amber',
    Health.problem => 'red',
    Health.bypass => 'purple',
    Health.notConfigured => 'grey',
  };
  return Platform.isWindows ? 'assets/icons/tray_$name.ico' : 'assets/icons/tray_$name.png';
}

/// Windows tray icon + menu. Closing the window hides it to the tray.
class TrayController with TrayListener, WindowListener {
  TrayController(this.controller, {required this.onRequestBypassOn});

  final CybervulcanController controller;

  /// Bypass ON needs the "affects everyone" confirmation dialog in the window.
  final VoidCallback onRequestBypassOn;

  Health? _lastHealth;
  String? _lastMenuSig;
  bool _quitting = false;

  Future<void> init() async {
    trayManager.addListener(this);
    windowManager.addListener(this);
    await windowManager.setPreventClose(true);
    controller.addListener(_sync);
    await _sync();
  }

  Future<void> showWindow() async {
    await windowManager.show();
    await windowManager.focus();
  }

  Future<void> _sync() async {
    final s = controller.snapshot;
    final h = s.health;
    if (h != _lastHealth) {
      _lastHealth = h;
      await trayManager.setIcon(trayIconAsset(h));
    }
    final tip = 'Cybervulcan - ${headline(s, controller.config)}';
    // Windows limits tray tooltips to 127 characters.
    await trayManager.setToolTip(tip.length > 120 ? '${tip.substring(0, 117)}...' : tip);

    final bypassOn = s.bypassActive ?? false;
    final pcClear = s.pcClear;
    final noLimit = isNoLimitExpiry(s.bypassExpiresAt);
    final remaining = noLimit ? null : s.bypassExpiresAt?.difference(DateTime.now().toUtc());
    final items = <MenuItem>[
      MenuItem(key: 'status', label: headline(s, controller.config), disabled: true),
      if (bypassOn && remaining != null)
        MenuItem(key: 'bypass_left', label: 'Bypass ends in ${formatDuration(remaining)}', disabled: true),
      if (bypassOn && noLimit)
        MenuItem(key: 'bypass_left', label: 'Bypass has no time limit', disabled: true),
      MenuItem.separator(),
      MenuItem(key: 'open', label: 'Open Cybervulcan'),
      if (controller.supportsPcMode && pcClear != null)
        MenuItem(
          key: 'pc_toggle',
          label: pcClear ? 'This PC: switch back to VPN' : 'This PC: switch to CLEAR (direct)',
          disabled: s.busy,
        ),
      MenuItem(
        key: 'bypass_toggle',
        label: bypassOn ? 'Whole house: turn VPN bypass OFF' : 'Whole house: VPN bypass ON...',
        disabled: s.busy || s.bypassActive == null,
      ),
      MenuItem(key: 'refresh', label: 'Refresh now'),
      MenuItem.separator(),
      MenuItem(key: 'quit', label: 'Quit'),
    ];
    final sig = items.map((i) => '${i.key}|${i.label}|${i.disabled}').join(';');
    if (sig != _lastMenuSig) {
      _lastMenuSig = sig;
      await trayManager.setContextMenu(Menu(items: items));
    }
  }

  @override
  void onTrayIconMouseDown() => unawaited(showWindow());

  @override
  void onTrayIconRightMouseDown() => unawaited(trayManager.popUpContextMenu());

  @override
  void onTrayMenuItemClick(MenuItem menuItem) {
    switch (menuItem.key) {
      case 'open':
        unawaited(showWindow());
      case 'pc_toggle':
        unawaited(controller.setPcClear(!(controller.snapshot.pcClear ?? false)));
      case 'bypass_toggle':
        if (controller.snapshot.bypassActive ?? false) {
          unawaited(controller.setBypass(false));
        } else {
          unawaited(showWindow().then((_) => onRequestBypassOn()));
        }
      case 'refresh':
        unawaited(controller.refresh());
      case 'quit':
        unawaited(quit());
    }
  }

  Future<void> quit() async {
    _quitting = true;
    controller.removeListener(_sync);
    await trayManager.destroy();
    await windowManager.setPreventClose(false);
    await windowManager.destroy();
  }

  @override
  void onWindowClose() {
    if (_quitting) return;
    unawaited(windowManager.hide());
  }
}
