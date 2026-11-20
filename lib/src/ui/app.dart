import 'dart:io';

import 'package:flutter/material.dart';

import '../core/controller.dart';
import '../core/updater.dart';
import 'devices_page.dart';
import 'help_page.dart';
import 'settings_page.dart';
import 'setup_wizard.dart';
import 'status_page.dart';
import 'tests_page.dart';
import 'theme.dart';
import 'widgets/vulcan_logo.dart';

final navigatorKey = GlobalKey<NavigatorState>();

class CybervulcanApp extends StatelessWidget {
  const CybervulcanApp({super.key, required this.controller, this.updates});

  final CybervulcanController controller;
  final UpdateService? updates;

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'OPNsense Cybervulcan',
        navigatorKey: navigatorKey,
        debugShowCheckedModeBanner: false,
        theme: buildTheme(),
        themeMode: ThemeMode.dark,
        home: LockGate(controller: controller, child: HomeShell(controller: controller, updates: updates)),
      );
}

class HomeShell extends StatefulWidget {
  const HomeShell({super.key, required this.controller, this.updates});
  final CybervulcanController controller;
  final UpdateService? updates;

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _index = 0;

  static const _destinations = [
    (Icons.shield_outlined, Icons.shield, 'Status'),
    (Icons.devices_outlined, Icons.devices, 'Devices'),
    (Icons.speed_outlined, Icons.speed, 'Tests'),
    (Icons.settings_outlined, Icons.settings, 'Settings'),
  ];

  @override
  Widget build(BuildContext context) {
    final c = widget.controller;
    return ListenableBuilder(
      listenable: c,
      builder: (context, _) {
        if (!c.hasCredentials) {
          return Scaffold(
            appBar: AppBar(title: const _Title()),
            body: SetupWizard(controller: c),
          );
        }
        final pages = [
          StatusPage(controller: c, updates: widget.updates),
          DevicesPage(key: ValueKey('devices-${c.config.baseUrl}'), controller: c),
          TestsPage(controller: c),
          SettingsPage(controller: c, updates: widget.updates),
        ];
        final wide = MediaQuery.sizeOf(context).width >= 720;
        final body = IndexedStack(index: _index, children: pages);
        if (wide) {
          return Scaffold(
            body: Row(children: [
              NavigationRail(
                selectedIndex: _index,
                onDestinationSelected: (i) => setState(() => _index = i),
                labelType: NavigationRailLabelType.all,
                leading: const Padding(
                  padding: EdgeInsets.symmetric(vertical: 16),
                  child: VulcanLogo(size: 40),
                ),
                trailing: Expanded(
                  child: Align(
                    alignment: Alignment.bottomCenter,
                    child: Padding(
                      padding: const EdgeInsets.only(bottom: 16),
                      child: IconButton(
                        tooltip: 'Setup guide',
                        onPressed: () => openSetupGuide(context),
                        icon: const Icon(Icons.help_outline),
                      ),
                    ),
                  ),
                ),
                destinations: [
                  for (final d in _destinations)
                    NavigationRailDestination(icon: Icon(d.$1), selectedIcon: Icon(d.$2), label: Text(d.$3)),
                ],
              ),
              const VerticalDivider(width: 1),
              Expanded(child: SafeArea(child: body)),
            ]),
          );
        }
        return Scaffold(
          appBar: AppBar(title: const _Title(), actions: [
            IconButton(
              tooltip: 'Setup guide',
              onPressed: () => openSetupGuide(context),
              icon: const Icon(Icons.help_outline),
            ),
          ]),
          body: body,
          bottomNavigationBar: NavigationBar(
            selectedIndex: _index,
            onDestinationSelected: (i) => setState(() => _index = i),
            destinations: [
              for (final d in _destinations)
                NavigationDestination(icon: Icon(d.$1), selectedIcon: Icon(d.$2), label: d.$3),
            ],
          ),
        );
      },
    );
  }
}

class _Title extends StatelessWidget {
  const _Title();

  @override
  Widget build(BuildContext context) => const Row(children: [
        VulcanLogo(size: 30),
        SizedBox(width: 12),
        Text('Cybervulcan'),
      ]);
}


/// App lock (v2.0.2): shows a lock screen until the person unlocks, and
/// tells the controller when the app goes to / comes back from the
/// background so it can lock again after the chosen time.
class LockGate extends StatefulWidget {
  const LockGate({super.key, required this.controller, required this.child});
  final CybervulcanController controller;
  final Widget child;

  @override
  State<LockGate> createState() => _LockGateState();
}

class _LockGateState extends State<LockGate> with WidgetsBindingObserver {
  bool _prompting = false;
  bool _autoTried = false;

  CybervulcanController get c => widget.controller;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
        c.appBackgrounded();
        _autoTried = false;
      case AppLifecycleState.resumed:
        c.appForegrounded();
      case AppLifecycleState.inactive:
      case AppLifecycleState.detached:
        break;
    }
  }

  Future<void> _unlock() async {
    if (_prompting) return;
    setState(() => _prompting = true);
    await c.unlock();
    if (mounted) setState(() => _prompting = false);
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
        listenable: c,
        builder: (context, _) {
          if (!c.locked) return widget.child;
          // Phone: ask straight away when the lock screen appears. PC: wait
          // for a click (the tray app may start hidden at sign-in).
          if (Platform.isAndroid && !_autoTried && !_prompting) {
            _autoTried = true;
            WidgetsBinding.instance.addPostFrameCallback((_) => _unlock());
          }
          final t = Theme.of(context).textTheme;
          return Scaffold(
            body: Center(
              child: Padding(
                padding: const EdgeInsets.all(32),
                child: Column(mainAxisSize: MainAxisSize.min, children: [
                  const VulcanLogo(size: 72),
                  const SizedBox(height: 20),
                  Text('Cybervulcan is locked', style: t.headlineSmall),
                  const SizedBox(height: 8),
                  Text('The house stays protected and alerts keep coming while it is locked.',
                      textAlign: TextAlign.center, style: t.bodyMedium?.copyWith(color: OpnColors.textSoft)),
                  const SizedBox(height: 24),
                  FilledButton.icon(
                    onPressed: _prompting ? null : _unlock,
                    icon: Icon(Platform.isWindows ? Icons.lock_open : Icons.fingerprint),
                    label: const Text('Unlock'),
                  ),
                ]),
              ),
            ),
          );
        },
      );
}
