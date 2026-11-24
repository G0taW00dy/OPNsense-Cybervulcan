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

/// Navigator of the lock screen: the unlock PIN dialog must show there,
/// because the app's own pages are hidden while locked.
final lockNavigatorKey = GlobalKey<NavigatorState>();

/// Context for dialogs the app lock shows (PIN entry).
BuildContext? lockDialogContext(CybervulcanController c) =>
    (c.locked ? lockNavigatorKey.currentContext : null) ?? navigatorKey.currentContext;

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
        // The lock sits above the Navigator, so it also covers pushed pages
        // and dialogs, and they survive being locked (v2.1 fix: the old lock
        // replaced the whole page tree while a file picker was open).
        builder: (context, child) => LockGate(controller: controller, child: child ?? const SizedBox.shrink()),
        home: HomeShell(controller: controller, updates: updates),
        // v2.2.8: a route name the app doesn't know (e.g. a widget link) is
        // ignored instead of failing with "Null check".
        onUnknownRoute: ignoreUnknownRoute,
      );
}

/// A route for unknown route names that shows nothing and removes itself.
Route<void> ignoreUnknownRoute(RouteSettings settings) => PageRouteBuilder<void>(
      settings: settings,
      opaque: false,
      pageBuilder: (context, _, _) {
        WidgetsBinding.instance.addPostFrameCallback((_) {
          final nav = Navigator.maybeOf(context);
          if (nav != null && nav.canPop()) nav.pop();
        });
        return const SizedBox.shrink();
      },
    );

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

  /// Android Back while locked must not pop the hidden pages.
  @override
  Future<bool> didPopRoute() async => c.locked;

  Future<void> _unlock() async {
    if (_prompting) return;
    setState(() => _prompting = true);
    await c.unlock();
    if (mounted) setState(() => _prompting = false);
  }

  /// Phone: ask straight away when the lock appears - but only once the app
  /// is really in front again. Asking for a fingerprint while Android is
  /// still handing back from another app (file picker, browser) can crash.
  void _autoPrompt() {
    Future<void>.delayed(const Duration(milliseconds: 600), () {
      if (!mounted || !c.locked || _prompting) return;
      if (WidgetsBinding.instance.lifecycleState != AppLifecycleState.resumed) {
        _autoTried = false; // try again on the next resume
        return;
      }
      _unlock();
    });
  }

  Widget _lockScreen(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Material(
      color: Theme.of(context).scaffoldBackgroundColor,
      child: SafeArea(
        child: Center(
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
      ),
    );
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
        listenable: c,
        builder: (context, _) {
          final locked = c.locked;
          // PC: wait for a click (the tray app may start hidden at sign-in).
          if (locked && Platform.isAndroid && !_autoTried && !_prompting) {
            _autoTried = true;
            WidgetsBinding.instance.addPostFrameCallback((_) => _autoPrompt());
          }
          return Stack(children: [
            // Kept mounted (pages, dialogs and their state survive), but not
            // painted, focusable or readable while locked.
            // ExcludeFocus: no Enter/Space on a focused button behind the lock
            // (Back is swallowed in didPopRoute).
            Offstage(
              offstage: locked,
              child: ExcludeFocus(excluding: locked, child: TickerMode(enabled: !locked, child: widget.child)),
            ),
            if (locked)
              Positioned.fill(
                // Its own Navigator must not share MaterialApp's HeroController:
                // a second navigator on the same controller breaks every later
                // page/dialog push ("Null check" in HeroController.didChangeTop,
                // seen in 2.1.0 diagnostics).
                child: HeroControllerScope.none(
                  child: Navigator(
                  key: lockNavigatorKey,
                  onGenerateRoute: (_) => PageRouteBuilder<void>(
                    pageBuilder: (context, _, _) => ListenableBuilder(
                      listenable: c,
                      builder: (context, _) => _lockScreen(context),
                    ),
                  ),
                ),
                ),
              ),
          ]);
        },
      );
}
