import 'dart:async';

import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../core/config.dart';
import '../core/controller.dart';
import '../net/tailscale_engine.dart';
import 'remote_access.dart' show copyText;
import 'settings_page.dart' show HelpButton, InfoLine, WarningLine;
import 'theme.dart';

/// One-line summary of the remote access choice for the Settings section header.
String remoteAccessSummary(AppConfig cfg, {bool? tailscaleHere, String deviceNoun = 'device'}) {
  final app = 'Tailscale app${tailscaleHere == true ? ' - active on this $deviceNoun' : ''}';
  // v2.0 Tailscale switch (device app), see remoteSteps().
  if (cfg.tailscaleEnabled && cfg.transport == 'wireguard') return app;
  if (!cfg.remoteEnabled) return 'Off - home only';
  final tsName = cfg.tailscaleBuiltIn ? 'Tailscale (built-in)' : app;
  return switch (cfg.transport) {
    'tailscale' => tsName,
    'auto' => 'Auto - WireGuard, then $tsName',
    _ => 'WireGuard (needs a public IP at home)',
  };
}

/// v2.1 Remote access controls: on/off, engine (WireGuard / Tailscale /
/// Auto), built-in Tailscale toggle, its status and sign-in / sign-out.
/// Changes go to [onChanged] (saved with the Settings page's Save).
class RemoteEngineSettings extends StatefulWidget {
  const RemoteEngineSettings({
    super.key,
    required this.controller,
    required this.config,
    required this.onChanged,
  });

  final CybervulcanController controller;
  final AppConfig config;
  final ValueChanged<AppConfig> onChanged;

  @override
  State<RemoteEngineSettings> createState() => _RemoteEngineSettingsState();
}

class _RemoteEngineSettingsState extends State<RemoteEngineSettings> {
  Timer? _poll;
  late TailscaleStatus _ts;
  bool _busy = false;

  CybervulcanController get c => widget.controller;
  AppConfig get cfg => widget.config;

  @override
  void initState() {
    super.initState();
    _ts = c.tailscaleStatus;
    _poll = Timer.periodic(const Duration(seconds: 2), (_) {
      if (mounted) setState(() => _ts = c.tailscaleStatus);
    });
  }

  @override
  void dispose() {
    _poll?.cancel();
    super.dispose();
  }

  // Every change here also clears the v2.0 Tailscale switch (tailscaleEnabled),
  // so the new choice is the only one in effect.
  void _change(AppConfig next) => widget.onChanged(next.copyWith(tailscaleEnabled: false));

  void _snack(String text) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));
  }

  Future<void> _signIn() async {
    setState(() => _busy = true);
    final url = await c.logInTailscale(cfg);
    if (!mounted) return;
    setState(() {
      _busy = false;
      _ts = c.tailscaleStatus;
    });
    if (url == null) {
      _snack(c.lastActionError ??
          (_ts.state == TailscaleState.needsApproval
              ? 'Signed in - now approve this device in the Tailscale admin console.'
              : 'Tailscale is signed in.'));
      return;
    }
    var opened = false;
    try {
      opened = await launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication);
    } on Object {
      opened = false;
    }
    if (!opened && mounted) {
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Sign in to Tailscale'),
          content: SelectableText('Open this link in a browser to sign in:\n\n$url'),
          actions: [
            TextButton(onPressed: () => copyText(ctx, url, 'Link copied'), child: const Text('Copy link')),
            FilledButton(onPressed: () => Navigator.pop(ctx), child: const Text('Close')),
          ],
        ),
      );
    }
  }

  Future<void> _signOut() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Sign out of Tailscale?'),
        content: const Text('The app forgets its Tailscale login on this device. To use Tailscale again you '
            'sign in again (and may have to approve the device again).'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Sign out')),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    setState(() => _busy = true);
    await c.logOutTailscale();
    if (!mounted) return;
    setState(() {
      _busy = false;
      _ts = c.tailscaleStatus;
    });
    _snack(c.lastActionError ?? c.lastActionInfo ?? 'Signed out of Tailscale.');
  }

  Widget _switch(String title, String help, bool value, ValueChanged<bool> onChanged, {String? subtitle}) =>
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        title: Row(children: [
          Flexible(child: Text(title)),
          HelpButton(title: title, text: help, small: true),
        ]),
        subtitle: subtitle == null ? null : Text(subtitle),
        value: value,
        onChanged: onChanged,
      );

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final transport = cfg.transport;
    final usesTailscale = cfg.remoteEnabled && transport != 'wireguard';
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      _switch(
        'Remote access',
        'Lets the app reach your router when you are away from home (mobile data, other Wi-Fi). Only the app '
            'uses it - nothing else on this device is routed home, and your VPN app can stay on.\n\n'
            'Off: the app only works at home.',
        cfg.remoteEnabled,
        (v) => _change(cfg.copyWith(remoteEnabled: v)),
        subtitle: 'Use the app away from home',
      ),
      if (cfg.remoteEnabled) ...[
        Row(children: [
          Text('Engine', style: t.titleSmall),
          const HelpButton(
            title: 'Engine',
            small: true,
            text: 'WireGuard: the app connects straight to the router\'s WireGuard port. Needs a public IP at '
                'home (does not work behind CGNAT, e.g. most 5G home internet).\n\n'
                'Tailscale: works behind CGNAT with no open ports - Tailscale\'s relays carry the traffic '
                'when a direct path is not possible. Needs Tailscale on the router (os-tailscale plugin).\n\n'
                'Auto: tries WireGuard first; if it cannot connect within a few seconds, uses Tailscale.',
          ),
        ]),
        const SizedBox(height: 4),
        SegmentedButton<String>(
          segments: const [
            ButtonSegment(value: 'wireguard', label: Text('WireGuard')),
            ButtonSegment(value: 'tailscale', label: Text('Tailscale')),
            ButtonSegment(value: 'auto', label: Text('Auto')),
          ],
          selected: {transport},
          onSelectionChanged: (v) => _change(cfg.copyWith(remoteTransport: v.first)),
        ),
        const SizedBox(height: 8),
        // REMOTE-MODE-UI: the "what remote access carries" choice (remoteMode:
        // app / home / everything) belongs here. Built by the VPN agents - not
        // part of the Tailscale engine work.
        if (usesTailscale) ...[
          _switch(
            'Built-in Tailscale',
            'On: Tailscale runs inside this app - no separate Tailscale app, no VPN slot used, no admin '
                'rights. Sign in once below; the app remembers the login.\n\n'
                'Off: the app uses the Tailscale app on this device instead (that one takes the device\'s VPN '
                'slot on Android).',
            cfg.tailscaleBuiltIn,
            (v) => _change(cfg.copyWith(tailscaleBuiltIn: v)),
            subtitle: cfg.tailscaleBuiltIn ? 'No separate Tailscale app needed' : 'Uses the Tailscale app on this device',
          ),
          if (cfg.tailscaleBuiltIn) _tailscaleBlock(t),
        ],
      ],
    ]);
  }

  static String _day(DateTime d) => d.toLocal().toString().substring(0, 10);

  Widget _tailscaleBlock(TextTheme t) {
    if (!c.tailscaleAvailable) {
      return WarningLine(c.tailscaleUnavailableReason ?? 'Built-in Tailscale is not available on this device.');
    }
    final exp = _ts.keyExpiry;
    final soon = exp != null && exp.difference(DateTime.now().toUtc()) < const Duration(days: 14);
    final canSignIn = const {TailscaleState.stopped, TailscaleState.needsLogin, TailscaleState.error}.contains(_ts.state);
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Expanded(
          child: InfoLine(_ts.state == TailscaleState.stopped
              ? 'Tailscale: idle (starts when you are away, or when you sign in)'
              : 'Tailscale: ${_ts.describe()}'),
        ),
        const HelpButton(
          title: 'Tailscale status',
          small: true,
          text: 'Signing in: tap "Sign in to Tailscale", log in in the browser with the account your router '
              'uses. If your tailnet requires device approval, approve the new device in the Tailscale admin '
              'console (Machines).\n\n'
              'The router must advertise a route to its own LAN IP (/32) and that route must be approved in the '
              'admin console - or enter the router\'s Tailscale address above.\n\n'
              'Key expiry: Tailscale device keys expire (default 180 days). Sign in again before then, or turn '
              'off key expiry for this device in the admin console.\n\n'
              'Sign out: forgets the login on this device. Remove the device in the admin console too if you '
              'no longer use it.',
        ),
      ]),
      if (exp != null && soon)
        WarningLine('This device\'s Tailscale key expires on ${_day(exp)}. Sign in again soon, or turn off key '
            'expiry for it in the admin console.')
      else if (exp != null)
        InfoLine('This device\'s Tailscale key expires on ${_day(exp)}.'),
      Wrap(spacing: 8, runSpacing: 4, children: [
        if (canSignIn)
          FilledButton.icon(
            onPressed: _busy ? null : _signIn,
            icon: _busy
                ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.login, size: 18),
            label: const Text('Sign in to Tailscale'),
          ),
        TextButton.icon(
          onPressed: _busy ? null : _signOut,
          icon: const Icon(Icons.logout, size: 18, color: OpnColors.muted),
          label: const Text('Sign out'),
        ),
      ]),
    ]);
  }
}
