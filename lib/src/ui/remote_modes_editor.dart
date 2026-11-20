import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

import '../core/config.dart';
import '../core/controller.dart';
import '../core/remote_modes.dart';
import '../platform/vpn_modes.dart';
import 'settings_page.dart' show HelpButton, InfoLine, WarningLine;

const _modesHelp = 'App only (default): only Cybervulcan talks to the router. Nothing else on this device changes '
    'and your VPN app can stay on.\n\n'
    'Home devices only: away from home, the addresses you list (for example the NAS: Synology Drive, Photos, '
    'file sharing) are reachable as if you were at home. Everything else goes the normal way.\n\n'
    'Everything via home: away from home, all traffic of this device goes to the house and leaves through the '
    'house\'s VPN tunnels (and its kill switch), DNS included. IPv6 is blocked so it can\'t leak around the house.\n\n'
    'Both VPN modes switch on by themselves when you are away and remote access is connected, and off again when '
    'you are home. They use the device\'s one VPN slot.';

const _devicesHelp = 'IPv4 addresses or subnets at home that this device should reach while away, separated by '
    'commas - for example 10.10.10.5 for the NAS, or 10.10.10.0/24 for the whole management network. The router '
    'itself is always included.\n\n'
    'The router has to let this device\'s tunnel address reach them (firewall rule on the WireGuard interface).\n\n'
    'Avoid subnets that are also common on other Wi-Fi networks (192.168.0.0/24, 192.168.1.0/24): '
    'while connected, those addresses would go home instead of to the local network.';

String _slotWarning(String vpnName) => Platform.isAndroid
    ? 'Uses the phone\'s VPN slot: Android runs one VPN app at a time, so ${vpnName.isEmpty ? 'your VPN app' : 'the $vpnName app'} '
        'must be off while this is connected (it turns off by itself when this starts). To keep apps from '
        'going around the VPN, use Android Settings > Network > VPN > Cybervulcan > "Always-on VPN" and '
        '"Block connections without VPN".'
    : Platform.isWindows
        // v2.1 Windows home link (vpn_modes_windows.dart).
        ? 'Each time this switches on, Windows asks for admin rights (UAC prompt) to add the "Cybervulcan" '
            'network adapter; it is removed again when this switches off or the app closes. A separate VPN app '
            'should be off while this is connected. The router\'s own pages stay reachable only through this app.'
        : 'Uses this computer\'s VPN slot: a separate VPN app should be off while this is connected.';

/// "What it carries" for remote access: App only / Home devices only /
/// Everything via home, plus the home-device list. Platform neutral: the
/// platform part is [SystemVpn] (controller.homeLink.vpn).
class RemoteModesEditor extends StatefulWidget {
  const RemoteModesEditor({super.key, required this.controller, required this.config, required this.onChanged});

  final CybervulcanController controller;
  final AppConfig config;
  final ValueChanged<AppConfig> onChanged;

  @override
  State<RemoteModesEditor> createState() => _RemoteModesEditorState();
}

class _RemoteModesEditorState extends State<RemoteModesEditor> {
  late final TextEditingController _devices = TextEditingController(text: widget.config.homeDevices);
  bool? _permission; // null = not asked in this screen

  HomeLink get _link => widget.controller.homeLink;

  @override
  void dispose() {
    _devices.dispose();
    super.dispose();
  }

  Future<void> _pick(String mode) async {
    widget.onChanged(widget.config.copyWith(remoteMode: mode));
    if (mode != 'app' && _link.vpn.isSupported) {
      // Ask for the VPN permission now, while the person is here.
      final ok = await _link.vpn.prepare();
      if (mounted) setState(() => _permission = ok);
    }
  }

  @override
  Widget build(BuildContext context) {
    final cfg = widget.config;
    final mode = cfg.mode;
    final t = Theme.of(context).textTheme;
    final status = _link.describe();
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      const SizedBox(height: 8),
      Row(children: [
        Text('What it carries', style: t.titleSmall),
        const HelpButton(title: 'What remote access carries', text: _modesHelp, small: true),
      ]),
      const SizedBox(height: 4),
      SegmentedButton<String>(
        segments: [
          for (final e in remoteModeLabels.entries) ButtonSegment(value: e.key, label: Text(e.value)),
        ],
        selected: {mode},
        onSelectionChanged: (v) => unawaited(_pick(v.first)),
      ),
      const SizedBox(height: 12),
      if (mode == 'home')
        Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: TextFormField(
            controller: _devices,
            decoration: const InputDecoration(
              labelText: 'Home devices',
              hintText: '10.10.10.5, 10.10.10.0/24',
              suffixIcon: HelpButton(title: 'Home devices', text: _devicesHelp),
            ),
            autovalidateMode: AutovalidateMode.onUserInteraction,
            validator: (v) => homeDevicesError(v ?? '', required: true),
            onChanged: (v) => widget.onChanged(widget.config.copyWith(homeDevices: v.trim())),
          ),
        ),
      if (mode != 'app') ...[
        if (!_link.vpn.isSupported)
          WarningLine(_link.vpn.unsupportedReason ?? 'Not available on this device.')
        else ...[
          WarningLine(_slotWarning(cfg.vpnName.trim())),
          if (_permission == false)
            const WarningLine('VPN permission was not given - tap the mode again to allow it.'),
        ],
        if (mode == 'everything')
          const InfoLine('The router must allow this device\'s tunnel address out to the internet through the '
              'house VPN gateway (and its kill switch) - see the guide.'),
        for (final p in remoteModeProblems(cfg)) WarningLine(p),
        if (status != null)
          Row(children: [
            Expanded(child: InfoLine(status)),
            if (_link.state == HomeLinkState.error)
              TextButton(
                onPressed: () async {
                  await _link.retry(widget.controller.config, widget.controller.snapshot.link);
                  if (mounted) setState(() {});
                },
                child: const Text('Try again'),
              ),
          ]),
      ],
    ]);
  }
}
