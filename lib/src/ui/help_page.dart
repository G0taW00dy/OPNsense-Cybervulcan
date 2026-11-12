import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';

import '../core/updater.dart';
import 'theme.dart';

/// Opens the setup guide.
Future<void> openSetupGuide(BuildContext context) =>
    Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const HelpPage()));

/// A rough, router-agnostic setup guide: what has to exist on OPNsense for
/// each feature, and how to connect the app. Written so someone else with a
/// similar setup can follow it; the defaults are this project's names.
class HelpPage extends StatelessWidget {
  const HelpPage({super.key});

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Setup guide')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
        children: [
          Text(
            'Cybervulcan talks to an OPNsense router over its API. It never changes the saved '
            'router configuration: it only reads status and adds or removes addresses in two '
            'runtime alias tables. Set the router up once (sections 1-4), then connect the app '
            '(section 5). Names in brackets are the defaults; use your own and change them in '
            'Settings.',
            style: t.bodyMedium?.copyWith(color: OpnColors.textSoft),
          ),
          const SizedBox(height: 16),
          const _Section(
            number: 1,
            title: 'What you need',
            initiallyExpanded: true,
            items: [
              'OPNsense 25.x or 26.x.',
              'Two WireGuard VPN tunnels set up as gateways, one main and one backup '
                  '(WG_MAIN_GW / WG_BACKUP_GW), in a failover gateway group. Any provider works.',
              'A separate network (VLAN) for devices that should use the VPN (10.10.40.0/24). '
                  'Its pass rule sends traffic out through the VPN gateway group.',
              'Optional: a "clear" network that goes straight out (for gaming), and an IoT network.',
            ],
          ),
          const _Section(
            number: 2,
            title: 'Aliases for bypass and PC mode',
            items: [
              'Firewall > Aliases: add two aliases of type "External (advanced)", leave them empty: '
                  'BYPASS_ALL and PCMODE_CLEAR. The app fills them at runtime; a router reboot '
                  'empties them, so everything falls back to the VPN.',
              'Firewall > Rules > [VPN network]: above the normal VPN pass rule, add pass rules '
                  'with source BYPASS_ALL and source PCMODE_CLEAR, gateway = your WAN (direct) '
                  'gateway.',
              'Optional but recommended: a port-forward (NAT) rule so DNS from those sources goes '
                  'to the router\'s own resolver instead of the VPN\'s DNS.',
            ],
          ),
          const _Section(
            number: 3,
            title: 'Kill switch',
            items: [
              'On the VPN network\'s pass rule(s), under Advanced, set the local tag NO_WAN_EGRESS.',
              'Add a block rule on WAN (direction out, or a floating rule) that matches the tag '
                  'NO_WAN_EGRESS. If both tunnels drop, VPN traffic is blocked instead of leaking '
                  'out the normal internet line.',
              'Leave "Skip rules when gateway is down" and default gateway switching OFF.',
              'The app shows the kill switch as Armed when it finds an enabled block rule with '
                  'that tag.',
            ],
          ),
          const _Section(
            number: 4,
            title: 'API user and key',
            items: [
              'System > Access > Users: add a user just for the app (pcmode). No GUI login needed.',
              'Required privileges: "Diagnostics: PF Table IP addresses" (bypass + PC mode) and '
                  '"System: Gateways" (live status and failover).',
              'Recommended: "Diagnostics: Show States" (moves open connections on every switch).',
              'Optional: "Services: Dnsmasq DNS/DHCP: Settings" (Devices page) and '
                  '"Firewall: Rules [new]" (kill switch armed check). Without them those parts '
                  'show "unknown"; nothing else breaks.',
              'Edit the user > API keys > "+". Your browser downloads apikey.txt with a key= and a '
                  'secret= line. Keep it private and delete it once the app is connected.',
            ],
          ),
          const _Section(
            number: 5,
            title: 'Connect the app',
            items: [
              'Settings > Router base URL: https://<router address> (http:// only on a test VM).',
              'Self-signed HTTPS certificate: press "Trust certificate..." and check the fingerprint '
                  'against System > Trust > Certificates before accepting.',
              'Paste the API key and secret. They are stored in Windows Credential Manager / the '
                  'Android Keystore and only ever sent to the router.',
              'Set the gateway names, labels, alias names, VPN network and kill switch tag to match '
                  'your router, then Save.',
              'Press "Test connection & privileges": every line should say OK.',
            ],
          ),
          const _Section(
            number: 6,
            title: 'Using it',
            items: [
              'Tray icon colours: green = main tunnel up, amber = failover or a change in progress, '
                  'red = problem (router unreachable, kill switch tripped or not armed), '
                  'purple = whole-house bypass on, grey = not set up.',
              'This PC (Windows): VPN or CLEAR for this PC only. CLEAR resets to VPN if the router '
                  'restarts.',
              'Whole-house bypass: takes everyone on the VPN network off the VPN, for a set time or '
                  'until you turn it off (reminder every 4 hours).',
              'The bypass ends on time while any copy of the app is running. To make the router end '
                  'it by itself (PC off, phone away), install the router timer (section 7).',
              'Tests: checks where this device\'s traffic and DNS actually exit.',
            ],
          ),
          _Section(
            number: 7,
            title: 'Router timer (recommended)',
            items: const [
              'Ends an expired whole-house bypass on the router itself, even when no copy of the app '
                  'is running. "No time limit" bypasses are left alone. It only touches the bypass '
                  'table, never the saved router configuration.',
              'Open a root shell on the router: console menu option 8 "Shell", or SSH '
                  '(System > Settings > Administration > Secure Shell; turn it off again afterwards).',
              'Paste the install line below. It should finish with "installed (self-check OK)".',
              'In the router web page: System > Settings > Cron > "+". Set Minutes, Hours, Day of the '
                  'month, Months and Days of the week all to *, Command "Cybervulcan - end expired '
                  'whole-house VPN bypass", Parameters = your bypass alias (BYPASS_ALL). Save, then Apply.',
              'Check: System > Log Files > General, search "cybervulcan". A line appears each time it '
                  'ends a bypass. The router\'s clock must be right (System > Settings > General / NTP).',
              'New router or restored backup: run the install line again and re-add the cron job. '
                  'To remove it, run the same line with "| sh -s uninstall" at the end.',
            ],
            extra: const _CommandBox(
              'fetch -qo - https://raw.githubusercontent.com/$updateRepo/main/router/install.sh | sh',
            ),
          ),
          const _Section(
            number: 8,
            title: 'Troubleshooting',
            items: [
              '"API key/secret rejected": re-enter the key and secret, or make a new key.',
              '"Missing a privilege": add the privilege named in the message to the API user.',
              '"Certificate not trusted": the router certificate changed; trust it again.',
              '"Gateways not found": the gateway names in Settings must match System > Gateways '
                  'exactly.',
              'Router unreachable: check the base URL and that this device can reach the router '
                  'GUI address.',
            ],
          ),
          const SizedBox(height: 16),
          Align(
            alignment: Alignment.centerLeft,
            child: OutlinedButton.icon(
              onPressed: () => launchUrl(Uri.parse('https://github.com/$updateRepo#readme'),
                  mode: LaunchMode.externalApplication),
              icon: const Icon(Icons.open_in_new),
              label: const Text('Full documentation on GitHub'),
            ),
          ),
        ],
      ),
    );
  }
}

class _Section extends StatelessWidget {
  const _Section({
    required this.number,
    required this.title,
    required this.items,
    this.initiallyExpanded = false,
    this.extra,
  });

  /// Optional widget shown after the bullet points (e.g. a command to copy).
  final Widget? extra;

  final int number;
  final String title;
  final List<String> items;
  final bool initiallyExpanded;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Card(
        clipBehavior: Clip.antiAlias,
        child: ExpansionTile(
          initiallyExpanded: initiallyExpanded,
          shape: const Border(),
          collapsedShape: const Border(),
          leading: CircleAvatar(
            radius: 14,
            backgroundColor: OpnColors.ember.withValues(alpha: 0.2),
            child: Text('$number',
                style: t.labelLarge?.copyWith(color: OpnColors.ember, fontWeight: FontWeight.w700)),
          ),
          title: Text(title, style: t.titleMedium?.copyWith(fontWeight: FontWeight.w600)),
          childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
          expandedCrossAxisAlignment: CrossAxisAlignment.start,
          children: [
            for (final s in items)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  const Padding(
                    padding: EdgeInsets.only(top: 7, right: 10),
                    child: Icon(Icons.circle, size: 6, color: OpnColors.glassCyan),
                  ),
                  Expanded(child: Text(s, style: t.bodyMedium)),
                ]),
              ),
            if (extra != null) ...[const SizedBox(height: 12), extra!],
          ],
        ),
      ),
    );
  }
}

/// A shell command shown in monospace with a Copy button.
class _CommandBox extends StatelessWidget {
  const _CommandBox(this.command);

  final String command;

  @override
  Widget build(BuildContext context) => Container(
        width: double.infinity,
        padding: const EdgeInsets.fromLTRB(12, 8, 4, 8),
        decoration: BoxDecoration(
          color: OpnColors.ink,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: OpnColors.border),
        ),
        child: Row(children: [
          Expanded(
            child: SelectableText(command,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 13, color: OpnColors.text)),
          ),
          IconButton(
            tooltip: 'Copy',
            icon: const Icon(Icons.copy, size: 18),
            onPressed: () async {
              await Clipboard.setData(ClipboardData(text: command));
              if (context.mounted) {
                ScaffoldMessenger.of(context)
                    .showSnackBar(const SnackBar(content: Text('Install line copied')));
              }
            },
          ),
        ]),
      );
}
