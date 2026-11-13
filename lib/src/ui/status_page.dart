import 'dart:async';

import 'package:flutter/material.dart';

import '../api/models.dart';
import '../core/bypass.dart';
import '../core/controller.dart';
import '../core/house_state.dart';
import '../core/updater.dart';
import '../net/router_link.dart';
import 'bypass_dialog.dart';
import 'format.dart';
import 'theme.dart';
import 'update_widgets.dart';
import 'widgets/volcano_art.dart';

class StatusPage extends StatefulWidget {
  const StatusPage({super.key, required this.controller, this.updates});

  final CybervulcanController controller;
  final UpdateService? updates;

  @override
  State<StatusPage> createState() => _StatusPageState();
}

class _StatusPageState extends State<StatusPage> {
  Timer? _tick;

  @override
  void initState() {
    super.initState();
    // Drives the bypass countdown between polls.
    _tick = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted && (widget.controller.snapshot.bypassActive ?? false)) setState(() {});
    });
  }

  @override
  void dispose() {
    _tick?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = widget.controller;
    return ListenableBuilder(
      listenable: c,
      builder: (context, _) {
        final s = c.snapshot;
        return RefreshIndicator(
          onRefresh: c.refresh,
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              _HeaderCard(snapshot: s, controller: c),
              if (widget.updates != null) UpdateBanner(updates: widget.updates!),
              if (c.config.isPlainHttp) ...[
                const SizedBox(height: 12),
                const _Banner(
                  text: 'The router address is plain http:// - the API key and everything else '
                      'travel unencrypted and nothing proves this is your router. Switch to '
                      'https:// in Settings once the router has its certificate.',
                  color: OpnColors.amber,
                  icon: Icons.lock_open,
                ),
              ],
              if (s.link != null && !s.link!.connected && s.link!.state != LinkState.notConfigured) ...[
                const SizedBox(height: 12),
                _Banner(
                  text: s.link!.describe(c.config),
                  color: s.link!.state == LinkState.wrongCertificate ? OpnColors.red : OpnColors.grey,
                  icon: s.link!.state == LinkState.wrongCertificate ? Icons.gpp_bad : Icons.wifi_off,
                ),
              ],
              if (s.reachable && (s.bypassActive ?? false) && s.bypassNoRouterDeadline) ...[
                const SizedBox(height: 12),
                _Banner(
                  text: 'The router has no deadline for this bypass, so the router can\'t end it by '
                      'itself - only a running Cybervulcan app can. Add the deadline so it ends on time '
                      'even with every app closed.',
                  color: OpnColors.amber,
                  icon: Icons.timer_off_outlined,
                  action: TextButton(
                    onPressed: s.busy ? null : c.addRouterDeadline,
                    child: const Text('Add deadline'),
                  ),
                ),
              ],
              if (c.lastActionError != null) ...[
                const SizedBox(height: 12),
                _Banner(text: c.lastActionError!, color: OpnColors.red, icon: Icons.error_outline),
              ] else if (c.lastActionInfo != null) ...[
                const SizedBox(height: 12),
                _Banner(text: c.lastActionInfo!, color: OpnColors.green, icon: Icons.check_circle_outline),
              ],
              if (s.configured && s.reachable) ...[
                const SizedBox(height: 16),
                _BypassCard(controller: c),
                if (c.supportsPcMode) ...[
                  const SizedBox(height: 16),
                  _PcModeCard(controller: c),
                ],
                const SizedBox(height: 16),
                LayoutBuilder(builder: (context, box) {
                  final wide = box.maxWidth > 640;
                  final cards = [
                    _TunnelCard(
                      title: '${c.config.mainLabel} - main',
                      subtitle: c.config.mainGateway,
                      gw: s.main,
                      active: s.exit == ProtonExit.main,
                    ),
                    _TunnelCard(
                      title: '${c.config.backupLabel} - backup',
                      subtitle: c.config.backupGateway,
                      gw: s.backup,
                      active: s.exit == ProtonExit.backup,
                    ),
                  ];
                  return wide
                      ? Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Expanded(child: cards[0]),
                            const SizedBox(width: 16),
                            Expanded(child: cards[1]),
                          ],
                        )
                      : Column(children: [cards[0], const SizedBox(height: 16), cards[1]]);
                }),
                const SizedBox(height: 16),
                _KillSwitchCard(snapshot: s),
              ],
              const SizedBox(height: 12),
              Center(
                child: Text(
                  'Updated ${formatClock(s.fetchedAt)} - every ${c.config.pollInterval.inSeconds}s',
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _HeaderCard extends StatelessWidget {
  const _HeaderCard({required this.snapshot, required this.controller});

  final HouseSnapshot snapshot;
  final CybervulcanController controller;

  /// Short uppercase status line above the big exit name.
  static String _label(HouseSnapshot s) {
    if (!s.configured) return 'Not set up';
    if (s.link?.state == LinkState.notHome) return 'Not home';
    if (s.link?.state == LinkState.wrongCertificate) return 'Wrong certificate';
    if (!s.reachable) return 'Router unreachable';
    if (s.bypassActive ?? false) return 'VPN bypass on';
    if (s.killSwitch.tripped) return 'Kill switch tripped';
    if (s.killSwitchArmed == false) return 'Kill switch not armed';
    if (s.busy) return 'Changing...';
    if (s.failoverActive) return 'Failover active';
    return switch (s.health) {
      Health.ok => 'Protected',
      Health.warning => 'Slow tunnel',
      _ => 'Problem',
    };
  }

  /// The big line: where the house's traffic leaves right now.
  static String _exitName(HouseSnapshot s, CybervulcanController c) {
    if (s.link?.state == LinkState.wrongCertificate) return 'Not your router?';
    if (!s.reachable) return 'No connection';
    if (s.bypassActive ?? false) return c.config.directLabel;
    return switch (s.exit) {
      ProtonExit.main => c.config.mainLabel,
      ProtonExit.backup => c.config.backupLabel,
      ProtonExit.none => 'No exit',
      ProtonExit.unknown => 'Unknown',
    };
  }

  @override
  Widget build(BuildContext context) {
    final color = OpnColors.forHealth(snapshot.health);
    final t = Theme.of(context).textTheme;
    final info = Padding(
      padding: const EdgeInsets.fromLTRB(24, 24, 24, 20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Row(children: [
            Container(
              width: 12,
              height: 12,
              decoration: BoxDecoration(
                color: color,
                shape: BoxShape.circle,
                boxShadow: [BoxShadow(color: color, blurRadius: 12)],
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                _label(snapshot).toUpperCase(),
                style: t.labelLarge?.copyWith(color: color, letterSpacing: 1.2, fontWeight: FontWeight.w700),
              ),
            ),
            if (snapshot.busy)
              const SizedBox(width: 24, height: 24, child: CircularProgressIndicator(strokeWidth: 2.5))
            else
              IconButton(
                tooltip: 'Refresh',
                onPressed: controller.refresh,
                icon: const Icon(Icons.refresh),
              ),
          ]),
          const SizedBox(height: 4),
          Text(
            _exitName(snapshot, controller),
            style: t.displaySmall?.copyWith(fontWeight: FontWeight.w700, color: OpnColors.text, height: 1.05),
          ),
          const SizedBox(height: 8),
          Text(headline(snapshot, controller.config),
              style: t.bodyLarge?.copyWith(color: OpnColors.textSoft)),
          if (snapshot.failoverActive && !(snapshot.bypassActive ?? false))
            const Padding(
              padding: EdgeInsets.only(top: 12),
              child: Chip(
                avatar: Icon(Icons.swap_horiz, size: 18, color: OpnColors.amber),
                label: Text('Failover active'),
              ),
            ),
          if (snapshot.reachable && (snapshot.link?.viaTunnel ?? false))
            const Padding(
              padding: EdgeInsets.only(top: 12),
              child: Chip(
                avatar: Icon(Icons.vpn_key, size: 18, color: OpnColors.glassCyan),
                label: Text('Remote access (WireGuard)'),
              ),
            ),
        ],
      ),
    );
    return Card(
      clipBehavior: Clip.antiAlias,
      child: DecoratedBox(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Color(0xFF121A30), Color(0xFF0D1222)],
          ),
        ),
        child: LayoutBuilder(builder: (context, box) {
          final wide = box.maxWidth >= 640;
          if (wide) {
            return SizedBox(
              height: 260,
              child: Row(children: [
                Expanded(flex: 5, child: Align(alignment: Alignment.centerLeft, child: info)),
                Expanded(flex: 6, child: VolcanoArt(accent: color)),
              ]),
            );
          }
          // Narrow (phone): art fills the card, text on top.
          return Stack(children: [
            Positioned.fill(child: VolcanoArt(accent: color)),
            Padding(padding: const EdgeInsets.only(bottom: 120), child: info),
          ]);
        }),
      ),
    );
  }
}

class _Banner extends StatelessWidget {
  const _Banner({required this.text, required this.color, required this.icon, this.action});

  final String text;
  final Color color;
  final IconData icon;
  final Widget? action;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withValues(alpha: 0.5)),
        ),
        child: Row(children: [
          Icon(icon, color: color),
          const SizedBox(width: 10),
          Expanded(child: Text(text)),
          if (action != null) ...[const SizedBox(width: 8), action!],
        ]),
      );
}

class _TunnelCard extends StatelessWidget {
  const _TunnelCard({required this.title, required this.subtitle, required this.gw, required this.active});

  final String title;
  final String subtitle;
  final GatewayStatus? gw;
  final bool active;

  @override
  Widget build(BuildContext context) {
    final g = gw;
    final t = Theme.of(context).textTheme;
    final Color color;
    if (g == null) {
      color = OpnColors.grey;
    } else if (!g.health.isUp) {
      color = OpnColors.red;
    } else if (g.health.isDegraded) {
      color = OpnColors.amber;
    } else {
      color = OpnColors.green;
    }
    String metric(double? v, String unit) => v == null ? '-' : '${v.toStringAsFixed(1)} $unit';
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              Icon(Icons.circle, size: 12, color: color),
              const SizedBox(width: 8),
              Expanded(child: Text(title, style: t.titleMedium)),
              if (active)
                const Chip(label: Text('IN USE'), visualDensity: VisualDensity.compact),
            ]),
            Text(subtitle, style: t.bodySmall),
            const SizedBox(height: 12),
            if (g == null)
              const Text('Gateway not found on router - check the name in Settings.')
            else ...[
              Text(g.statusText ?? g.health.name, style: t.bodyLarge?.copyWith(color: color)),
              const SizedBox(height: 8),
              Wrap(spacing: 24, runSpacing: 8, children: [
                _Metric(label: 'Ping', value: metric(g.delayMs, 'ms')),
                _Metric(label: 'Loss', value: metric(g.lossPercent, '%')),
                _Metric(label: 'Jitter', value: metric(g.stddevMs, 'ms')),
                _Metric(label: 'Monitor', value: g.monitor ?? '-'),
              ]),
            ],
          ],
        ),
      ),
    );
  }
}

class _Metric extends StatelessWidget {
  const _Metric({required this.label, required this.value});
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(label, style: t.labelSmall),
      Text(value, style: t.titleSmall?.copyWith(fontFeatures: const [FontFeature.tabularFigures()])),
    ]);
  }
}

class _BypassCard extends StatelessWidget {
  const _BypassCard({required this.controller});
  final CybervulcanController controller;

  @override
  Widget build(BuildContext context) {
    final s = controller.snapshot;
    final active = s.bypassActive;
    final t = Theme.of(context).textTheme;
    final noLimit = isNoLimitExpiry(s.bypassExpiresAt);
    final remaining = noLimit ? null : s.bypassExpiresAt?.difference(DateTime.now().toUtc());
    return Card(
      color: (active ?? false) ? OpnColors.purple.withValues(alpha: 0.16) : null,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              const Icon(Icons.public_off, color: OpnColors.purple),
              const SizedBox(width: 8),
              Expanded(child: Text('Whole-house VPN bypass', style: t.titleMedium)),
              Switch(
                value: active ?? false,
                activeThumbColor: OpnColors.purple,
                onChanged: active == null || s.busy
                    ? null
                    : (on) => on
                        ? confirmAndStartBypass(context, controller)
                        : controller.setBypass(false),
              ),
            ]),
            if (active == null)
              const Text('Status unknown - the API user needs "Diagnostics: PF Table IP addresses".')
            else if (active) ...[
              Text(
                noLimit
                    ? 'ON - no time limit. Turn it off here when you\'re done.'
                    : remaining != null
                    ? 'ON - VPN resumes in ${formatDuration(remaining)} (at ${formatClock(s.bypassExpiresAt!)})'
                    : 'ON',
                style: t.titleSmall?.copyWith(color: OpnColors.purple, fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 4),
              const Text('Everyone on the VPN network is going direct right now.'),
            ] else
              const Text('Off. Turning it on sends EVERY device on the VPN network straight to '
                  'the internet (DNS via the router\'s own resolver) for a limited time.'),
          ],
        ),
      ),
    );
  }
}

class _PcModeCard extends StatelessWidget {
  const _PcModeCard({required this.controller});
  final CybervulcanController controller;

  @override
  Widget build(BuildContext context) {
    final s = controller.snapshot;
    final t = Theme.of(context).textTheme;
    final clear = s.pcClear;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              const Icon(Icons.computer),
              const SizedBox(width: 8),
              Expanded(child: Text('This PC', style: t.titleMedium)),
              SegmentedButton<bool>(
                segments: const [
                  ButtonSegment(value: false, label: Text('VPN'), icon: Icon(Icons.vpn_lock)),
                  ButtonSegment(value: true, label: Text('CLEAR'), icon: Icon(Icons.sports_esports)),
                ],
                selected: {clear ?? false},
                onSelectionChanged: clear == null || s.busy
                    ? null
                    : (v) => controller.setPcClear(v.first),
              ),
            ]),
            const SizedBox(height: 6),
            Text(s.pcIp == null
                ? 'Could not detect this PC\'s house IP - set it in Settings.'
                : clear == null
                    ? 'IP ${s.pcIp}: mode unknown (alias not readable).'
                    : 'IP ${s.pcIp} is ${clear ? 'CLEAR - direct internet, only this PC' : 'on the VPN'}.'),
          ],
        ),
      ),
    );
  }
}

class _KillSwitchCard extends StatelessWidget {
  const _KillSwitchCard({required this.snapshot});
  final HouseSnapshot snapshot;

  @override
  Widget build(BuildContext context) {
    final k = snapshot.killSwitch;
    final t = Theme.of(context).textTheme;
    final (label, color, icon) = k.tripped
        ? ('TRIPPED - VPN network has no internet', OpnColors.red, Icons.gpp_bad)
        : switch (k.armed) {
            true => ('Armed', OpnColors.green, Icons.verified_user),
            false => ('NOT ARMED', OpnColors.red, Icons.gpp_maybe),
            null => ('Armed state unknown', OpnColors.grey, Icons.shield_outlined),
          };
    return Card(
      child: ListTile(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        leading: Icon(icon, color: color, size: 32),
        title: Text('Kill switch: $label', style: t.titleMedium),
        subtitle: Text(k.detail ?? ''),
      ),
    );
  }
}
