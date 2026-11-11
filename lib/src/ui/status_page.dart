import 'dart:async';

import 'package:flutter/material.dart';

import '../api/models.dart';
import '../core/controller.dart';
import '../core/house_state.dart';
import 'bypass_dialog.dart';
import 'format.dart';
import 'theme.dart';
import 'widgets/opn_logo.dart';

class StatusPage extends StatefulWidget {
  const StatusPage({super.key, required this.controller});

  final CybervulcanController controller;

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

  @override
  Widget build(BuildContext context) {
    final color = OpnColors.forHealth(snapshot.health);
    final t = Theme.of(context).textTheme;
    return Card(
      child: Container(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(18),
          gradient: LinearGradient(
            colors: [color.withValues(alpha: 0.22), color.withValues(alpha: 0.04)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
        ),
        padding: const EdgeInsets.all(20),
        child: Row(
          children: [
            OpnLogo(size: 56, accent: color, showN: false),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    (snapshot.bypassActive ?? false)
                        ? 'Exit: direct (bypass)'
                        : 'Exit: ${exitLabel(snapshot.exit, controller.config)}',
                    style: t.titleLarge?.copyWith(fontWeight: FontWeight.w700),
                  ),
                  const SizedBox(height: 4),
                  Text(headline(snapshot, controller.config), style: t.bodyMedium),
                  if (snapshot.failoverActive && !(snapshot.bypassActive ?? false))
                    Padding(
                      padding: const EdgeInsets.only(top: 8),
                      child: Chip(
                        avatar: const Icon(Icons.swap_horiz, size: 18),
                        label: const Text('Failover active'),
                        backgroundColor: OpnColors.amber.withValues(alpha: 0.2),
                      ),
                    ),
                ],
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
          ],
        ),
      ),
    );
  }
}

class _Banner extends StatelessWidget {
  const _Banner({required this.text, required this.color, required this.icon});

  final String text;
  final Color color;
  final IconData icon;

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
    final remaining = s.bypassExpiresAt?.difference(DateTime.now().toUtc());
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
                remaining != null
                    ? 'ON - VPN resumes in ${formatDuration(remaining)} (at ${formatClock(s.bypassExpiresAt!)})'
                    : 'ON',
                style: t.titleSmall?.copyWith(color: OpnColors.purple, fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 4),
              const Text('Everyone on the VPN network is going direct right now.'),
            ] else
              const Text('Off. Turning it on sends EVERY device on the VPN network straight to '
                  'the internet (DNS via the router\'s Quad9 DoT) for a limited time.'),
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
