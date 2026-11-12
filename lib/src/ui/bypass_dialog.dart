import 'package:flutter/material.dart';

import '../core/bypass.dart';
import '../core/controller.dart';
import 'format.dart';
import 'theme.dart';

/// The "this affects everyone" confirmation. Returns true if bypass was
/// requested. Used by the status page, tray menu, widget and QS tile.
Future<bool> confirmAndStartBypass(BuildContext context, CybervulcanController c) async {
  if (c.snapshot.bypassActive ?? false) return false;
  var duration = isNoLimitDuration(c.config.bypassDuration) ? bypassNoLimit : c.config.bypassDuration;
  final options = <Duration>{
    const Duration(minutes: 30),
    const Duration(hours: 1),
    const Duration(hours: 2),
    const Duration(hours: 4),
    bypassNoLimit,
    if (!isNoLimitDuration(c.config.bypassDuration)) c.config.bypassDuration,
  }.toList()
    ..sort();

  final ok = await showDialog<bool>(
    context: context,
    builder: (ctx) => StatefulBuilder(
      builder: (ctx, setState) => AlertDialog(
        icon: const Icon(Icons.warning_amber_rounded, color: OpnColors.purple, size: 40),
        title: const Text('Turn off the VPN for the whole house?'),
        content: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 460),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'EVERY device on the VPN network (${c.config.bypassNetwork}) - phones, TVs, '
                'laptops, everyone in the house - will go straight to the internet without '
                'Proton until the bypass ends.',
              ),
              const SizedBox(height: 8),
              const Text('DNS is redirected to the router\'s Quad9 DNS-over-TLS resolver while '
                  'bypass is on. The kill switch does not protect bypassed traffic.'),
              const SizedBox(height: 16),
              const Text('Turn the VPN back on:'),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                children: [
                  for (final d in options)
                    ChoiceChip(
                      label: Text(bypassDurationLabel(d)),
                      selected: d == duration,
                      onSelected: (_) => setState(() => duration = d),
                    ),
                ],
              ),
              if (isNoLimitDuration(duration))
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Text(
                    'No time limit: the VPN stays off for everyone until someone turns the bypass '
                    'off. You\'ll get a reminder every 4 hours.',
                    style: TextStyle(color: OpnColors.amber.withValues(alpha: 0.95)),
                  ),
                ),
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: OpnColors.purple),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Bypass VPN for everyone'),
          ),
        ],
      ),
    ),
  );
  if (ok != true) return false;
  await c.setBypass(true, duration: duration);
  return true;
}
