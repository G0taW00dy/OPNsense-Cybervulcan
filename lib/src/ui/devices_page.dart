import 'package:flutter/material.dart';

import '../api/models.dart';
import '../api/opnsense_client.dart';
import '../core/controller.dart';
import '../core/network_map.dart';
import 'format.dart';
import 'theme.dart';

/// Who's online: Dnsmasq DHCP leases grouped by house network.
class DevicesPage extends StatefulWidget {
  const DevicesPage({super.key, required this.controller});

  final CybervulcanController controller;

  @override
  State<DevicesPage> createState() => _DevicesPageState();
}

class _DevicesPageState extends State<DevicesPage> {
  late Future<List<DhcpLease>> _future;

  @override
  void initState() {
    super.initState();
    _future = widget.controller.leases();
  }

  Future<void> _reload() async {
    setState(() => _future = widget.controller.leases());
    try {
      await _future;
    } on Exception {
      // shown by the FutureBuilder
    }
  }

  @override
  Widget build(BuildContext context) {
    final cfg = widget.controller.config;
    return FutureBuilder<List<DhcpLease>>(
      future: _future,
      builder: (context, snap) {
        if (snap.connectionState != ConnectionState.done) {
          return const Center(child: CircularProgressIndicator());
        }
        if (snap.hasError) {
          final e = snap.error;
          return Center(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(mainAxisSize: MainAxisSize.min, children: [
                const Icon(Icons.devices_other, size: 48),
                const SizedBox(height: 12),
                Text(
                  e is OpnsenseException && e.kind == ApiErrorKind.forbidden
                      ? 'The API user needs "Services: Dnsmasq DNS/DHCP: Settings" to list devices.'
                      : e is OpnsenseException
                          ? errorHint(e)
                          : '$e',
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 12),
                FilledButton.tonal(onPressed: _reload, child: const Text('Retry')),
              ]),
            ),
          );
        }
        final leases = snap.data ?? const [];
        final groups = <String, List<DhcpLease>>{};
        for (final l in leases) {
          final net = networkNameFor(l.address, cfg.networks) ?? l.interfaceDescription ?? 'Other';
          groups.putIfAbsent(net, () => []).add(l);
        }
        final order = [
          for (final n in cfg.networks)
            if (groups.containsKey(n.name)) n.name,
          ...groups.keys.where((k) => !cfg.networks.any((n) => n.name == k)),
        ];
        return RefreshIndicator(
          onRefresh: _reload,
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              Text('${leases.length} devices with a DHCP lease',
                  style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 4),
              Text('Devices with static IPs and no lease are not listed.',
                  style: Theme.of(context).textTheme.bodySmall),
              if (leases.isEmpty)
                Padding(
                  padding: const EdgeInsets.only(top: 48),
                  child: Column(children: [
                    const Icon(Icons.devices_other, size: 48, color: OpnColors.muted),
                    const SizedBox(height: 12),
                    Text('Nothing connected yet', style: Theme.of(context).textTheme.titleMedium),
                    const SizedBox(height: 4),
                    Text('Devices appear here once the router gives them an address.',
                        textAlign: TextAlign.center,
                        style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: OpnColors.textSoft)),
                  ]),
                ),
              for (final net in order) ...[
                const SizedBox(height: 16),
                _NetworkHeader(
                  name: net,
                  cidr: cfg.networks.where((n) => n.name == net).map((n) => n.cidr).firstOrNull,
                  count: groups[net]!.length,
                ),
                Card(
                  child: Column(children: [
                    for (final l in groups[net]!)
                      ListTile(
                        dense: true,
                        leading: Icon(l.isStatic ? Icons.push_pin_outlined : Icons.devices),
                        title: Text(l.hostname ?? '(no hostname)'),
                        subtitle: Text([l.address, l.mac, if (l.vendor != null) l.vendor!].join('  -  ')),
                        trailing: l.expire != null
                            ? Text('until ${formatClock(l.expire!)}',
                                style: Theme.of(context).textTheme.bodySmall)
                            : null,
                      ),
                  ]),
                ),
              ],
            ],
          ),
        );
      },
    );
  }
}

class _NetworkHeader extends StatelessWidget {
  const _NetworkHeader({required this.name, this.cidr, required this.count});
  final String name;
  final String? cidr;
  final int count;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(left: 4, bottom: 8),
        child: Text('$name${cidr != null ? '  ($cidr)' : ''}  -  $count',
            style: Theme.of(context).textTheme.titleSmall),
      );
}
