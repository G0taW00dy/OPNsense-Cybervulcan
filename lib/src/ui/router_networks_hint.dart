import 'package:flutter/material.dart';

import '../core/controller.dart';
import '../core/network_map.dart';
import 'settings_page.dart' show InfoLine, networksFromText;

/// v2.1.22: under Settings > Network layout - lists networks the router has
/// that are not in the "House networks" box (23 Nov: CAMS was missing) and
/// adds them with one tap.
class RouterNetworksHint extends StatefulWidget {
  const RouterNetworksHint({super.key, required this.controller, required this.text, required this.onAdded});

  final CybervulcanController controller;
  final TextEditingController text;
  final VoidCallback onAdded;

  @override
  State<RouterNetworksHint> createState() => _RouterNetworksHintState();
}

class _RouterNetworksHintState extends State<RouterNetworksHint> {
  List<NamedNetwork> _router = const [];

  @override
  void initState() {
    super.initState();
    widget.controller.routerNetworks().then((n) {
      if (mounted) setState(() => _router = n);
    });
    widget.text.addListener(_changed);
  }

  @override
  void dispose() {
    widget.text.removeListener(_changed);
    super.dispose();
  }

  void _changed() {
    if (mounted) setState(() {});
  }

  void _add(List<NamedNetwork> missing) {
    final t = widget.text.text.trimRight();
    final lines = [for (final n in missing) '${n.name} ${n.cidr}'];
    widget.text.text = [if (t.isNotEmpty) t, ...lines].join('\n');
    widget.onAdded();
  }

  @override
  Widget build(BuildContext context) {
    final listed = networksFromText(widget.text.text);
    if (listed == null || _router.isEmpty) return const SizedBox.shrink();
    final missing = missingNetworks(_router, listed);
    if (missing.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        InfoLine('The router also has: ${missing.map((n) => '${n.name} ${n.cidr}').join(', ')}'),
        TextButton.icon(
          icon: const Icon(Icons.add),
          label: Text(missing.length == 1 ? 'Add it' : 'Add them'),
          onPressed: () => _add(missing),
        ),
      ]),
    );
  }
}
