/// Shaper (lag control) in Settings, v2.1.13.
///
/// Two paths, matching the router rules by exit path:
/// * Tunnel - traffic through the VPN tunnels (VPN pipes).
/// * Direct line - traffic straight out of WAN: the CLEAR network, devices
///   switched to CLEAR, whole-house bypass (CLEAR pipes).
///
/// Each path can be switched on/off and its limits typed in. "Recommend"
/// turns a speed test (measured here with the shaper off, or typed from
/// speedtest.net) into limits that keep the ping flat under load.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../api/shaper_models.dart';
import '../core/controller.dart';
import '../core/quick_tests.dart';
import 'settings_page.dart' show InfoLine;
import 'theme.dart';

class ShaperPanel extends StatefulWidget {
  const ShaperPanel({super.key, required this.controller});
  final CybervulcanController controller;

  @override
  State<ShaperPanel> createState() => _ShaperPanelState();
}

class _ShaperPanelState extends State<ShaperPanel> {
  CybervulcanController get c => widget.controller;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    unawaited(_refresh());
  }

  Future<void> _refresh() async {
    await c.refreshShaperInfo();
    await c.checkShaperLayout();
    if (mounted) setState(() {});
  }

  Future<void> _run(Future<void> Function() f) async {
    setState(() => _busy = true);
    try {
      await f();
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// The path this device is on now (null = unknown).
  bool? get _onTunnel {
    final path = expectedPathFor(
      deviceIp: c.snapshot.pcIp,
      cfg: c.config,
      bypassActive: c.snapshot.bypassActive,
      pcClear: c.supportsPcMode ? c.snapshot.pcClear : null,
    );
    return switch (path) {
      ExpectedPath.vpn => true,
      ExpectedPath.direct => false,
      ExpectedPath.unknown => null,
    };
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return ListenableBuilder(
      listenable: c,
      builder: (context, _) => Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(children: [
          Expanded(child: Text('Limits on the router now', style: t.labelLarge)),
          IconButton(
              tooltip: 'Read again',
              onPressed: _busy ? null : () => _run(_refresh),
              icon: const Icon(Icons.refresh, size: 20)),
        ]),
        if (c.allShaperPipes == null)
          InfoLine(c.tuner.lastReason ?? 'Reading the router\'s shaper limits ...')
        else ...[
          _pathRow(context, tunnel: true),
          _pathRow(context, tunnel: false),
        ],
        if (c.shaperLayout == ShaperLayout.other || c.shaperLayout == ShaperLayout.none) ...[
          const SizedBox(height: 6),
          InfoLine(c.shaperLayout == ShaperLayout.none
              ? 'No shaper rules use these limits yet.'
              : 'The router\'s shaper rules sort traffic by network, not by exit path: a device switched to CLEAR '
                  'is then held to the tunnel limit. Set them up by exit path (tunnel interfaces and WAN).'),
          Align(
            alignment: Alignment.centerLeft,
            child: OutlinedButton.icon(
                onPressed: _busy ? null : () => _run(() async => c.setupExitPathShaper()),
                icon: const Icon(Icons.alt_route),
                label: const Text('Set up rules by exit path')),
          ),
        ],
        if (c.shaperLayoutNote != null) InfoLine(c.shaperLayoutNote!),
        const SizedBox(height: 4),
        Text(
            'Tunnel = everything through the VPN. Direct line = the CLEAR network, devices switched to CLEAR and '
            'whole-house bypass. Set each limit just under that path\'s real speed: the router then keeps the queue '
            'at home, so games and calls stay smooth while someone downloads.',
            style: t.bodySmall),
      ]),
    );
  }

  Widget _pathRow(BuildContext context, {required bool tunnel}) {
    final t = Theme.of(context).textTheme;
    final p = c.shaperPath(tunnel: tunnel);
    final title = tunnel ? 'Tunnel (VPN)' : 'Direct line (CLEAR, bypass)';
    if (p == null) {
      return ListTile(
        contentPadding: EdgeInsets.zero,
        title: Text(title),
        subtitle: Text('No ${tunnel ? 'VPN' : 'CLEAR'} download/upload pipes on the router (Firewall > Shaper > Pipes).'),
      );
    }
    final on = p.down.enabled && p.up.enabled;
    final d = p.down.mbit.round(), u = p.up.mbit.round();
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(children: [
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(title, style: t.titleSmall),
            Text(
                on
                    ? 'Limit $d / $u Mbit/s - about ${expectedRealMbps(tunnel: tunnel, limit: d)} / '
                        '${expectedRealMbps(tunnel: tunnel, limit: u)} real'
                    : 'Off - no lag control on this path ($d / $u Mbit/s kept for when it\'s on)',
                style: t.bodySmall?.copyWith(color: on ? null : OpnColors.amber)),
          ]),
        ),
        TextButton(onPressed: _busy ? null : () => _edit(tunnel: tunnel), child: const Text('Change')),
        Switch(
            value: on,
            onChanged: _busy ? null : (v) => _run(() async => c.setShaperPath(tunnel: tunnel, enabled: v))),
      ]),
    );
  }

  Future<void> _edit({required bool tunnel}) async {
    final p = c.shaperPath(tunnel: tunnel);
    if (p == null) return;
    final r = await showDialog<({int down, int up})>(
      context: context,
      builder: (_) => _ShaperEditDialog(
        controller: c,
        tunnel: tunnel,
        down: p.down.mbit.round(),
        up: p.up.mbit.round(),
        onThisPath: _onTunnel == null ? null : _onTunnel == tunnel,
      ),
    );
    if (r == null) return;
    await _run(() async => c.setShaperPath(tunnel: tunnel, down: r.down, up: r.up));
  }
}

class _ShaperEditDialog extends StatefulWidget {
  const _ShaperEditDialog({
    required this.controller,
    required this.tunnel,
    required this.down,
    required this.up,
    required this.onThisPath,
  });
  final CybervulcanController controller;
  final bool tunnel;
  final int down, up;

  /// Is this device on that path now? null = unknown.
  final bool? onThisPath;

  @override
  State<_ShaperEditDialog> createState() => _ShaperEditDialogState();
}

class _ShaperEditDialogState extends State<_ShaperEditDialog> {
  late final _down = TextEditingController(text: '${widget.down}');
  late final _up = TextEditingController(text: '${widget.up}');
  final _mDown = TextEditingController();
  final _mUp = TextEditingController();
  bool _measuring = false;
  String? _note;

  @override
  void dispose() {
    for (final x in [_down, _up, _mDown, _mUp]) {
      x.dispose();
    }
    super.dispose();
  }

  int? _n(TextEditingController x) {
    final v = double.tryParse(x.text.trim().replaceAll(',', '.'));
    return v == null || v < 1 || v > 100000 ? null : v.round();
  }

  void _recommend() {
    final d = double.tryParse(_mDown.text.trim().replaceAll(',', '.'));
    final u = double.tryParse(_mUp.text.trim().replaceAll(',', '.'));
    if (d == null || u == null || d <= 0 || u <= 0) {
      setState(() => _note = 'Type the measured download and upload first (or press Measure).');
      return;
    }
    final r = recommendedLimits(tunnel: widget.tunnel, downMbps: d, upMbps: u);
    setState(() {
      _down.text = '${r.down}';
      _up.text = '${r.up}';
      _note = 'Recommended ${r.down} / ${r.up} - you can still change them before saving.';
    });
  }

  Future<void> _measure() async {
    setState(() {
      _measuring = true;
      _note = 'Measuring with the shaper off for this path (about 25 seconds) ...';
    });
    final web = http.Client();
    try {
      final r = await widget.controller.measureShaperPath(tunnel: widget.tunnel, web: web);
      if (!mounted) return;
      if (r == null) {
        setState(() => _note = widget.controller.lastActionError ?? 'Speed test failed.');
        return;
      }
      _mDown.text = r.down.toStringAsFixed(0);
      _mUp.text = r.up.toStringAsFixed(1);
      _recommend();
    } finally {
      web.close();
      if (mounted) setState(() => _measuring = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final word = widget.tunnel ? 'tunnel' : 'direct line';
    final d = _n(_down), u = _n(_up);
    return AlertDialog(
      title: Text(widget.tunnel ? 'Tunnel (VPN) limits' : 'Direct line limits'),
      content: SizedBox(
        width: 460,
        child: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(
                  child: TextField(
                      controller: _down,
                      keyboardType: const TextInputType.numberWithOptions(decimal: true),
                      onChanged: (_) => setState(() {}),
                      decoration: const InputDecoration(labelText: 'Download limit', suffixText: 'Mbit/s'))),
              const SizedBox(width: 12),
              Expanded(
                  child: TextField(
                      controller: _up,
                      keyboardType: const TextInputType.numberWithOptions(decimal: true),
                      onChanged: (_) => setState(() {}),
                      decoration: const InputDecoration(labelText: 'Upload limit', suffixText: 'Mbit/s'))),
            ]),
            if (d != null && u != null)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text(
                    'About ${expectedRealMbps(tunnel: widget.tunnel, limit: d)} / '
                    '${expectedRealMbps(tunnel: widget.tunnel, limit: u)} Mbit/s real speed through these limits.',
                    style: t.bodySmall),
              ),
            const SizedBox(height: 18),
            Text('Recommend from a speed test', style: t.titleSmall),
            const SizedBox(height: 4),
            Text(
                'Speed of the $word with the shaper OFF: press Measure (this device must be on the $word), or '
                'type what speedtest.net showed${widget.tunnel ? ' through the VPN' : ' on CLEAR / bypass'}.',
                style: t.bodySmall),
            Row(children: [
              Expanded(
                  child: TextField(
                      controller: _mDown,
                      keyboardType: const TextInputType.numberWithOptions(decimal: true),
                      decoration: const InputDecoration(labelText: 'Measured download', suffixText: 'Mbit/s'))),
              const SizedBox(width: 12),
              Expanded(
                  child: TextField(
                      controller: _mUp,
                      keyboardType: const TextInputType.numberWithOptions(decimal: true),
                      decoration: const InputDecoration(labelText: 'Measured upload', suffixText: 'Mbit/s'))),
            ]),
            const SizedBox(height: 8),
            Wrap(spacing: 8, runSpacing: 8, children: [
              OutlinedButton.icon(
                  onPressed: _measuring || widget.onThisPath == false ? null : _measure,
                  icon: _measuring
                      ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                      : const Icon(Icons.speed),
                  label: const Text('Measure')),
              OutlinedButton.icon(
                  onPressed: _measuring ? null : _recommend,
                  icon: const Icon(Icons.auto_fix_high),
                  label: const Text('Use recommended')),
            ]),
            if (widget.onThisPath == false)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text(
                    'This device is not on the $word now, so it can\'t measure it - '
                    '${widget.tunnel ? 'switch it back to the VPN' : 'switch it to CLEAR'} first, or type the figures.',
                    style: t.bodySmall?.copyWith(color: OpnColors.amber)),
              ),
            if (_note != null)
              Padding(padding: const EdgeInsets.only(top: 8), child: Text(_note!, style: t.bodySmall)),
          ]),
        ),
      ),
      actions: [
        TextButton(onPressed: _measuring ? null : () => Navigator.pop(context), child: const Text('Cancel')),
        FilledButton(
            onPressed: _measuring || d == null || u == null ? null : () => Navigator.pop(context, (down: d, up: u)),
            child: const Text('Save to router')),
      ],
    );
  }
}
