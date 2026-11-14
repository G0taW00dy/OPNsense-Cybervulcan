import 'dart:io';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../core/controller.dart';
import '../core/network_map.dart';
import '../core/pc_mode.dart';
import '../core/quick_tests.dart';
import 'theme.dart';

class TestsPage extends StatefulWidget {
  const TestsPage({super.key, required this.controller});
  final CybervulcanController controller;

  @override
  State<TestsPage> createState() => _TestsPageState();
}

class _TestsPageState extends State<TestsPage> {
  final _http = http.Client();
  bool _running = false;
  ExitCheckResult? _exit;
  DnsResolverInfo? _dns;
  String? _exitError;
  String? _dnsError;
  String? _deviceIp;

  @override
  void dispose() {
    _http.close();
    super.dispose();
  }

  Future<void> _run() async {
    setState(() {
      _running = true;
      _exit = null;
      _dns = null;
      _exitError = null;
      _dnsError = null;
    });
    final c = widget.controller;
    final tests = QuickTests(_http);
    _deviceIp = c.snapshot.pcIp ?? await detectPcIp(c.config);
    final expected = expectedPathFor(
      deviceIp: _deviceIp,
      cfg: c.config,
      bypassActive: c.snapshot.bypassActive,
      pcClear: c.supportsPcMode ? c.snapshot.pcClear : null,
    );
    try {
      final info = await tests.exitInfo();
      _exit = evaluateExit(info, expected, c.config);
    } on Exception catch (e) {
      _exitError = '$e';
    }
    try {
      _dns = await tests.dnsResolver();
    } on Exception catch (e) {
      _dnsError = '$e';
    }
    if (mounted) setState(() => _running = false);
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final cfg = widget.controller.config;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Row(children: [
          Expanded(child: Text('Quick tests', style: t.titleLarge)),
          FilledButton.icon(
            onPressed: _running ? null : _run,
            icon: _running
                ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.play_arrow),
            label: const Text('Run'),
          ),
        ]),
        const SizedBox(height: 8),
        Text(
          'Checks where this device\'s traffic actually leaves the house and which DNS '
          'resolver answers for it, then compares that with what the router says should happen.',
          style: t.bodySmall,
        ),
        const SizedBox(height: 16),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('Exit IP', style: t.titleMedium),
              const SizedBox(height: 8),
              if (_exit != null) ...[
                _verdict(_exit!.verdict),
                const SizedBox(height: 8),
                SelectableText('${_exit!.info.ip}\n'
                    '${[_exit!.info.city, _exit!.info.country].whereType<String>().join(', ')}'
                    '${_exit!.info.org != null ? '\n${_exit!.info.org}' : ''}'),
                const SizedBox(height: 8),
                Text(_exit!.explanation),
                Text(
                  'Device ${_deviceIp ?? 'IP unknown'}'
                  '${_deviceIp != null ? ' on ${networkNameFor(_deviceIp!, cfg.networks) ?? 'a non-house network'}' : ''}'
                  ' - expected: ${_exit!.expected.name.toUpperCase()}',
                  style: t.bodySmall,
                ),
              ] else if (_exitError != null)
                Text('Failed: $_exitError')
              else
                const Text('Not run yet.'),
            ]),
          ),
        ),
        const SizedBox(height: 16),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('DNS resolver', style: t.titleMedium),
              const SizedBox(height: 8),
              if (_dns != null) ...[
                SelectableText('${_dns!.resolverIp}${_dns!.geo != null ? '\n${_dns!.geo}' : ''}'),
                const SizedBox(height: 8),
                Text(
                  'On the VPN this should be a ${cfg.vpnName}/${cfg.vpnCountryCode} resolver; during '
                  'bypass, the router\'s own DNS forwarder (e.g. Quad9). An ISP resolver in ${cfg.homeCountryCode} '
                  'while on the VPN suggests a DNS leak.',
                  style: t.bodySmall,
                ),
              ] else if (_dnsError != null)
                Text('Failed: $_dnsError')
              else
                const Text('Not run yet.'),
            ]),
          ),
        ),
        const SizedBox(height: 16),
        Text('Limitations', style: t.titleSmall),
        Text(
          '- Uses third-party services: api.ipify.org, ipwho.is (fallback ipapi.co) and '
          'edns.ip-api.com (plain HTTP).\n'
          '- The DNS test sees one resolver from one lookup; it is not a full multi-query leak test.\n'
          '- Country matching is a heuristic: a ${cfg.vpnName} server in your home country would look "direct".\n'
          '- ${Platform.isAndroid ? 'On mobile data the phone is not on a house network, so results are inconclusive.' : 'Results reflect this PC only.'}',
          style: t.bodySmall,
        ),
      ],
    );
  }

  Widget _verdict(Verdict v) {
    final (label, color, icon) = switch (v) {
      Verdict.ok => ('As expected', OpnColors.green, Icons.check_circle),
      Verdict.mismatch => ('MISMATCH', OpnColors.red, Icons.warning),
      Verdict.inconclusive => ('Inconclusive', OpnColors.amber, Icons.help_outline),
    };
    return Row(children: [
      Icon(icon, color: color),
      const SizedBox(width: 8),
      Text(label, style: TextStyle(color: color, fontWeight: FontWeight.w700)),
    ]);
  }
}
