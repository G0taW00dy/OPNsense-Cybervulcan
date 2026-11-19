import 'dart:async';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../api/opnsense_client.dart';
import '../core/controller.dart';
import '../core/server_switcher.dart';
import 'remote_access.dart';
import 'theme.dart';

/// Status-page card: where each tunnel points, plus "Find best".
class ServersCard extends StatefulWidget {
  const ServersCard({super.key, required this.controller});
  final CybervulcanController controller;

  @override
  State<ServersCard> createState() => _ServersCardState();
}

class _ServersCardState extends State<ServersCard> {
  (WgPeerInfo, WgPeerInfo)? _peers;
  String? _error;

  CybervulcanController get c => widget.controller;

  @override
  void initState() {
    super.initState();
    unawaited(_load());
  }

  Future<void> _load() async {
    try {
      final p = await c.tunnelPeers();
      if (mounted) {
        setState(() {
          _peers = p;
          _error = null;
        });
      }
    } on OpnsenseException catch (e) {
      if (mounted) {
        setState(() => _error = e.kind == ApiErrorKind.forbidden
            ? 'Needs the "VPN: WireGuard" privilege on your app user (router: System > Access > Users).'
            : e.message);
      }
    } on Object catch (e) {
      if (mounted) setState(() => _error = '$e');
    }
  }

  String _describe(WgPeerInfo p) {
    final s = p.match(c.cachedServers());
    return s != null ? s.label : p.address;
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final cfg = c.config;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            const Icon(Icons.dns_outlined, color: OpnColors.glassCyan),
            const SizedBox(width: 8),
            Expanded(child: Text('VPN servers', style: t.titleMedium)),
            IconButton(tooltip: 'Reload', onPressed: _load, icon: const Icon(Icons.refresh, size: 20)),
          ]),
          const SizedBox(height: 6),
          if (_error != null)
            Text(_error!, style: t.bodySmall?.copyWith(color: OpnColors.amber))
          else if (_peers == null)
            const LinearProgressIndicator()
          else ...[
            _row(context, '${cfg.mainLabel} (main)', _describe(_peers!.$1)),
            _row(context, '${cfg.backupLabel} (backup)', _describe(_peers!.$2)),
          ],
          const SizedBox(height: 12),
          Wrap(spacing: 8, runSpacing: 8, children: [
            FilledButton.tonalIcon(
              onPressed: c.serverBusy || _error != null
                  ? null
                  : () async {
                      await Navigator.of(context).push(MaterialPageRoute<void>(
                          builder: (_) => ServersPage(controller: c, autoStartBest: true)));
                      await _load();
                    },
              icon: const Icon(Icons.speed),
              label: const Text('Find best'),
            ),
            OutlinedButton.icon(
              onPressed: c.serverBusy || _error != null
                  ? null
                  : () async {
                      await Navigator.of(context)
                          .push(MaterialPageRoute<void>(builder: (_) => ServersPage(controller: c)));
                      await _load();
                    },
              icon: const Icon(Icons.swap_horiz),
              label: const Text('Change server'),
            ),
          ]),
        ]),
      ),
    );
  }

  Widget _row(BuildContext context, String label, String value) => Padding(
        padding: const EdgeInsets.only(bottom: 4),
        child: Row(children: [
          SizedBox(width: 150, child: Text(label, style: Theme.of(context).textTheme.bodySmall)),
          Expanded(child: Text(value, style: const TextStyle(fontWeight: FontWeight.w600))),
        ]),
      );
}

/// Server list, manual switch, and the "find best" run with live progress.
class ServersPage extends StatefulWidget {
  const ServersPage({super.key, required this.controller, this.autoStartBest = false});
  final CybervulcanController controller;
  final bool autoStartBest;

  @override
  State<ServersPage> createState() => _ServersPageState();
}

class _ServersPageState extends State<ServersPage> {
  final _http = http.Client();
  List<ProtonServer> _servers = [];
  bool _onlyMyCities = true;
  bool _loading = false;
  String? _message;
  final List<String> _log = [];
  bool _running = false;
  int _candidates = 3;
  BestServerPlan? _plan;

  CybervulcanController get c => widget.controller;

  @override
  void initState() {
    super.initState();
    _servers = c.cachedServers();
    if (widget.autoStartBest) {
      WidgetsBinding.instance.addPostFrameCallback((_) => unawaited(_findBest()));
    }
  }

  @override
  void dispose() {
    _http.close();
    super.dispose();
  }

  List<ProtonServer> get _visible {
    final cities = c.config.serverCityList.map((x) => x.toLowerCase()).toSet();
    final list = _onlyMyCities && cities.isNotEmpty
        ? _servers.where((s) => cities.contains((s.city ?? '').toLowerCase())).toList()
        : [..._servers];
    list.sort((a, b) => (a.load ?? 100).compareTo(b.load ?? 100));
    return list;
  }

  Future<void> _download() async {
    setState(() {
      _loading = true;
      _message = null;
    });
    try {
      final list = await fetchProtonServers(_http, country: c.config.vpnCountryCode);
      // Keep manually added servers that Proton's list doesn't have.
      final manual = _servers.where((m) => !list.any((s) => s.entryIp == m.entryIp));
      _servers = [...list, ...manual];
      await c.saveServers(_servers);
      _message = 'Downloaded ${list.length} ${c.config.vpnCountryCode} servers from Proton.';
    } on Object catch (e) {
      _message = '$e';
    }
    if (mounted) setState(() => _loading = false);
  }

  Future<void> _addFromConf() async {
    final text = await pasteOrOpenText(context,
        title: 'Add server from a Proton .conf',
        hint: 'Paste a Proton WireGuard config (or open the file). Only the server address and its PUBLIC key '
            'are used - the private key in the file is ignored and never stored.');
    if (text == null || !mounted) return;
    final s = serverFromWireGuardConf(text);
    if (s == null) {
      setState(() => _message = 'No [Peer] with a PublicKey and Endpoint found in that text.');
      return;
    }
    final city = await _askCity(s);
    final server = ProtonServer(
        name: s.name, entryIp: s.entryIp, publicKey: s.publicKey, port: s.port, city: city, country: c.config.vpnCountryCode);
    _servers = [..._servers.where((x) => x.entryIp != server.entryIp), server];
    await c.saveServers(_servers);
    if (mounted) setState(() => _message = 'Added ${server.name}. (The private key in the file was ignored.)');
  }

  Future<String?> _askCity(ProtonServer s) async {
    final ctl = TextEditingController(text: c.config.serverCityList.firstOrNull ?? '');
    final r = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('City of ${s.name}'),
        content: TextField(controller: ctl, decoration: const InputDecoration(labelText: 'City, e.g. Chicago')),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Skip')),
          FilledButton(onPressed: () => Navigator.pop(ctx, ctl.text.trim()), child: const Text('OK')),
        ],
      ),
    );
    ctl.dispose();
    return (r ?? '').isEmpty ? null : r;
  }

  Future<void> _use(ProtonServer s, {required bool main}) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Use ${s.name} for the ${main ? 'main' : 'backup'} tunnel?'),
        content: Text(main
            ? 'The main tunnel restarts on the new server. For a few seconds the house fails over to '
                '${c.config.backupLabel}; the kill switch keeps everything protected.'
            : 'The backup tunnel restarts on the new server. The house keeps using the main tunnel.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Switch')),
        ],
      ),
    );
    if (ok != true) return;
    setState(() => _loading = true);
    final done = await c.moveTunnel(main: main, server: s);
    if (!mounted) return;
    setState(() {
      _loading = false;
      _message = done
          ? '${main ? c.config.mainLabel : c.config.backupLabel} tunnel now uses ${s.name}. '
              'Give it a minute for the latency figures to settle.'
          : (c.lastActionError ?? 'Not changed.');
    });
  }

  Future<void> _findBest() async {
    if (_running) return;
    var pool = _servers;
    if (pool.isEmpty) {
      await _download();
      pool = _servers;
    }
    final candidates = pickCandidates(pool, c.config.serverCityList, max: _candidates);
    if (candidates.isEmpty) {
      setState(() => _message = 'No servers to test - download the list or add some from .conf files.');
      return;
    }
    setState(() {
      _running = true;
      _plan = null;
      _log
        ..clear()
        ..add('Testing ${candidates.length} server(s) on the backup tunnel - about '
            '${(candidates.length * 1.6 + 0.5).ceil()} min. The house stays on the main tunnel.');
    });
    final plan = await c.findBestServer(candidates, (line) {
      if (mounted) setState(() => _log.add(line));
    });
    if (mounted) {
      setState(() {
        _running = false;
        _plan = plan;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final visible = _visible;
    return Scaffold(
      appBar: AppBar(title: const Text('VPN servers')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('Find the best server', style: t.titleMedium),
              const SizedBox(height: 4),
              Text(
                'Each candidate is tried on the backup tunnel and measured by the router (latency, jitter, '
                'loss). The winner moves to main only if it beats the current main by 10 % or more; the '
                'runner-up (another city if possible) becomes the backup.',
                style: t.bodySmall,
              ),
              const SizedBox(height: 12),
              Row(children: [
                const Text('Candidates:'),
                const SizedBox(width: 8),
                DropdownButton<int>(
                  value: _candidates,
                  items: const [
                    DropdownMenuItem(value: 2, child: Text('2 (~4 min)')),
                    DropdownMenuItem(value: 3, child: Text('3 (~5 min)')),
                    DropdownMenuItem(value: 5, child: Text('5 (~9 min)')),
                  ],
                  onChanged: _running ? null : (v) => setState(() => _candidates = v ?? 3),
                ),
                const Spacer(),
                if (_running)
                  OutlinedButton(onPressed: c.cancelFindBest, child: const Text('Stop'))
                else
                  FilledButton.icon(
                    onPressed: _loading ? null : _findBest,
                    icon: const Icon(Icons.speed),
                    label: const Text('Start'),
                  ),
              ]),
              if (_running) const Padding(padding: EdgeInsets.only(top: 8), child: LinearProgressIndicator()),
              if (_log.isNotEmpty)
                Container(
                  width: double.infinity,
                  margin: const EdgeInsets.only(top: 12),
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(color: OpnColors.ink, borderRadius: BorderRadius.circular(10)),
                  child: SelectableText(_log.join('\n'),
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: OpnColors.textSoft)),
                ),
              if (_plan != null)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Row(children: [
                    const Icon(Icons.check_circle, color: OpnColors.green),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(_plan!.changeMain
                          ? 'Main is now ${_plan!.newMain.server.name} (${_plan!.newMain.describe()}).'
                          : 'Kept the current main - it is already about as good as it gets.'),
                    ),
                  ]),
                ),
            ]),
          ),
        ),
        const SizedBox(height: 16),
        Row(children: [
          Expanded(child: Text('Servers (${visible.length})', style: t.titleMedium)),
          if (_loading) const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2)),
        ]),
        const SizedBox(height: 8),
        Wrap(spacing: 8, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
          OutlinedButton.icon(
              onPressed: _loading || _running ? null : _download,
              icon: const Icon(Icons.cloud_download_outlined),
              label: const Text('Download Proton list')),
          OutlinedButton.icon(
              onPressed: _loading || _running ? null : _addFromConf,
              icon: const Icon(Icons.note_add_outlined),
              label: const Text('Add from .conf')),
          FilterChip(
            label: Text('Only ${c.config.serverCities.isEmpty ? 'my cities' : c.config.serverCities}'),
            selected: _onlyMyCities,
            onSelected: (v) => setState(() => _onlyMyCities = v),
          ),
        ]),
        if (_message != null)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: Text(_message!, style: t.bodySmall?.copyWith(color: OpnColors.glassCyan)),
          ),
        const SizedBox(height: 8),
        if (visible.isEmpty)
          Padding(
            padding: const EdgeInsets.all(16),
            child: Text(
              _servers.isEmpty
                  ? 'No servers yet. Download Proton\'s list, or add servers from Proton WireGuard .conf files '
                      '(account.protonvpn.com > Downloads > WireGuard).'
                  : 'No servers in your cities - turn the filter off or change the cities in Settings.',
              style: t.bodySmall,
            ),
          )
        else
          Card(
            child: Column(children: [
              for (final s in visible.take(60))
                ListTile(
                  dense: true,
                  leading: _LoadDot(load: s.load),
                  title: Text(s.name),
                  subtitle: Text([s.city ?? '?', s.entryIp, if (s.load != null) '${s.load}% load'].join(' - ')),
                  trailing: PopupMenuButton<bool>(
                    enabled: !_running && !_loading,
                    tooltip: 'Use this server',
                    onSelected: (main) => _use(s, main: main),
                    itemBuilder: (_) => [
                      PopupMenuItem(value: true, child: Text('Use for ${c.config.mainLabel} (main)')),
                      PopupMenuItem(value: false, child: Text('Use for ${c.config.backupLabel} (backup)')),
                    ],
                  ),
                ),
            ]),
          ),
        const SizedBox(height: 12),
        Text(
          'Proton has no official public server API; if downloading stops working, add servers from .conf '
          'files. The tunnels keep the router\'s own private keys - only the server address and the server\'s '
          'public key change.',
          style: t.bodySmall,
        ),
      ]),
    );
  }
}

class _LoadDot extends StatelessWidget {
  const _LoadDot({required this.load});
  final int? load;

  @override
  Widget build(BuildContext context) {
    final l = load;
    final color = l == null
        ? OpnColors.grey
        : l < 50
            ? OpnColors.green
            : l < 80
                ? OpnColors.amber
                : OpnColors.red;
    return Container(width: 12, height: 12, decoration: BoxDecoration(color: color, shape: BoxShape.circle));
  }
}
