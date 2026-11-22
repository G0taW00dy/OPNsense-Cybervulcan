import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../api/opnsense_client.dart';
import '../core/config.dart';
import '../core/controller.dart';
import '../core/providers.dart';
import '../core/router_server_list.dart';
import '../core/server_switcher.dart';
import 'qr_scan_page.dart';
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
      // Fills this device's copy from the router list, so the card shows
      // server names, not bare IPs (22 Nov, new PC install).
      try {
        await c.loadServerList();
      } on Object {
        // The card still works with addresses.
      }
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
    final s = p.match(c.cachedServers()) ??
        serverFromTunnelPeer(name: p.name, address: p.address, publicKey: p.publicKey, port: p.port);
    return s != null ? s.label : p.address;
  }

  /// Swaps the servers of the main and backup tunnels (v2.1.16).
  Future<void> _swap() async {
    final p = _peers;
    if (p == null) return;
    final cfg = c.config;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Swap main and backup?'),
        content: Text('Main (${cfg.mainLabel}) moves to ${_describe(p.$2)}, backup (${cfg.backupLabel}) to '
            '${_describe(p.$1)}.\n\nCompare their ping, jitter and loss on the tunnel cards first. The router '
            'allows each server on one tunnel at a time, so the backup waits on another server from your list for a '
            'moment. Main restarts once (a few seconds without internet on the VPN), backup twice.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Swap')),
        ],
      ),
    );
    if (ok != true) return;
    setState(() {});
    await c.swapTunnels();
    await _load();
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
              onPressed: c.serverBusy || _error != null || _peers == null ? null : _swap,
              icon: const Icon(Icons.swap_vert),
              label: const Text('Swap'),
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
    unawaited(_loadPeers());
    unawaited(_loadList());
    if (widget.autoStartBest) {
      WidgetsBinding.instance.addPostFrameCallback((_) => unawaited(_findBest()));
    }
  }

  /// " (on the router - every device sees it)" / a failure note / "".
  String _whereSaved() => !c.config.serverListOnRouter
      ? ''
      : c.serverListNote != null
          ? ' - ${c.serverListNote}'
          : ' (on the router - your other devices see it too)';

  /// Reads the shared list from the router (when switched on in Settings).
  Future<void> _loadList() async {
    if (!c.config.serverListOnRouter) return;
    setState(() => _loading = true);
    final list = await c.loadServerList();
    if (!mounted) return;
    setState(() {
      _loading = false;
      _servers = _peers == null ? list : withTunnelServers(list, _peers!, c.config);
      if (c.serverListNote != null) _message = c.serverListNote;
    });
  }

  /// What each tunnel uses on the router now (null until read / unreadable).
  (WgPeerInfo, WgPeerInfo)? _peers;

  Future<void> _loadPeers() async {
    try {
      final p = await c.tunnelPeers();
      if (!mounted) return;
      setState(() {
        _peers = p;
        _servers = withTunnelServers(_servers, p, c.config);
      });
    } on Object {
      // The tile tags are a nicety; the page still works without them.
    }
  }

  /// "main" / "backup" when [s] is what that tunnel uses now.
  String? _inUse(ProtonServer s) {
    final p = _peers;
    if (p == null) return null;
    if (s.sameEndpoint(p.$1.address, p.$1.publicKey)) return 'main';
    if (s.sameEndpoint(p.$2.address, p.$2.publicKey)) return 'backup';
    return null;
  }

  @override
  void dispose() {
    _http.close();
    super.dispose();
  }

  /// Cities ticked in the dropdown that have servers here (a ticked city
  /// with no servers no longer hides the whole list).
  Set<String> get _activeCities {
    final have = {for (final s in _servers) (s.city ?? '').toLowerCase()};
    return {
      for (final x in c.config.serverCityList)
        if (have.contains(x.toLowerCase())) x.toLowerCase(),
    };
  }

  Widget _cityMenu(BuildContext context) {
    final all = knownCities(_servers, c.config);
    final ticked = c.config.serverCityList.map((x) => x.toLowerCase()).toSet();
    final active = _activeCities;
    final label = active.isEmpty
        ? 'All cities'
        : [for (final x in all) if (active.contains(x.toLowerCase())) x].join(', ');
    return MenuAnchor(
      menuChildren: [
        MenuItemButton(
          leadingIcon: Icon(active.isEmpty ? Icons.check_box : Icons.check_box_outline_blank),
          onPressed: () => _setCities(const []),
          child: const Text('All cities'),
        ),
        for (final city in all)
          MenuItemButton(
            closeOnActivate: false,
            leadingIcon:
                Icon(ticked.contains(city.toLowerCase()) ? Icons.check_box : Icons.check_box_outline_blank),
            onPressed: () => _setCities([
              for (final x in c.config.serverCityList)
                if (x.toLowerCase() != city.toLowerCase()) x,
              if (!ticked.contains(city.toLowerCase())) city,
            ]),
            child: Text(city),
          ),
      ],
      builder: (context, ctl, _) => OutlinedButton.icon(
        onPressed: () => ctl.isOpen ? ctl.close() : ctl.open(),
        icon: const Icon(Icons.location_city_outlined),
        label: Row(mainAxisSize: MainAxisSize.min, children: [
          Text(label),
          const Icon(Icons.arrow_drop_down),
        ]),
      ),
    );
  }

  Future<void> _setCities(List<String> cities) async {
    await c.setServerCities(cities);
    if (mounted) setState(() {});
  }

  /// Servers Find best can pick from (ticked cities; the tunnels' own
  /// servers are excluded by the switcher).
  int get _poolSize {
    final cities = _activeCities;
    final n = cities.isEmpty
        ? _servers.length
        : _servers.where((s) => cities.contains((s.city ?? '').toLowerCase())).length;
    return n < 1 ? 1 : n;
  }

  /// About 100 s per candidate plus the main measurement.
  String _minutes(int n) => '~${((n * 100 + 90) / 60).ceil()} min';

  List<ProtonServer> get _visible {
    final cities = _activeCities;
    final list = cities.isNotEmpty
        ? _servers.where((s) => cities.contains((s.city ?? '').toLowerCase())).toList()
        : [..._servers];
    list.sort((a, b) => (a.load ?? 100).compareTo(b.load ?? 100));
    return list;
  }

  ProviderProfile get _profile => ProviderProfile.byId(c.config.providerId);

  Future<void> _download() async {
    final p = _profile;
    if (!p.hasServerList) return;
    setState(() {
      _loading = true;
      _message = null;
    });
    try {
      final list = await p.fetchServers(_http, country: c.config.vpnCountryCode);
      // Keep manually added servers that the provider's list doesn't have.
      final manual = _servers.where((m) => !list.any((s) => s.entryIp == m.entryIp));
      _servers = [...list, ...manual];
      await c.saveServers(_servers);
      _message = 'Downloaded ${list.length} ${c.config.vpnCountryCode} servers from ${p.name}.';
    } on ProviderException catch (e) {
      _message = e.message;
    } on Object {
      _message = 'Could not download the ${p.name} server list - check the internet connection, or add servers '
          'from config files.';
    }
    if (mounted) setState(() => _loading = false);
  }

  Future<void> _scanQr() async {
    final text = await QrScanPage.scan(context,
        title: 'Scan a WireGuard QR code',
        hint: 'Point the camera at the QR code on your provider\'s config page. Only the server address and its '
            'public key are kept - the private key in the code is ignored.');
    if (text == null || !mounted) return;
    await _importConfigText(text);
  }

  Future<void> _addFromConf() async {
    final text = await pasteOrOpenText(context,
        title: 'Add a server from a WireGuard config',
        hint: 'Paste the [Peer] part (or the whole config, or open the file). Only the server address and its '
            'PUBLIC key are used - a private key in the text is ignored and never stored.\n\n${_profile.configHelp}');
    if (text == null || !mounted) return;
    await _importConfigText(text);
  }

  Future<void> _importConfigText(String text) async {
    final s = serverFromWireGuardConf(text);
    if (s == null) {
      setState(() => _message = 'No [Peer] with a PublicKey and an IPv4 Endpoint found in that text.');
      return;
    }
    final city = await _askCity(s);
    final server = ProtonServer(
        name: s.name, entryIp: s.entryIp, publicKey: s.publicKey, port: s.port, city: city, country: c.config.vpnCountryCode);
    _servers = [..._servers.where((x) => x.entryIp != server.entryIp), server];
    await c.saveServers(_servers);
    final hidden = !_visible.any((x) => x.entryIp == server.entryIp);
    if (mounted) {
      setState(() => _message = 'Added ${server.name}${_whereSaved()}.'
          '${hidden ? ' It is hidden by the city filter - choose "All cities" to show it.' : ''}'
          ' (Any private key in it was ignored.)');
    }
  }

  Future<void> _setCity(ProtonServer s) async {
    final city = await _askCity(s);
    if (city == null) return;
    _servers = [
      for (final x in _servers)
        x.entryIp == s.entryIp
            ? ProtonServer(
                name: x.name, entryIp: x.entryIp, publicKey: x.publicKey, port: x.port, city: city, country: x.country,
                load: x.load, score: x.score)
            : x,
    ];
    await c.saveServers(_servers);
    if (_inUse(s) != null) {
      await c.nameTunnelPeer(_servers.firstWhere((x) => x.entryIp == s.entryIp));
    }
    if (mounted) setState(() => _message = '${s.name} is now listed in $city${_whereSaved()}.');
  }

  /// Renames a server (e.g. "Former Backup server" -> "JP#219"). A server a
  /// tunnel uses also gets its name on the router's tunnel peer, so the other
  /// devices see it (v2.1.13).
  Future<void> _rename(ProtonServer s) async {
    final ctl = TextEditingController(text: s.name);
    final name = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Rename server'),
        content: TextField(
            controller: ctl,
            autofocus: true,
            onSubmitted: (v) => Navigator.pop(ctx, v.trim()),
            decoration: const InputDecoration(labelText: 'Name', hintText: 'e.g. JP#219')),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, ctl.text.trim()), child: const Text('Save')),
        ],
      ),
    );
    if (name == null || name.isEmpty || name == s.name) return;
    final renamed = ProtonServer(
        name: name, entryIp: s.entryIp, publicKey: s.publicKey, port: s.port, city: s.city, country: s.country,
        load: s.load, score: s.score);
    _servers = [for (final x in _servers) x.sameEndpoint(s.entryIp, s.publicKey) ? renamed : x];
    await c.saveServers(_servers);
    if (_inUse(s) != null) await c.nameTunnelPeer(renamed);
    if (mounted) setState(() => _message = 'Renamed to $name${_whereSaved()}.');
  }

  Future<void> _remove(ProtonServer s) async {
    _servers = _servers.where((x) => x.entryIp != s.entryIp).toList();
    await c.removeServer(s);
    if (mounted) {
      setState(() => _message = 'Removed ${s.name} from the list${_whereSaved()}. The tunnels are not changed.');
    }
  }

  Future<String?> _askCity(ProtonServer s) async {
    // No guess: a wrong pre-filled city mislabels the server (20 Nov bug).
    final ctl = TextEditingController();
    final region = serverRegionHint(s.name);
    final r = await showDialog<String>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setD) => AlertDialog(
          title: Text('Which city is ${s.name} in?'),
          content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            if (region != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Text('The name says region $region. The provider\'s server list shows the city.'),
              ),
            TextField(
                controller: ctl,
                onChanged: (_) => setD(() {}),
                decoration: const InputDecoration(labelText: 'New city', hintText: 'e.g. Los Angeles')),
            if (knownCities(_servers, c.config).isNotEmpty) ...[
              const SizedBox(height: 10),
              Text('Or pick one you already have:', style: Theme.of(ctx).textTheme.bodySmall),
              const SizedBox(height: 4),
              Wrap(spacing: 6, runSpacing: 6, children: [
                for (final city in knownCities(_servers, c.config))
                  ChoiceChip(
                      label: Text(city),
                      selected: ctl.text.trim().toLowerCase() == city.toLowerCase(),
                      onSelected: (_) => setD(() => ctl.text = city)),
              ]),
            ],
          ]),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Skip')),
            FilledButton(onPressed: () => Navigator.pop(ctx, ctl.text.trim()), child: const Text('OK')),
          ],
        ),
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
      // The "(main/backup) now" tags and the server left behind (21 Nov:
      // tags stayed on the old servers until the page was reopened).
      if (done) _servers = c.cachedServers();
    });
    if (done) await _loadPeers();
  }

  Future<void> _findBest() async {
    if (_running) return;
    var pool = _servers;
    if (pool.isEmpty) {
      await _download();
      pool = _servers;
    }
    final candidates =
        pickCandidates(pool, c.config.serverCityList, max: _candidates, lastTested: c.serverLastTested);
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
        _servers = c.cachedServers();
      });
      await _loadPeers();
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
                  value: _candidates >= _poolSize ? 999 : _candidates,
                  items: [
                    for (final n in const [3, 5, 10])
                      if (n < _poolSize) DropdownMenuItem(value: n, child: Text('$n (${_minutes(n)})')),
                    DropdownMenuItem(value: 999, child: Text('All $_poolSize (${_minutes(_poolSize)})')),
                  ],
                  onChanged: _running ? null : (v) => setState(() => _candidates = v ?? 3),
                  // A choice above the pool size shows as "All".
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
          Expanded(
              child: Text(
                  visible.length == _servers.length
                      ? 'Servers (${visible.length})'
                      : 'Servers (${visible.length} of ${_servers.length} - filter on)',
                  style: t.titleMedium)),
          if (_loading) const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2)),
        ]),
        const SizedBox(height: 8),
        Wrap(spacing: 8, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
          if (_profile.hasServerList)
            OutlinedButton.icon(
                onPressed: _loading || _running ? null : _download,
                icon: const Icon(Icons.cloud_download_outlined),
                label: Text('Download ${_profile.name} list')),
          if (Platform.isAndroid)
            OutlinedButton.icon(
                onPressed: _loading || _running ? null : _scanQr,
                icon: const Icon(Icons.qr_code_scanner),
                label: const Text('Scan QR')),
          OutlinedButton.icon(
              onPressed: _loading || _running ? null : _addFromConf,
              icon: const Icon(Icons.note_add_outlined),
              label: const Text('Paste config')),
          // v2.1.16: a dropdown with a tick per city (was an on/off chip that
          // hid everything when the chosen cities had no servers).
          if (knownCities(_servers, c.config).isNotEmpty) _cityMenu(context),
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
                  ? 'No servers yet. ${_profile.noListReason ?? 'Download the list, or add servers from config files.'}'
                  : 'No servers in the ticked cities - choose "All cities".',
              style: t.bodySmall,
            ),
          )
        else
          Card(
            child: Column(children: [
              for (final s in visible.take(60))
                ListTile(
                  dense: true,
                  // No load figure (Proton no longer publishes it): a plain
                  // server icon, not a grey dot that reads as "offline".
                  leading: s.load == null ? const Icon(Icons.dns_outlined, size: 20) : _LoadDot(load: s.load),
                  title: Text.rich(TextSpan(text: s.name, children: [
                    if (_inUse(s) != null)
                      TextSpan(
                          text: '   ${_inUse(s) == 'main' ? c.config.mainLabel : c.config.backupLabel} (${_inUse(s)}) now',
                          style: t.labelMedium?.copyWith(color: OpnColors.glassCyan)),
                  ])),
                  subtitle: Text([s.city ?? '?', s.entryIp, if (s.load != null) '${s.load}% load'].join(' - ')),
                  trailing: PopupMenuButton<String>(
                    enabled: !_running && !_loading,
                    tooltip: 'Use this server',
                    onSelected: (v) => switch (v) {
                      'main' => _use(s, main: true),
                      'backup' => _use(s, main: false),
                      'city' => _setCity(s),
                      'rename' => _rename(s),
                      _ => _remove(s),
                    },
                    itemBuilder: (_) => [
                      if (_inUse(s) != 'main')
                        PopupMenuItem(value: 'main', child: Text('Use for ${c.config.mainLabel} (main)')),
                      if (_inUse(s) != 'backup')
                        PopupMenuItem(value: 'backup', child: Text('Use for ${c.config.backupLabel} (backup)')),
                      const PopupMenuDivider(),
                      const PopupMenuItem(value: 'rename', child: Text('Rename')),
                      const PopupMenuItem(value: 'city', child: Text('Set city')),
                      const PopupMenuItem(value: 'remove', child: Text('Remove from list')),
                    ],
                  ),
                ),
            ]),
          ),
        const SizedBox(height: 12),
        Text(
          '${_profile.hasServerList ? '' : '${_profile.noListReason} '}'
          'The tunnels keep the router\'s own private keys - only the server address and the server\'s public key '
          'change, and the app waits for a real handshake before calling a switch done.',
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

/// Cities the person already uses (server list + "Cities to choose from"),
/// one spelling each (first seen wins), sorted.
List<String> knownCities(List<ProtonServer> servers, AppConfig cfg) {
  final byKey = <String, String>{};
  for (final c in [...cfg.serverCityList, for (final s in servers) ?s.city]) {
    final t = c.trim();
    if (t.isNotEmpty) byKey.putIfAbsent(t.toLowerCase(), () => t);
  }
  return byKey.values.toList()..sort((a, b) => a.toLowerCase().compareTo(b.toLowerCase()));
}

/// [servers] plus the server each tunnel uses now when it is not in the list
/// (e.g. set up on the router before the app, or chosen on another device):
/// the router list can't hold those (one peer per key), so every device
/// shows them from the live tunnels. Name them with "Set city".
List<ProtonServer> withTunnelServers(List<ProtonServer> servers, (WgPeerInfo, WgPeerInfo) peers, AppConfig cfg) {
  final out = [...servers];
  for (final (label, p) in [(cfg.mainLabel, peers.$1), (cfg.backupLabel, peers.$2)]) {
    if (p.address.isEmpty || p.match(out) != null) continue;
    out.insert(
        0,
        serverFromTunnelPeer(name: p.name, address: p.address, publicKey: p.publicKey, port: p.port) ??
            ProtonServer(name: '$label tunnel server', entryIp: p.address, publicKey: p.publicKey, port: p.port));
  }
  return out;
}
