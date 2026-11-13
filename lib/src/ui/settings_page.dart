import 'package:flutter/material.dart';

import '../api/opnsense_client.dart';
import '../api/tls.dart';
import 'dart:io';

import '../core/client_factory.dart';
import '../core/config.dart';
import '../core/network_map.dart';
import '../core/controller.dart';
import '../core/bypass.dart';
import '../core/settings_transfer.dart';
import '../core/storage.dart';
import '../core/updater.dart';
import '../net/router_link.dart';
import '../platform/autostart.dart';
import 'format.dart';
import 'help_page.dart';
import 'remote_access.dart';
import 'theme.dart';
import 'update_widgets.dart';

/// Networks as editable text: one "NAME CIDR description" per line.
String networksToText(List<NamedNetwork> nets) =>
    nets.map((n) => '${n.name} ${n.cidr}${n.description.isEmpty ? '' : ' ${n.description}'}').join('\n');

/// Parses [networksToText] output; null when a line is invalid.
List<NamedNetwork>? networksFromText(String text) {
  final out = <NamedNetwork>[];
  for (final line in text.split('\n')) {
    final l = line.trim();
    if (l.isEmpty) continue;
    final parts = l.split(RegExp(r'\s+'));
    if (parts.length < 2) return null;
    final cidr = canonicalCidr(parts[1]);
    if (cidr == null || !RegExp(r'^[A-Za-z0-9_-]{1,32}$').hasMatch(parts[0])) return null;
    out.add(NamedNetwork(parts[0], cidr, description: parts.skip(2).join(' ')));
  }
  return out.isEmpty ? null : out;
}

/// Validator for the router address field.
String? validateRouterAddress(String? v) {
  final u = Uri.tryParse(normaliseRouterAddress(v ?? ''));
  return u == null || u.host.isEmpty || !(u.scheme == 'http' || u.scheme == 'https')
      ? 'e.g. https://10.10.10.254 or 10.10.10.254'
      : null;
}

String? validateCertName(String? v) {
  final n = v?.trim() ?? '';
  if (n.isEmpty) return null;
  return RegExp(r'^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$')
          .hasMatch(n)
      ? null
      : 'A host name, e.g. router.cybervulcan.com';
}

/// Runs the identity check and every endpoint with the given settings.
/// Returns report lines; the first says how the router was reached.
Future<List<String>> testRouterConnection(AppConfig cfg, ApiCredentials? creds) async {
  final target = RouterTarget.fromConfig(cfg);
  if (target == null) return ['FAIL  Router address is not valid'];
  final probe = await probeRouter(target, RouterRoute.direct(target.host, target.port),
      const Duration(seconds: 4));
  final lines = <String>[];
  switch (probe.kind) {
    case ProbeKind.ok:
      lines.add(target.secure
          ? 'OK    Certificate valid for ${target.tlsName}${target.pinned ? ' (pinned)' : ''}'
          : 'WARN  Plain http:// - no certificate check, API key sent unencrypted');
    case ProbeKind.wrongCertificate:
      return ['FAIL  Wrong certificate - not your router? ${probe.detail ?? ''}',
        '      The API key was NOT sent.'];
    case ProbeKind.unreachable:
      return ['FAIL  ${target.host}:${target.port} did not answer (${probe.detail ?? 'timeout'}).',
        '      At home? Check the address. Away? The test only works at home.'];
  }
  final client = buildRouterClient(cfg, creds);
  if (client == null) return [...lines, 'FAIL  Enter the API key and secret first'];
  Future<void> run(String name, Future<Object?> Function() f) async {
    try {
      await f();
      lines.add('OK    $name');
    } on OpnsenseException catch (e) {
      lines.add('${e.kind == ApiErrorKind.forbidden ? 'NO PRIVILEGE' : 'FAIL'}  $name: ${e.message}');
    }
  }

  await run('Gateway status', client.gatewayStatus);
  await run('Bypass alias ${cfg.bypassAlias}', () => client.aliasList(cfg.bypassAlias));
  await run('PC mode alias ${cfg.pcModeAlias}', () => client.aliasList(cfg.pcModeAlias));
  await run('DHCP leases (optional)', client.dnsmasqLeases);
  await run('Kill switch rule search (optional)', () => client.searchRules(cfg.killSwitchTag));
  client.close();
  return lines;
}

/// First-run setup and settings. Secrets go to OS secure storage only.
class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key, required this.controller, this.firstRun = false, this.updates});

  final CybervulcanController controller;
  final bool firstRun;
  final UpdateService? updates;

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  final _form = GlobalKey<FormState>();
  late AppConfig _cfg;
  late final Map<String, TextEditingController> _t;
  final _apiKey = TextEditingController();
  final _apiSecret = TextEditingController();
  bool _showSecret = false;
  bool _busy = false;
  String? _message;
  bool _messageIsError = false;
  bool? _autostart; // null = unknown / not Windows

  @override
  void initState() {
    super.initState();
    _cfg = widget.controller.config;
    if (WindowsAutostart.supported) {
      WindowsAutostart.isEnabled().then((v) {
        if (mounted) setState(() => _autostart = v);
      });
    }
    _t = {
      'baseUrl': TextEditingController(text: _cfg.baseUrl),
      'certName': TextEditingController(text: _cfg.certName),
      'vpnName': TextEditingController(text: _cfg.vpnName),
      'directLabel': TextEditingController(text: _cfg.directLabel),
      'directNetworkName': TextEditingController(text: _cfg.directNetworkName),
      'networks': TextEditingController(text: networksToText(_cfg.networks)),
      'mainGateway': TextEditingController(text: _cfg.mainGateway),
      'backupGateway': TextEditingController(text: _cfg.backupGateway),
      'mainLabel': TextEditingController(text: _cfg.mainLabel),
      'backupLabel': TextEditingController(text: _cfg.backupLabel),
      'pcModeAlias': TextEditingController(text: _cfg.pcModeAlias),
      'bypassAlias': TextEditingController(text: _cfg.bypassAlias),
      'bypassNetwork': TextEditingController(text: _cfg.bypassNetwork),
      'bypassMinutes': TextEditingController(
          text: isNoLimitDuration(_cfg.bypassDuration) ? '0' : '${_cfg.bypassDuration.inMinutes}'),
      'pcIpOverride': TextEditingController(text: _cfg.pcIpOverride ?? ''),
      'killSwitchTag': TextEditingController(text: _cfg.killSwitchTag),
      'killSwitchRuleUuid': TextEditingController(text: _cfg.killSwitchRuleUuid ?? ''),
      'pollSeconds': TextEditingController(text: '${_cfg.pollInterval.inSeconds}'),
      'homeCountryCode': TextEditingController(text: _cfg.homeCountryCode),
      'vpnCountryCode': TextEditingController(text: _cfg.vpnCountryCode),
    };
  }

  @override
  void dispose() {
    for (final c in _t.values) {
      c.dispose();
    }
    _apiKey.dispose();
    _apiSecret.dispose();
    super.dispose();
  }

  String _v(String k) => _t[k]!.text.trim();

  AppConfig _collect() => _cfg.copyWith(
        baseUrl: normaliseRouterAddress(_v('baseUrl')),
        certName: _v('certName'),
        vpnName: _v('vpnName'),
        directLabel: _v('directLabel'),
        directNetworkName: _v('directNetworkName'),
        networks: networksFromText(_t['networks']!.text),
        mainGateway: _v('mainGateway'),
        backupGateway: _v('backupGateway'),
        mainLabel: _v('mainLabel'),
        backupLabel: _v('backupLabel'),
        pcModeAlias: _v('pcModeAlias'),
        bypassAlias: _v('bypassAlias'),
        bypassNetwork: canonicalCidr(_v('bypassNetwork')),
        bypassDuration: switch (int.tryParse(_v('bypassMinutes'))) {
          0 => bypassNoLimit,
          final int m when m > 0 => Duration(minutes: m),
          _ => const Duration(minutes: 120),
        },
        pcIpOverride: _v('pcIpOverride').isEmpty ? null : _v('pcIpOverride'),
        clearPcIpOverride: _v('pcIpOverride').isEmpty,
        killSwitchTag: _v('killSwitchTag'),
        killSwitchRuleUuid: _v('killSwitchRuleUuid').isEmpty ? null : _v('killSwitchRuleUuid'),
        clearKillSwitchRuleUuid: _v('killSwitchRuleUuid').isEmpty,
        pollInterval: Duration(seconds: int.tryParse(_v('pollSeconds')) ?? 15),
        homeCountryCode: _v('homeCountryCode').toUpperCase(),
        vpnCountryCode: _v('vpnCountryCode').toUpperCase(),
      );

  ApiCredentials? _newCreds() {
    final k = _apiKey.text.trim();
    final s = _apiSecret.text.trim();
    return k.isEmpty && s.isEmpty ? null : ApiCredentials(k, s);
  }

  void _say(String msg, {bool error = false}) => setState(() {
        _message = msg;
        _messageIsError = error;
      });

  Future<void> _save() async {
    if (!_form.currentState!.validate()) return;
    final creds = _newCreds();
    if (creds != null && !creds.isComplete) {
      _say('Enter both the API key and the API secret.', error: true);
      return;
    }
    if (!widget.controller.hasCredentials && creds == null) {
      _say('API key and secret are required.', error: true);
      return;
    }
    setState(() => _busy = true);
    await widget.controller.saveSettings(_collect(), credentials: creds);
    if (!mounted) return;
    _apiKey.clear();
    _apiSecret.clear();
    _cfg = widget.controller.config;
    setState(() => _busy = false);
    final s = widget.controller.snapshot;
    final err = s.error;
    _say(err == null ? 'Saved. Connected to the router.' : 'Saved, but: ${errorHint(err)}',
        error: err != null);
  }

  /// Trust-on-first-use for a self-signed router certificate.
  Future<void> _trustCertificate() async {
    final uri = Uri.tryParse(normaliseRouterAddress(_v('baseUrl')));
    if (uri == null || uri.scheme != 'https' || uri.host.isEmpty) {
      _say('Certificate pinning only applies to an https:// base URL.', error: true);
      return;
    }
    setState(() => _busy = true);
    final cert = await probeCertificate(uri.host, uri.hasPort ? uri.port : 443);
    if (!mounted) return;
    setState(() => _busy = false);
    if (cert == null) {
      _say('Could not read a TLS certificate from ${uri.host}.', error: true);
      return;
    }
    if (!mounted) return;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Trust this router certificate?'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Compare the SHA-256 fingerprint with the one shown on the router '
                  '(System > Trust > Certificates, or the browser\'s certificate viewer) '
                  'before trusting it.'),
              const SizedBox(height: 12),
              SelectableText(cert.fingerprint,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 13)),
              const SizedBox(height: 12),
              Text('Subject: ${cert.subject}'),
              Text('Issuer: ${cert.issuer}'),
              Text('Valid: ${cert.validFrom.toLocal()} - ${cert.validTo.toLocal()}'),
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Trust')),
        ],
      ),
    );
    if (ok != true) return;
    _cfg = _cfg.copyWith(pinnedCertSha256: cert.fingerprint);
    _say('Certificate pinned. Press Save to apply.');
  }

  Future<void> _testConnection() async {
    if (!_form.currentState!.validate()) return;
    final creds = _newCreds() ?? await widget.controller.secrets.read();
    if (!mounted) return;
    setState(() => _busy = true);
    final results = await testRouterConnection(_collect(), creds);
    if (!mounted) return;
    setState(() => _busy = false);
    _say(results.join('\n'), error: results.any((r) => r.startsWith('FAIL') || r.startsWith('NO')));
  }

  Future<void> _export() async {
    final text = exportSettings(_collect());
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Share settings'),
        content: SizedBox(
          width: 520,
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Everything except secrets: no API key or secret, no WireGuard private or '
                'pre-shared key. The other person enters their own API key and makes their own '
                'WireGuard key on their device.'),
            const SizedBox(height: 12),
            ConstrainedBox(
              constraints: const BoxConstraints(maxHeight: 260),
              child: SingleChildScrollView(
                child: SelectableText(text, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
              ),
            ),
          ]),
        ),
        actions: [
          TextButton(onPressed: () => copyText(ctx, text, 'Settings copied'), child: const Text('Copy')),
          TextButton(
            onPressed: () => showQrDialog(ctx,
                title: 'Settings (no secrets)', text: exportSettings(_collect(), pretty: false)),
            child: const Text('QR'),
          ),
          if (Platform.isWindows)
            TextButton(
              onPressed: () async {
                final path = await saveTextFile('cybervulcan-settings.json', text);
                if (path != null && ctx.mounted) {
                  ScaffoldMessenger.of(ctx).showSnackBar(SnackBar(content: Text('Saved to $path')));
                }
              },
              child: const Text('Save file...'),
            ),
          FilledButton(onPressed: () => Navigator.pop(ctx), child: const Text('Close')),
        ],
      ),
    );
  }

  Future<void> _import() async {
    final text = await pasteOrOpenText(context,
        title: 'Import settings', hint: 'Paste the settings text you were given (JSON).');
    if (text == null || text.trim().isEmpty || !mounted) return;
    try {
      final r = importSettings(text, _collect());
      setState(() {
        _cfg = r.config;
        _reload();
      });
      _say([
        'Imported ${r.applied.length} settings. Check them, then press Save.',
        if (r.ignored.isNotEmpty) 'Ignored: ${r.ignored.join(', ')}',
        ...r.warnings,
      ].join('\n'));
    } on FormatException catch (e) {
      _say(e.message, error: true);
    }
  }

  /// Refills every text field from [_cfg] (after an import).
  void _reload() {
    _t['baseUrl']!.text = _cfg.baseUrl;
    _t['certName']!.text = _cfg.certName;
    _t['vpnName']!.text = _cfg.vpnName;
    _t['directLabel']!.text = _cfg.directLabel;
    _t['directNetworkName']!.text = _cfg.directNetworkName;
    _t['networks']!.text = networksToText(_cfg.networks);
    _t['mainGateway']!.text = _cfg.mainGateway;
    _t['backupGateway']!.text = _cfg.backupGateway;
    _t['mainLabel']!.text = _cfg.mainLabel;
    _t['backupLabel']!.text = _cfg.backupLabel;
    _t['pcModeAlias']!.text = _cfg.pcModeAlias;
    _t['bypassAlias']!.text = _cfg.bypassAlias;
    _t['bypassNetwork']!.text = _cfg.bypassNetwork;
    _t['bypassMinutes']!.text =
        isNoLimitDuration(_cfg.bypassDuration) ? '0' : '${_cfg.bypassDuration.inMinutes}';
    _t['killSwitchTag']!.text = _cfg.killSwitchTag;
    _t['killSwitchRuleUuid']!.text = _cfg.killSwitchRuleUuid ?? '';
    _t['pollSeconds']!.text = '${_cfg.pollInterval.inSeconds}';
    _t['homeCountryCode']!.text = _cfg.homeCountryCode;
    _t['vpnCountryCode']!.text = _cfg.vpnCountryCode;
    _remoteGen++;
  }

  int _remoteGen = 0;

  Widget _field(String key, String label,
          {String? help, String? Function(String?)? validator, bool number = false, ValueChanged<String>? onChanged}) =>
      Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: TextFormField(
          controller: _t[key],
          decoration: InputDecoration(labelText: label, helperText: help, helperMaxLines: 3),
          keyboardType: number ? TextInputType.number : TextInputType.text,
          validator: validator,
          onChanged: onChanged,
        ),
      );

  String? _required(String? v) => (v == null || v.trim().isEmpty) ? 'Required' : null;

  String? _alias(String? v) =>
      RegExp(r'^[A-Za-z0-9_]{1,32}$').hasMatch(v?.trim() ?? '') ? null : 'Letters, digits, _ only';

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final hasCreds = widget.controller.hasCredentials;
    return Form(
      key: _form,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Align(
            alignment: Alignment.centerRight,
            child: OutlinedButton.icon(
              onPressed: () => openSetupGuide(context),
              icon: const Icon(Icons.help_outline),
              label: const Text('Setup guide'),
            ),
          ),
          if (widget.firstRun) ...[
            Text('Welcome to Cybervulcan', style: t.headlineSmall),
            const SizedBox(height: 8),
            const Text('Connect to your OPNsense router with your own API key (from the router admin). '
                'See the setup guide for the privileges it needs.'),
            const SizedBox(height: 16),
          ],
          _section('Router'),
          _field('baseUrl', 'Router address',
              help: 'The app connects here, e.g. https://10.10.10.254',
              validator: validateRouterAddress,
              onChanged: (_) => setState(() {})),
          _field('certName', 'Certificate name',
              help: 'The router\'s certificate must be valid for this name (e.g. router.cybervulcan.com). '
                  'If it is not, the app refuses to connect and never sends the API key. '
                  'Leave empty to check the certificate against the address (or use a pin).',
              validator: validateCertName),
          if (normaliseRouterAddress(_v('baseUrl')).startsWith('http://'))
            const _Warning('Plain http:// sends the API key unencrypted and cannot prove this is '
                'your router. Use https:// once the router has its certificate.'),
          Row(children: [
            Expanded(
              child: Text(
                _cfg.pinnedCertSha256 == null
                    ? 'No pinned certificate (only CA-trusted certificates are accepted).'
                    : 'Pinned SHA-256: ${_cfg.pinnedCertSha256}',
                style: t.bodySmall,
              ),
            ),
            TextButton(onPressed: _busy ? null : _trustCertificate, child: const Text('Trust certificate...')),
            if (_cfg.pinnedCertSha256 != null)
              TextButton(
                onPressed: () => setState(() => _cfg = _cfg.copyWith(clearPin: true)),
                child: const Text('Forget'),
              ),
          ]),
          const SizedBox(height: 12),
          TextFormField(
            controller: _apiKey,
            decoration: InputDecoration(
              labelText: 'API key',
              helperText: hasCreds ? 'Stored securely. Leave blank to keep the current key.' : null,
            ),
            autocorrect: false,
            enableSuggestions: false,
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _apiSecret,
            obscureText: !_showSecret,
            autocorrect: false,
            enableSuggestions: false,
            decoration: InputDecoration(
              labelText: 'API secret',
              suffixIcon: IconButton(
                icon: Icon(_showSecret ? Icons.visibility_off : Icons.visibility),
                onPressed: () => setState(() => _showSecret = !_showSecret),
              ),
            ),
          ),
          if (hasCreds)
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                onPressed: _busy ? null : () async {
                  await widget.controller.forgetCredentials();
                  if (mounted) setState(() {});
                },
                icon: const Icon(Icons.delete_outline),
                label: const Text('Forget stored API key'),
              ),
            ),
          const SizedBox(height: 8),
          _section('VPN gateways (main / backup)'),
          Row(children: [
            Expanded(child: _field('mainGateway', 'Main gateway', validator: _required)),
            const SizedBox(width: 12),
            Expanded(child: _field('mainLabel', 'Label', validator: _required)),
          ]),
          Row(children: [
            Expanded(child: _field('backupGateway', 'Backup gateway', validator: _required)),
            const SizedBox(width: 12),
            Expanded(child: _field('backupLabel', 'Label', validator: _required)),
          ]),
          _section('Bypass & PC mode'),
          _field('bypassAlias', 'Whole-house bypass alias', validator: _alias),
          _field('bypassNetwork', 'VPN network to bypass',
              validator: (v) {
                final net = Ipv4Subnet.tryParse(v ?? '');
                if (net == null || !(v ?? '').contains('/')) return 'CIDR, e.g. 10.10.40.0/24';
                // A short prefix (e.g. 0.0.0.0/0 or /8) would take far more than the
                // VPN VLAN off Proton and make kill_states reset most connections.
                if (net.prefix < 16) return 'Prefix must be /16 or longer';
                return null;
              }),
          _field('bypassMinutes', 'Default bypass length (minutes)', number: true,
              help: '0 = no time limit (stays off until someone turns it off). You can still pick a length each time.',
              validator: (v) {
                final n = int.tryParse(v ?? '');
                return n != null && (n == 0 || n >= 5) ? null : '0, or at least 5';
              }),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Store bypass deadline on the router'),
            subtitle: const Text('Adds a marker entry (240.x.x.x) to the bypass table so every '
                'device enforces the same expiry. Harmless: that range never appears on the LAN.'),
            value: _cfg.useExpiryMarker,
            onChanged: (v) => setState(() => _cfg = _cfg.copyWith(useExpiryMarker: v)),
          ),
          if (!_cfg.useExpiryMarker)
            const _Warning('Off: the router-side timer can\'t see the deadline, so a bypass only '
                'ends while a Cybervulcan app is running. Leave this on unless you have a reason.'),
          _field('pcModeAlias', 'PC mode (CLEAR) alias', validator: _alias),
          _field('pcIpOverride', 'This PC\'s IP (blank = auto-detect)',
              validator: (v) => (v == null || v.trim().isEmpty || ipv4ToInt(v) != null) ? null : 'IPv4 address'),
          _section('Names and networks'),
          Row(children: [
            Expanded(child: _field('vpnName', 'VPN provider name', validator: _required)),
            const SizedBox(width: 12),
            Expanded(child: _field('directLabel', 'Label while bypassed', validator: _required)),
          ]),
          _field('directNetworkName', 'Direct (clear) network name',
              help: 'Which network below always goes straight out (for PC IP detection and tests).'),
          Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: TextFormField(
              controller: _t['networks'],
              maxLines: null,
              minLines: 3,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
              decoration: const InputDecoration(
                labelText: 'House networks',
                helperText: 'One per line: NAME CIDR description, e.g. "VPN 10.10.40.0/24 Everything via VPN"',
                helperMaxLines: 2,
              ),
              validator: (v) => networksFromText(v ?? '') == null ? 'Each line: NAME a.b.c.d/nn [description]' : null,
            ),
          ),
          _section('Kill switch'),
          _field('killSwitchTag', 'Kill switch tag', validator: _required),
          _field('killSwitchRuleUuid', 'Rule UUID (optional)',
              help: 'Only needed if the API user has "Firewall: Rules" but not "Firewall: Rules [new]".'),
          _section('Checks & alerts'),
          _field('pollSeconds', 'Poll every (seconds)', number: true,
              validator: (v) => (int.tryParse(v ?? '') ?? 0) >= 5 ? null : 'At least 5'),
          Row(children: [
            Expanded(child: _field('homeCountryCode', 'Home country (ISP)', validator: _required)),
            const SizedBox(width: 12),
            Expanded(child: _field('vpnCountryCode', 'VPN exit country', validator: _required)),
          ]),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Notify on failover / failback / both tunnels down'),
            value: _cfg.notifyOnFailover,
            onChanged: (v) => setState(() => _cfg = _cfg.copyWith(notifyOnFailover: v)),
          ),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Notify when bypass starts / ends'),
            value: _cfg.notifyOnBypass,
            onChanged: (v) => setState(() => _cfg = _cfg.copyWith(notifyOnBypass: v)),
          ),
          _section('Remote access (WireGuard)'),
          RemoteAccessEditor(
            key: ValueKey('remote-$_remoteGen'),
            controller: widget.controller,
            config: _cfg,
            onChanged: (c) => setState(() => _cfg = c),
          ),
          const SizedBox(height: 16),
          _section('Share settings'),
          const Text('Hand a ready-made setup to another person (no secrets included), or load one.'),
          const SizedBox(height: 8),
          Wrap(spacing: 12, runSpacing: 12, children: [
            OutlinedButton.icon(onPressed: _export, icon: const Icon(Icons.ios_share), label: const Text('Export...')),
            OutlinedButton.icon(onPressed: _import, icon: const Icon(Icons.download), label: const Text('Import...')),
          ]),
          const SizedBox(height: 16),
          if (_message != null)
            Container(
              padding: const EdgeInsets.all(12),
              margin: const EdgeInsets.only(bottom: 12),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(12),
                color: (_messageIsError ? Colors.red : Colors.green).withValues(alpha: 0.12),
              ),
              child: SelectableText(_message!, style: const TextStyle(fontFamily: 'monospace')),
            ),
          Wrap(spacing: 12, runSpacing: 12, children: [
            FilledButton.icon(
              onPressed: _busy ? null : _save,
              icon: const Icon(Icons.save),
              label: const Text('Save'),
            ),
            OutlinedButton.icon(
              onPressed: _busy ? null : _testConnection,
              icon: const Icon(Icons.network_check),
              label: const Text('Test connection & privileges'),
            ),
          ]),
          if (_autostart != null) ...[
            const SizedBox(height: 24),
            _section('App'),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Start Cybervulcan in the tray when I sign in'),
              subtitle: const Text('Applies straight away.'),
              value: _autostart!,
              onChanged: (v) async {
                final ok = await WindowsAutostart.setEnabled(v);
                final now = await WindowsAutostart.isEnabled();
                if (!mounted) return;
                setState(() => _autostart = now);
                if (!ok) _say('Could not change the startup setting.', error: true);
              },
            ),
          ],
          if (widget.updates != null) ...[
            const SizedBox(height: 24),
            _section('Updates'),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Check for updates automatically'),
              subtitle: const Text('At start-up and every 12 hours. Save to apply.'),
              value: _cfg.checkUpdates,
              onChanged: (v) => setState(() => _cfg = _cfg.copyWith(checkUpdates: v)),
            ),
            UpdateSettingsCard(updates: widget.updates!),
          ],
          const SizedBox(height: 32),
        ],
      ),
    );
  }

  Widget _section(String title) => Padding(
        padding: const EdgeInsets.only(top: 8, bottom: 12),
        child: Text(title, style: Theme.of(context).textTheme.titleMedium),
      );
}

class _Warning extends StatelessWidget {
  const _Warning(this.text);
  final String text;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Icon(Icons.warning_amber_rounded, color: OpnColors.amber, size: 20),
          const SizedBox(width: 8),
          Expanded(child: Text(text, style: const TextStyle(color: OpnColors.amber))),
        ]),
      );
}
