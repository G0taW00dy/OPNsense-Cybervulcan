import 'package:flutter/material.dart';

import '../api/opnsense_client.dart';
import '../api/tls.dart';
import '../core/client_factory.dart';
import '../core/config.dart';
import '../core/network_map.dart';
import '../core/controller.dart';
import '../core/bypass.dart';
import '../core/storage.dart';
import '../core/updater.dart';
import '../platform/autostart.dart';
import 'format.dart';
import 'help_page.dart';
import 'update_widgets.dart';

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
        baseUrl: _v('baseUrl'),
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
    final uri = Uri.tryParse(_v('baseUrl'));
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
    final client = buildRouterClient(_collect(), creds);
    if (client == null) {
      _say('Enter the base URL, API key and secret first.', error: true);
      return;
    }
    setState(() => _busy = true);
    final results = <String>[];
    Future<void> probe(String name, Future<Object?> Function() f) async {
      try {
        await f();
        results.add('OK    $name');
      } on OpnsenseException catch (e) {
        results.add('${e.kind == ApiErrorKind.forbidden ? 'NO PRIVILEGE' : 'FAIL'}  $name: ${e.message}');
      }
    }

    final cfg = _collect();
    await probe('Gateway status', client.gatewayStatus);
    await probe('Bypass alias ${cfg.bypassAlias}', () => client.aliasList(cfg.bypassAlias));
    await probe('PC mode alias ${cfg.pcModeAlias}', () => client.aliasList(cfg.pcModeAlias));
    await probe('DHCP leases', client.dnsmasqLeases);
    await probe('Kill switch rule search', () => client.searchRules(cfg.killSwitchTag));
    client.close();
    if (!mounted) return;
    setState(() => _busy = false);
    _say(results.join('\n'), error: results.any((r) => !r.startsWith('OK')));
  }

  Widget _field(String key, String label, {String? help, String? Function(String?)? validator, bool number = false}) =>
      Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: TextFormField(
          controller: _t[key],
          decoration: InputDecoration(labelText: label, helperText: help, helperMaxLines: 3),
          keyboardType: number ? TextInputType.number : TextInputType.text,
          validator: validator,
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
            const Text('Connect to your OPNsense router with the API key of the "pcmode" user '
                '(System > Access > Users > pcmode > API keys). See the README for the '
                'privileges it needs.'),
            const SizedBox(height: 16),
          ],
          _section('Router'),
          _field('baseUrl', 'Router base URL', help: 'e.g. https://10.10.10.254', validator: (v) {
            final u = Uri.tryParse(v?.trim() ?? '');
            return u == null || u.host.isEmpty || !(u.scheme == 'http' || u.scheme == 'https')
                ? 'Must be http(s)://host'
                : null;
          }),
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
              validator: (v) => canonicalCidr(v ?? '') == null ? 'CIDR, e.g. 10.10.40.0/24' : null),
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
          _field('pcModeAlias', 'PC mode (CLEAR) alias', validator: _alias),
          _field('pcIpOverride', 'This PC\'s IP (blank = auto-detect)',
              validator: (v) => (v == null || v.trim().isEmpty || ipv4ToInt(v) != null) ? null : 'IPv4 address'),
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
