import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../api/opnsense_client.dart';
import '../api/shaper_models.dart';
import '../api/tls.dart';
import '../core/bypass.dart';
import '../core/client_factory.dart';
import '../core/config.dart';
import '../core/controller.dart';
import '../core/network_map.dart';
import '../core/providers.dart';
import '../core/schedule.dart';
import '../core/settings_transfer.dart';
import '../core/storage.dart';
import '../core/updater.dart';
import '../net/router_link.dart';
import '../net/tailscale_engine.dart';
import '../platform/app_lock.dart';
import '../platform/autostart.dart';
import 'format.dart';
import 'help_page.dart';
import 'remote_access.dart';
import 'remote_engine_settings.dart';
import 'remote_modes_editor.dart';
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
      ? 'e.g. https://router.example.com or https://192.168.1.1'
      : null;
}

String? validateCertName(String? v) {
  final n = v?.trim() ?? '';
  if (n.isEmpty) return null;
  return RegExp(r'^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$')
          .hasMatch(n)
      ? null
      : 'A host name, e.g. router.example.com';
}

/// Runs the identity check and every endpoint with the given settings.
/// Returns report lines; the first says how the router was reached.
Future<List<String>> testRouterConnection(AppConfig cfg, ApiCredentials? creds, {RouterLink? link}) async {
  final target = RouterTarget.fromConfig(cfg);
  if (target == null) return ['FAIL  Router address is not valid'];
  var route = RouterRoute.direct(target.host, target.port);
  var probe = await probeRouter(target, route, const Duration(seconds: 4));
  final lines = <String>[];
  // Away from home: reuse the remote route the app is already connected on
  // (Tailscale or the in-app tunnel) instead of failing on the home address.
  if (probe.kind == ProbeKind.unreachable && link != null && link.status.connected && link.status.remote) {
    final remote = link.routeFor(target);
    final viaRemote = await probeRouter(target, remote, const Duration(seconds: 8));
    if (viaRemote.kind != ProbeKind.unreachable) {
      route = remote;
      probe = viaRemote;
      lines.add('INFO  Away from home - tested through '
          '${link.status.viaTailscale ? 'Tailscale' : 'the remote access tunnel'}');
    }
  }
  switch (probe.kind) {
    case ProbeKind.ok:
      lines.add(target.secure
          ? 'OK    Certificate valid for ${target.tlsName}${target.pinned ? ' (pinned)' : ''}'
          : 'WARN  Plain http:// - no certificate check, API key sent unencrypted');
    case ProbeKind.wrongCertificate:
      return [...lines, 'FAIL  Wrong certificate - not your router? ${probe.detail ?? ''}',
        '      The API key was NOT sent.'];
    case ProbeKind.unreachable:
      return ['FAIL  ${target.host}:${target.port} did not answer (${probe.detail ?? 'timeout'}).',
        link != null && link.status.remote
            ? '      Remote access did not answer either - check the Status page.'
            : '      At home? Check the address. Away? Open the Status page first so the app '
                'connects through remote access, then test again.'];
  }
  final picked = route;
  final client = buildRouterClient(cfg, creds, route: (_) => picked);
  if (client == null) return [...lines, 'FAIL  Enter the API key and secret first'];
  // Setup checker (v2.1): not only "can I call it" but "is it set up the
  // way the app expects", with the fix in the line.
  final powers = <String>[];
  Future<T?> check<T>(String name, Future<T> Function() f,
      {bool optional = false, String? power, String? Function(T)? verify}) async {
    try {
      final r = await f();
      final problem = verify?.call(r);
      lines.add(problem == null ? 'OK    $name' : 'FIX   $name: $problem');
      if (power != null) powers.add(power);
      return r;
    } on OpnsenseException catch (e) {
      final tag = e.kind == ApiErrorKind.forbidden ? (optional ? 'SKIP ' : 'NO PRIVILEGE') : 'FAIL';
      lines.add('$tag  $name: ${e.kind == ApiErrorKind.forbidden && optional ? 'not granted (optional)' : e.message}');
      return null;
    }
  }

  await check('Gateway status', client.gatewayStatus, verify: (gws) {
    final names = gws.map((g) => g.name).toSet();
    final missing = [cfg.mainGateway, cfg.backupGateway].where((n) => !names.contains(n)).toList();
    return missing.isEmpty
        ? null
        : 'gateway ${missing.join(' and ')} not found - check the names in Settings > VPN tunnels '
            '(router: System > Gateways)';
  });
  await check('Bypass alias ${cfg.bypassAlias}', () => client.aliasList(cfg.bypassAlias), power: 'turn the whole-house bypass on/off');
  await check('CLEAR alias ${cfg.pcModeAlias}', () => client.aliasList(cfg.pcModeAlias), power: 'put single devices on CLEAR');
  await check('DHCP leases (devices, new-device alerts)', client.dnsmasqLeases, optional: true, power: 'see device names');
  await check('Kill switch rule (tag ${cfg.killSwitchTag})', () => client.searchRules(cfg.killSwitchTag),
      optional: true,
      verify: (rules) => rules.isEmpty
          ? 'no firewall rule with that tag - without it the VPN network is not protected when both tunnels drop'
          : null);
  await check('WireGuard peers (server switcher)', client.wgPeers,
      optional: !cfg.serverSwitcherEnabled,
      power: 'change VPN servers (and read the router\'s WireGuard keys)', verify: (peers) {
    final missing = [cfg.mainWgInstance, cfg.backupWgInstance].where((i) => !peers.any((p) => p.belongsTo(i))).toList();
    return !cfg.serverSwitcherEnabled || missing.isEmpty
        ? null
        : 'no peer linked to instance ${missing.join(' / ')} - check the instance names, or tick the instance on the '
            'peer (VPN > WireGuard > Peers)';
  });
  if (cfg.serverSwitcherEnabled) {
    await check('Route refresh after a server switch', client.routesProbe,
        optional: true, power: 'change static routes');
    await check('Gateway monitor restart after a server switch', client.servicesProbe,
        optional: true, power: 'restart router services');
  }
  await check('Shaper (lag control)', client.shaperPipes,
      optional: !cfg.shaperAutoTune,
      power: 'change the shaper limits',
      verify: (pipes) => findVpnPipes(pipes) == null
          ? 'no enabled pipes named with "VPN" and "download"/"upload" (Firewall > Shaper > Pipes)'
          : null);
  await check('Unbound DNS-over-TLS (Tests page)', client.dotServers, optional: true);
  lines.add('');
  lines.add('INFO  This key can: ${powers.isEmpty ? 'read the status only' : powers.join('; ')}.');
  if (powers.any((p) => p.contains('VPN servers') || p.contains('shaper') || p.contains('routes') || p.contains('services'))) {
    lines.add('INFO  Keys for other people should only have Gateways + Diagnostics: Tables (status, bypass, CLEAR).');
  }
  client.close();
  return lines;
}

/// v2.0 settings: fold-out sections, a "?" with a plain explanation next to
/// every field, Save / Test always at hand. Secrets go to secure storage only.
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
  bool? _tailscaleHere;
  bool _dirty = false;

  CybervulcanController get c => widget.controller;

  @override
  void initState() {
    super.initState();
    _cfg = c.config;
    if (WindowsAutostart.supported) {
      WindowsAutostart.isEnabled().then((v) {
        if (mounted) setState(() => _autostart = v);
      });
    }
    unawaited(_refreshPin());
    unawaited(c.refreshShaperInfo().then((_) {
      if (mounted) setState(() {});
    }));
    tailscaleActiveOnDevice().then((v) {
      if (mounted) setState(() => _tailscaleHere = v);
    });
    _t = {for (final k in _textKeys) k: TextEditingController()};
    _reload();
    _dirty = false;
  }

  static const _textKeys = [
    'baseUrl', 'certName', 'routerLanIp', 'vpnName', 'directLabel', 'directNetworkName', 'networks',
    'mainGateway', 'backupGateway', 'mainLabel', 'backupLabel', 'pcModeAlias', 'bypassAlias',
    'bypassNetwork', 'bypassMinutes', 'pcIpOverride', 'killSwitchTag', 'killSwitchRuleUuid',
    'pollSeconds', 'homeCountryCode', 'vpnCountryCode', 'tailscaleAddress', 'mainWgInstance',
    'backupWgInstance', 'serverCities', 'schedStart', 'schedMinutes', 'mainKeyExpiry', 'backupKeyExpiry',
    'shaperMinDown', 'shaperMaxDown', 'shaperMinUp', 'shaperMaxUp',
  ];

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
        routerLanIp: _v('routerLanIp'),
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
        tailscaleAddress: _v('tailscaleAddress'),
        mainWgInstance: _v('mainWgInstance'),
        backupWgInstance: _v('backupWgInstance'),
        serverCities: _v('serverCities'),
        schedStart: _v('schedStart'),
        schedMinutes: int.tryParse(_v('schedMinutes')) ?? 180,
        mainKeyExpiry: _v('mainKeyExpiry'),
        backupKeyExpiry: _v('backupKeyExpiry'),
        shaperMinDown: int.tryParse(_v('shaperMinDown')) ?? _cfg.shaperMinDown,
        shaperMaxDown: int.tryParse(_v('shaperMaxDown')) ?? _cfg.shaperMaxDown,
        shaperMinUp: int.tryParse(_v('shaperMinUp')) ?? _cfg.shaperMinUp,
        shaperMaxUp: int.tryParse(_v('shaperMaxUp')) ?? _cfg.shaperMaxUp,
      );

  /// Refills every text field from [_cfg] (start, after an import).
  void _reload() {
    final cfg = _cfg;
    final m = {
      'baseUrl': cfg.baseUrl,
      'certName': cfg.certName,
      'routerLanIp': cfg.routerLanIp,
      'vpnName': cfg.vpnName,
      'directLabel': cfg.directLabel,
      'directNetworkName': cfg.directNetworkName,
      'networks': networksToText(cfg.networks),
      'mainGateway': cfg.mainGateway,
      'backupGateway': cfg.backupGateway,
      'mainLabel': cfg.mainLabel,
      'backupLabel': cfg.backupLabel,
      'pcModeAlias': cfg.pcModeAlias,
      'bypassAlias': cfg.bypassAlias,
      'bypassNetwork': cfg.bypassNetwork,
      'bypassMinutes': isNoLimitDuration(cfg.bypassDuration) ? '0' : '${cfg.bypassDuration.inMinutes}',
      'pcIpOverride': cfg.pcIpOverride ?? '',
      'killSwitchTag': cfg.killSwitchTag,
      'killSwitchRuleUuid': cfg.killSwitchRuleUuid ?? '',
      'pollSeconds': '${cfg.pollInterval.inSeconds}',
      'homeCountryCode': cfg.homeCountryCode,
      'vpnCountryCode': cfg.vpnCountryCode,
      'tailscaleAddress': cfg.tailscaleAddress,
      'mainWgInstance': cfg.mainWgInstance,
      'backupWgInstance': cfg.backupWgInstance,
      'serverCities': cfg.serverCities,
      'schedStart': cfg.schedStart,
      'schedMinutes': '${cfg.schedMinutes}',
      'mainKeyExpiry': cfg.mainKeyExpiry,
      'backupKeyExpiry': cfg.backupKeyExpiry,
      'shaperMinDown': '${cfg.shaperMinDown}',
      'shaperMaxDown': '${cfg.shaperMaxDown}',
      'shaperMinUp': '${cfg.shaperMinUp}',
      'shaperMaxUp': '${cfg.shaperMaxUp}',
    };
    for (final e in m.entries) {
      _t[e.key]!.text = e.value;
    }
    _remoteGen++;
  }

  int _remoteGen = 0;

  void _set(AppConfig cfg) => setState(() {
        _cfg = cfg;
        _dirty = true;
      });

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
    if (!_form.currentState!.validate()) {
      _say('Some fields need fixing - look for the red text in the open sections.', error: true);
      return;
    }
    final creds = _newCreds();
    if (creds != null && !creds.isComplete) {
      _say('Enter both the API key and the API secret.', error: true);
      return;
    }
    if (!c.hasCredentials && creds == null) {
      _say('API key and secret are required.', error: true);
      return;
    }
    // Saving can loosen protection (e.g. turn the app lock off): ask first.
    if (c.config.appLock && !await c.authorize('Save Cybervulcan settings')) return;
    setState(() => _busy = true);
    await c.saveSettings(_collect(), credentials: creds);
    if (!mounted) return;
    _apiKey.clear();
    _apiSecret.clear();
    _cfg = c.config;
    setState(() {
      _busy = false;
      _dirty = false;
    });
    final err = c.snapshot.error;
    _say(err == null ? 'Saved. Connected to the router.' : 'Saved, but: ${errorHint(err)}', error: err != null);
  }

  /// Trust-on-first-use for a self-signed router certificate.
  Future<void> _trustCertificate() async {
    final uri = Uri.tryParse(normaliseRouterAddress(_v('baseUrl')));
    if (uri == null || uri.scheme != 'https' || uri.host.isEmpty) {
      _say('Certificate pinning only applies to an https:// address.', error: true);
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
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Trust this router certificate?'),
        content: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Compare the SHA-256 fingerprint with the one shown on the router '
                '(System > Trust > Certificates, or the browser\'s certificate viewer) before trusting it.'),
            const SizedBox(height: 12),
            SelectableText(cert.fingerprint, style: const TextStyle(fontFamily: 'monospace', fontSize: 13)),
            const SizedBox(height: 12),
            Text('Subject: ${cert.subject}'),
            Text('Issuer: ${cert.issuer}'),
            Text('Valid: ${cert.validFrom.toLocal()} - ${cert.validTo.toLocal()}'),
          ]),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Trust')),
        ],
      ),
    );
    if (ok != true) return;
    _set(_cfg.copyWith(pinnedCertSha256: cert.fingerprint));
    _say('Certificate pinned. Press Save to apply.');
  }

  Future<void> _testConnection() async {
    if (!_form.currentState!.validate()) return;
    final creds = _newCreds() ?? await c.secrets.read();
    if (!mounted) return;
    setState(() => _busy = true);
    final results = await testRouterConnection(_collect(), creds, link: c.link);
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
                'pre-shared key, and none of your personal preferences. The other person enters '
                'their own API key and makes their own WireGuard key on their device.'),
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
            onPressed: () => showQrDialog(ctx, title: 'Settings (no secrets)', text: exportSettings(_collect(), pretty: false)),
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
    final text = await pasteOrOpenText(context, title: 'Import settings', hint: 'Paste the settings text you were given (JSON).');
    if (text == null || text.trim().isEmpty || !mounted) return;
    try {
      final r = importSettings(text, _collect());
      setState(() {
        _cfg = r.config;
        _dirty = true;
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

  AppLock get _lock => AppLock(store: c.secrets, context: () => mounted ? context : null);

  bool? _hasAppPin;

  Future<void> _refreshPin() async {
    final v = await _lock.hasAppPin();
    if (mounted) setState(() => _hasAppPin = v);
  }

  Future<void> _toggleAppLock(bool on) async {
    if (on) {
      final lock = _lock;
      if (!await lock.available()) {
        _say(
            Platform.isWindows
                ? 'Windows Hello is not set up on this PC - set an app PIN below first (or set up Windows Hello '
                    'in Windows Settings > Accounts > Sign-in options).'
                : 'This phone has no screen lock - set an app PIN below first (or a screen lock in Android Settings).',
            error: true);
        return;
      }
      if (!await lock.authorize('Turn on the Cybervulcan app lock')) return;
    } else if (!await c.authorize('Turn off the Cybervulcan app lock', always: true)) {
      return;
    }
    _set(_cfg.copyWith(appLock: on));
  }

  Future<void> _setPin() async {
    if (_hasAppPin == true && !await c.authorize('Change the app PIN', always: true)) return;
    if (!mounted) return;
    if (await _lock.setAppPin(context)) {
      _say('App PIN saved. It works as a backup whenever the fingerprint prompt has no PIN option.');
    }
    await _refreshPin();
  }

  Future<void> _removePin() async {
    if (!await c.authorize('Remove the app PIN', always: true)) return;
    await _lock.removeAppPin();
    _say('App PIN removed.');
    await _refreshPin();
  }

  // ------------------------------------------------------------- widgets

  Widget _field(String key, String label,
          {String? help, String? hint, String? note, String? Function(String?)? validator, bool number = false}) =>
      Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: TextFormField(
          controller: _t[key],
          decoration: InputDecoration(
            labelText: label,
            hintText: hint,
            helperText: note,
            helperMaxLines: 3,
            suffixIcon: help == null ? null : HelpButton(title: label, text: help),
          ),
          keyboardType: number ? TextInputType.number : TextInputType.text,
          validator: validator,
          onChanged: (_) => setState(() => _dirty = true),
        ),
      );

  Widget _switch(String title, bool value, ValueChanged<bool> onChanged, {String? subtitle, String? help}) =>
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        title: Row(children: [
          Flexible(child: Text(title)),
          if (help != null) HelpButton(title: title, text: help, small: true),
        ]),
        subtitle: subtitle == null ? null : Text(subtitle),
        value: value,
        onChanged: onChanged,
      );

  String? _dateOrEmpty(String? v) {
    final s = v?.trim() ?? '';
    if (s.isEmpty) return null;
    return parseIsoDate(s) == null ? 'Use a real date as yyyy-mm-dd' : null;
  }

  String? _required(String? v) => (v == null || v.trim().isEmpty) ? 'Required' : null;

  String? _alias(String? v) =>
      RegExp(r'^[A-Za-z0-9_]{1,32}$').hasMatch(v?.trim() ?? '') ? null : 'Letters, digits, _ only';

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final hasCreds = c.hasCredentials;
    final isPhone = Platform.isAndroid;
    final deviceNoun = isPhone ? 'phone' : 'PC';
    final routerSummary = [
      normaliseRouterAddress(_v('baseUrl')),
      hasCreds ? 'API key stored' : 'no API key',
    ].join(' - ');

    final sections = <Widget>[
      // 1 ------------------------------------------------------------ router
      SettingsSection(
        icon: Icons.router_outlined,
        title: 'Router connection',
        summary: routerSummary,
        initiallyExpanded: widget.firstRun || !hasCreds,
        children: [
          _field('baseUrl', 'Router URL',
              hint: 'https://router.example.com',
              help: 'Where the app finds your router. Best is the router\'s own name (e.g. '
                  'https://router.example.com) if it has a real certificate (e.g. Let\'s Encrypt): it is '
                  'then checked normally and the same address works at home and through remote access. '
                  'An IP (e.g. https://192.168.1.1) works too - then set the certificate name below or pin '
                  'the certificate.',
              validator: validateRouterAddress),
          if (_v('certName').isNotEmpty &&
              validateCertName(_v('certName')) == null &&
              !_v('certName').startsWith('*') &&
              (Uri.tryParse(normaliseRouterAddress(_v('baseUrl')))?.host ?? '') != _v('certName'))
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                onPressed: () => setState(() {
                  final lan = Uri.tryParse(normaliseRouterAddress(_v('baseUrl')))?.host ?? '';
                  if (_v('routerLanIp').isEmpty && ipv4ToInt(lan) != null) _t['routerLanIp']!.text = lan;
                  _t['baseUrl']!.text = 'https://${_v('certName')}';
                  _dirty = true;
                }),
                icon: const Icon(Icons.auto_fix_high, size: 18),
                label: Text('Use https://${_v('certName')}'),
              ),
            ),
          if (normaliseRouterAddress(_v('baseUrl')).startsWith('http://'))
            const WarningLine('Plain http:// sends the API key unencrypted and cannot prove this is your router. '
                'Use https:// once the router has its certificate.'),
          TextFormField(
            controller: _apiKey,
            decoration: InputDecoration(
              labelText: 'API key',
              helperText: hasCreds ? 'Stored securely. Leave blank to keep the current key.' : null,
              suffixIcon: const HelpButton(
                  title: 'API key',
                  text: 'Your own key for the router (System > Access > Users > your app user > API keys). '
                      'One user per person, e.g. alex-app / sam-app, with only the privileges the app needs. '
                      'Kept in Windows Credential Manager / the Android Keystore, never shown again or exported.'),
            ),
            autocorrect: false,
            enableSuggestions: false,
            onChanged: (_) => setState(() => _dirty = true),
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _apiSecret,
            obscureText: !_showSecret,
            autocorrect: false,
            enableSuggestions: false,
            onChanged: (_) => setState(() => _dirty = true),
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
                onPressed: _busy
                    ? null
                    : () async {
                        await c.forgetCredentials();
                        if (mounted) setState(() {});
                      },
                icon: const Icon(Icons.delete_outline),
                label: const Text('Forget stored API key'),
              ),
            ),
          const SizedBox(height: 4),
          SubSection(title: 'Certificate & remote target', children: [
            _field('certName', 'Certificate name',
                help: 'The router\'s certificate must be valid for this name. If it is not, the app refuses '
                    'to connect and never sends the API key - protection against a fake router. Leave '
                    'empty to check against the router URL itself (or use a pin).',
                validator: validateCertName),
            Row(children: [
              Expanded(
                child: Text(
                  _cfg.pinnedCertSha256 == null
                      ? 'No pinned certificate (CA-trusted certificates only).'
                      : 'Pinned SHA-256: ${_cfg.pinnedCertSha256}',
                  style: t.bodySmall,
                ),
              ),
              TextButton(onPressed: _busy ? null : _trustCertificate, child: const Text('Pin...')),
              if (_cfg.pinnedCertSha256 != null)
                TextButton(onPressed: () => _set(_cfg.copyWith(clearPin: true)), child: const Text('Forget')),
            ]),
            const SizedBox(height: 8),
            _field('routerLanIp', 'Router LAN IP',
                help: 'The router\'s address on your home network (e.g. 192.168.1.1). Only needed when the '
                    'router URL is a name: remote access through '
                    'WireGuard needs an IP to reach, even when the router URL is a name.',
                validator: (v) => (v ?? '').trim().isEmpty || ipv4ToInt(v ?? '') != null
                    ? null
                    : 'IPv4 address, e.g. 192.168.1.1'),
          ]),
        ],
      ),

      // 2 ----------------------------------------------------------- tunnels
      SettingsSection(
        icon: Icons.vpn_lock_outlined,
        title: 'VPN tunnels & servers',
        summary: '${_cfg.mainLabel} main, ${_cfg.backupLabel} backup'
            '${_cfg.serverSwitcherEnabled ? ' - server switcher on' : ''}',
        children: [
          _field('vpnName', 'VPN provider name',
              help: 'Only used in texts, e.g. "back on Proton".', validator: _required),
          Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: DropdownButtonFormField<String>(
              initialValue: _cfg.providerId,
              decoration: const InputDecoration(
                labelText: 'Provider profile',
                suffixIcon: HelpButton(
                    title: 'Provider profile',
                    text: 'Tells the server switcher where servers come from.\n\n'
                        'Proton VPN: add servers by scanning the QR code (phone) or pasting the [Peer] part of a '
                        'config from account.protonvpn.com - Proton closed its public server list in 2025.\n\n'
                        'Mullvad: the app downloads Mullvad\'s public server list.\n\n'
                        'Other: any WireGuard provider - add servers from its config files. The router keeps its '
                        'own key, so the provider must accept one key on all its servers (most do); the app checks '
                        'for a real handshake and puts the old server back if not.\n\n'
                        'Everything else in the app (tunnels, failover, kill switch, bypass, tests) works with any '
                        'WireGuard provider.'),
              ),
              items: [
                for (final p in ProviderProfile.all) DropdownMenuItem(value: p.id, child: Text(p.name)),
              ],
              onChanged: (v) => _set(_cfg.copyWith(vpnProvider: v)),
            ),
          ),
          Row(children: [
            Expanded(
                child: _field('mainGateway', 'Main gateway',
                    help: 'Gateway name on the router (System > Gateways), e.g. WG_MAIN_GW.', validator: _required)),
            const SizedBox(width: 12),
            Expanded(child: _field('mainLabel', 'Shown as', help: 'Friendly name, e.g. the server\'s city.', validator: _required)),
          ]),
          Row(children: [
            Expanded(
                child: _field('backupGateway', 'Backup gateway',
                    help: 'The failover gateway, e.g. WG_BACKUP_GW.', validator: _required)),
            const SizedBox(width: 12),
            Expanded(child: _field('backupLabel', 'Shown as', help: 'e.g. the backup server\'s city.', validator: _required)),
          ]),
          SubSection(title: 'Tunnel key expiry', children: [
            Row(children: [
              Expanded(
                  child: _field('mainKeyExpiry', 'Main key expires',
                      hint: 'yyyy-mm-dd',
                      validator: _dateOrEmpty,
                      help: 'Some providers give each router config an expiry date (Proton: shown next to the config '
                          'name under Downloads > WireGuard configuration). When it passes, that tunnel stops - and '
                          'if both stop, the kill switch blocks the VPN network. The app warns 30, 7 and 1 day(s) '
                          'before. Empty = no warning.')),
              const SizedBox(width: 12),
              Expanded(
                  child: _field('backupKeyExpiry', 'Backup key expires',
                      hint: 'yyyy-mm-dd', validator: _dateOrEmpty, help: 'Same for the backup tunnel\'s config.')),
            ]),
          ]),
          _switch('Server switcher', _cfg.serverSwitcherEnabled, (v) => _set(_cfg.copyWith(serverSwitcherEnabled: v)),
              subtitle: 'Change the exit city from the app, or let it find the fastest server.',
              help: 'Adds a "VPN servers" card to Status. It changes which provider server each tunnel '
                  'connects to (address + the server\'s public key). The router\'s private keys never '
                  'leave the router.\n\nNeeds the router privilege "VPN: WireGuard" on YOUR app user '
                  'only (not on keys you give to others). Note: that privilege can also read the WireGuard keys, so keep the '
                  'app lock on.'),
          if (_cfg.serverSwitcherEnabled) ...[
            Row(children: [
              Expanded(
                  child: _field('mainWgInstance', 'Main instance',
                      help: 'WireGuard instance behind the main gateway (VPN > WireGuard > Instances), '
                          'e.g. VPN_Main.',
                      validator: _required)),
              const SizedBox(width: 12),
              Expanded(
                  child: _field('backupWgInstance', 'Backup instance',
                      help: 'Instance behind the backup gateway, e.g. VPN_Backup. "Find best" tests '
                          'candidates on this one, so the house never loses its main tunnel while testing.',
                      validator: _required)),
            ]),
            _field('serverCities', 'Cities to choose from',
                help: 'Comma-separated cities "find best" may pick, e.g. "Chicago, New York". Empty = any. '
                    'Keeps streaming regions predictable.',
                hint: 'Chicago, New York'),
            _switch('Find the best server every night', _cfg.autoBestNightly,
                (v) => _set(_cfg.copyWith(autoBestNightly: v)),
                subtitle: 'Between 3 and 5 am, while this app is running (best on the always-on PC).',
                help: 'Tests a few servers on the backup tunnel, then moves the fastest to main if it is '
                    'clearly better (at least 10 %). Takes about 5 minutes. You get a notification with the result.'),
          ],
          SubSection(title: 'Shaper (lag control)', children: [
            InfoLine(c.shaperPipes == null
                ? (c.tuner.lastReason ?? 'Reading the router\'s shaper limits ...')
                : c.shaperPipes!.isEmpty
                    ? 'The router has no shaper limits set up (Firewall > Shaper).'
                    : 'Limits now: ${c.shaperPipes!.map((p) => '${p.description} ${p.mbit.round()}').join(' · ')} Mbit/s.'
                        '${c.tuner.lastReason == null ? '' : ' Last check: ${c.tuner.lastReason}'}'),
            _switch('Auto-tune the shaper', _cfg.shaperAutoTune, (v) => _set(_cfg.copyWith(shaperAutoTune: v)),
                subtitle: 'Lower the VPN limits when lag rises under load, raise them when it\'s clear.',
                help: 'Mobile lines change speed all the time, so a fixed shaper limit is either too high (lag) or '
                    'too low (wasted speed). Auto-tune watches the tunnel\'s ping (the router\'s gateway monitor) and '
                    'how busy each direction is, and moves the VPN limits within the range below - about every '
                    '30 seconds at most. After a server switch it starts again, because each server has its own '
                    'speed and ping.\n\nRun it on ONE device only (best: the always-on PC). Needs the router '
                    'privilege "Firewall: Shaper" on this app user, and shaper pipes named with "VPN" and '
                    '"download"/"upload". The original limits are saved first: "Restore original limits" puts '
                    'them back, and the app does so by itself if tuning keeps failing.'),
            if (_cfg.shaperAutoTune) ...[
              Row(children: [
                Expanded(child: _field('shaperMinDown', 'Download min', number: true, note: 'Mbit/s')),
                const SizedBox(width: 12),
                Expanded(child: _field('shaperMaxDown', 'Download max', number: true, note: 'Mbit/s')),
              ]),
              Row(children: [
                Expanded(child: _field('shaperMinUp', 'Upload min', number: true, note: 'Mbit/s')),
                const SizedBox(width: 12),
                Expanded(child: _field('shaperMaxUp', 'Upload max', number: true, note: 'Mbit/s')),
              ]),
            ],
            Wrap(spacing: 8, runSpacing: 8, children: [
              OutlinedButton.icon(
                  onPressed: () async {
                    await c.retuneShaper();
                    await c.refreshShaperInfo();
                    if (mounted) setState(() {});
                  },
                  icon: const Icon(Icons.tune),
                  label: const Text('Re-tune now')),
              if (c.shaperOriginal != null)
                OutlinedButton.icon(
                    onPressed: () async {
                      await c.restoreShaperOriginal();
                      await c.refreshShaperInfo();
                      if (mounted) setState(() {});
                    },
                    icon: const Icon(Icons.undo),
                    label: Text('Restore original limits (${c.shaperOriginal!.values.join(' / ')})')),
            ]),
          ]),
        ],
      ),

      // 3 ------------------------------------------------- bypass & device
      SettingsSection(
        icon: Icons.public_off_outlined,
        title: 'Bypass & $deviceNoun mode',
        summary: 'Default ${isNoLimitDuration(_cfg.bypassDuration) ? 'no limit' : '${_cfg.bypassDuration.inMinutes} min'}'
            ' - schedule: ${describeSchedule(_cfg)}',
        children: [
          _field('bypassMinutes', 'Default bypass length (minutes)',
              number: true,
              help: 'How long the whole-house bypass lasts unless you pick another length. 0 = no time limit '
                  '(stays off the VPN until someone turns it back on).',
              validator: (v) {
                final n = int.tryParse(v ?? '');
                return n != null && (n == 0 || n >= 5) ? null : '0, or at least 5';
              }),
          _switch('Store the deadline on the router', _cfg.useExpiryMarker, (v) => _set(_cfg.copyWith(useExpiryMarker: v)),
              help: 'Adds a marker (240.x.x.x) to the bypass table so the router\'s own timer ends the bypass '
                  'on time even when every app is closed. Harmless: that range never appears on the LAN.'),
          if (!_cfg.useExpiryMarker)
            const WarningLine('Off: the bypass only ends while a Cybervulcan app is running. Leave this on.'),
          SubSection(title: 'Scheduled bypass', children: [
            _switch('Bypass on a schedule', _cfg.schedBypassEnabled, (v) => _set(_cfg.copyWith(schedBypassEnabled: v)),
                help: 'Turns the whole-house bypass on automatically, e.g. for TV in the evening, and lets the '
                    'normal timer end it. Runs from this device while the app is running.'),
            if (_cfg.schedBypassEnabled) ...[
              Wrap(spacing: 6, runSpacing: 6, children: [
                for (var d = 1; d <= 7; d++)
                  FilterChip(
                    label: Text(weekdayShort[d - 1]),
                    selected: _cfg.schedDays & weekdayBit(d) != 0,
                    onSelected: (on) => _set(_cfg.copyWith(
                        schedDays: on ? _cfg.schedDays | weekdayBit(d) : _cfg.schedDays & ~weekdayBit(d))),
                  ),
              ]),
              const SizedBox(height: 12),
              Row(children: [
                Expanded(
                  child: _field('schedStart', 'Start (24 h)',
                      hint: '19:00',
                      help: 'Local time the bypass starts, e.g. 19:00.',
                      validator: (v) => parseClock(v ?? '') == null ? 'HH:MM' : null),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: _field('schedMinutes', 'Length (minutes)',
                      number: true,
                      help: 'How long it stays on, e.g. 180 for 3 hours.',
                      validator: (v) => (int.tryParse(v ?? '') ?? 0) >= 5 ? null : 'At least 5'),
                ),
              ]),
              if (_cfg.schedDays == 0) const WarningLine('Pick at least one day.'),
            ],
          ]),
          SubSection(title: 'Router aliases', children: [
            _field('bypassAlias', 'Whole-house bypass alias',
                help: 'The router table the app fills to send the VPN network direct (BYPASS_ALL).', validator: _alias),
            _field('bypassNetwork', 'VPN network to bypass',
                help: 'The network the bypass applies to, e.g. 10.10.40.0/24.',
                validator: (v) {
                  final net = Ipv4Subnet.tryParse(v ?? '');
                  if (net == null || !(v ?? '').contains('/')) return 'CIDR, e.g. 10.10.40.0/24';
                  if (net.prefix < 16) return 'Prefix must be /16 or longer';
                  return null;
                }),
            _field('pcModeAlias', 'CLEAR alias',
                help: 'Router table for single devices that go direct (PCMODE_CLEAR). Used by "This PC" and "This phone".',
                validator: _alias),
            _field('pcIpOverride', 'This $deviceNoun\'s IP (blank = auto)',
                help: 'Normally detected automatically from the house network. Only set it if detection picks '
                    'the wrong address.',
                validator: (v) => (v == null || v.trim().isEmpty || ipv4ToInt(v) != null) ? null : 'IPv4 address'),
          ]),
          if (isPhone)
            InfoLine('CLEAR on the phone only helps while the ${_cfg.vpnName} app on the phone is off - otherwise the '
                'phone still tunnels everything itself.'),
        ],
      ),

      // 4 ----------------------------------------------------------- remote
      SettingsSection(
        icon: Icons.travel_explore,
        title: 'Remote access',
        // v2.1: on/off + engine + built-in Tailscale live in RemoteEngineSettings.
        summary: remoteAccessSummary(_cfg, tailscaleHere: _tailscaleHere, deviceNoun: deviceNoun),
        children: [
          RemoteEngineSettings(controller: c, config: _cfg, onChanged: _set),
          const SizedBox(height: 4),
          if (remoteSteps(_cfg).any((s) => s != RemoteStep.wireguard)) ...[
            if (remoteSteps(_cfg).contains(RemoteStep.tailscaleDevice))
              InfoLine(_tailscaleHere == null
                  ? 'Checking for Tailscale on this $deviceNoun...'
                  : _tailscaleHere!
                      ? 'Tailscale is connected on this $deviceNoun.'
                      : 'Tailscale is not connected on this $deviceNoun right now (fine at home).'),
            const SizedBox(height: 8),
            _field('tailscaleAddress', 'Router\'s Tailscale address (optional)',
                hint: '100.x.y.z or opnsense.tailnet.ts.net',
                help: 'Works behind the 5G hotspot\'s CGNAT, no open ports needed.\n\n'
                    'Best: on the router (os-tailscale plugin) advertise a subnet route for the router\'s LAN IP (/32) and '
                    'approve it in the Tailscale admin. Then leave this empty - the normal router URL just works '
                    'through Tailscale.\n\nOtherwise enter the router\'s 100.x address or MagicDNS name here. '
                    'The certificate is still checked against the certificate name.',
                validator: (v) {
                  final s = v?.trim() ?? '';
                  if (s.isEmpty) return null;
                  if (!RegExp(r'^[A-Za-z0-9.:-]+$').hasMatch(s)) return 'An IP or host name';
                  final own = defaultTailscaleHostname().toLowerCase();
                  final low = s.toLowerCase();
                  if (low == own || low.startsWith('$own.')) {
                    return 'That is this $deviceNoun\'s own Tailscale name - enter the router\'s, or leave empty';
                  }
                  return null;
                }),
            if (isPhone && remoteSteps(_cfg).contains(RemoteStep.tailscaleDevice))
              InfoLine('Android allows one VPN app at a time: while the Tailscale app is on, the ${_cfg.vpnName} app '
                  'on the phone is off. The built-in Tailscale engine doesn\'t use that slot.'),
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                onPressed: () => openSetupGuide(context),
                icon: const Icon(Icons.menu_book_outlined, size: 18),
                label: const Text('Router setup steps (guide)'),
              ),
            ),
          ],
          if (remoteSteps(_cfg).contains(RemoteStep.wireguard))
            RemoteAccessEditor(
              key: ValueKey('remote-$_remoteGen'),
              controller: c,
              config: _cfg,
              showToggle: false,
              onChanged: _set,
            ),
          // v2.1: what remote access carries (app only / home devices / everything).
          if (_cfg.remoteEnabled)
            RemoteModesEditor(key: ValueKey('modes-$_remoteGen'), controller: c, config: _cfg, onChanged: _set),
        ],
      ),

      // 5 ----------------------------------------------------------- alerts
      SettingsSection(
        icon: Icons.notifications_none,
        title: 'Alerts & reminders',
        summary: [
          if (_cfg.notifyOnFailover) 'failover',
          if (_cfg.notifyOnBypass) 'bypass',
          if (_cfg.alertNewDevices) 'new devices',
          if (_cfg.backupReminderDays > 0) 'backup every ${_cfg.backupReminderDays} d',
          if (isPhone && _cfg.protonReminder) 'VPN app reminder',
        ].join(', ').let((s) => s.isEmpty ? 'All off' : s),
        children: [
          _switch('Failover, failback, both tunnels down', _cfg.notifyOnFailover,
              (v) => _set(_cfg.copyWith(notifyOnFailover: v)),
              help: 'A notification when the house moves between the main and backup tunnel, or loses both '
                  '(kill switch active). Also used for server-switch results.'),
          _switch('Bypass starts / ends', _cfg.notifyOnBypass, (v) => _set(_cfg.copyWith(notifyOnBypass: v)),
              help: 'Including a reminder every 4 hours while a no-limit bypass is on.'),
          _switch('New device joins the network', _cfg.alertNewDevices, (v) => _set(_cfg.copyWith(alertNewDevices: v)),
              help: 'Checks the router\'s DHCP leases every couple of minutes and tells you when a device it has '
                  'never seen gets an address. The first check just learns what is there. Needs the DHCP '
                  'leases privilege.'),
          if (_cfg.alertNewDevices)
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton(
                onPressed: () async {
                  await c.resetKnownDevices();
                  _say('Known devices forgotten - the next check re-learns them quietly.');
                },
                child: const Text('Forget known devices'),
              ),
            ),
          // v2.1: phone reminder to turn the VPN app off at home / on when away.
          if (isPhone)
            _switch('Remind me about my VPN app', _cfg.protonReminder, (v) => _set(_cfg.copyWith(protonReminder: v)),
                help: 'At home the router already sends everything through '
                    '${_cfg.vpnName.trim().isEmpty ? 'the VPN' : _cfg.vpnName.trim()}, so the VPN app on the phone '
                    'is not needed there. With this on you get a notification when you arrive home with the VPN '
                    'app still on ("you can turn it off"), and when you leave with it off ("turn it back on"). '
                    'Only on changes, at most every 20 minutes.\n\n'
                    'Works while Cybervulcan is running (open or in the background). "Home" means the router '
                    'answers directly, so if your VPN app blocks the local network, allow LAN connections in it.'),
          Row(children: [
            const Expanded(child: Text('Router backup reminder')),
            const HelpButton(
                title: 'Router backup reminder',
                text: 'Reminds you to save an encrypted router config backup (System > Configuration > Backups) '
                    'somewhere safe off the router. Tap "I saved a backup" on the Status page to reset the timer. The app '
                    'never downloads the config itself - that needs far too much access.',
                small: true),
            DropdownButton<int>(
              value: const [0, 7, 14, 30].contains(_cfg.backupReminderDays) ? _cfg.backupReminderDays : 0,
              items: const [
                DropdownMenuItem(value: 0, child: Text('Off')),
                DropdownMenuItem(value: 7, child: Text('Weekly')),
                DropdownMenuItem(value: 14, child: Text('Every 2 weeks')),
                DropdownMenuItem(value: 30, child: Text('Monthly')),
              ],
              onChanged: (v) => _set(_cfg.copyWith(backupReminderDays: v ?? 0)),
            ),
          ]),
          const SizedBox(height: 8),
          _field('pollSeconds', 'Check the router every (seconds)',
              number: true,
              help: 'How often status refreshes. 15 s is a good balance; lower uses a little more battery on the phone.',
              validator: (v) => (int.tryParse(v ?? '') ?? 0) >= 5 ? null : 'At least 5'),
        ],
      ),

      // 6 ------------------------------------------------- security & privacy
      SettingsSection(
        icon: Icons.lock_outline,
        title: 'Security & privacy',
        summary: '${_cfg.appLock ? 'App lock on' : 'App lock off'} - '
            '${_cfg.externalTests ? 'outside test services allowed' : 'router-only tests'}',
        children: [
          _switch('App lock', _cfg.appLock, _toggleAppLock,
              subtitle: Platform.isWindows
                  ? 'Windows Hello or app PIN when the app opens'
                  : 'Fingerprint / face / PIN when the app opens',
              help: 'Unlock once when you open the app (${Platform.isWindows ? 'Windows Hello' : 'fingerprint, face or phone PIN'}, '
                  'or the app PIN below). It locks again after the time you choose in the background. '
                  'Turning the lock off and changing VPN servers always ask again. Shortcuts outside the app '
                  '(${Platform.isWindows ? 'tray menu' : 'widget, quick-settings tile'}) ask before going off the '
                  'VPN unless the app was unlocked a moment ago. Going back on the VPN never asks.'),
          if (_cfg.appLock)
            Row(children: [
              const Expanded(child: Text('Lock again after')),
              DropdownButton<int>(
                value: const [1, 5, 15].contains(_cfg.lockAfterMinutes) ? _cfg.lockAfterMinutes : 5,
                items: const [
                  DropdownMenuItem(value: 1, child: Text('1 min')),
                  DropdownMenuItem(value: 5, child: Text('5 min')),
                  DropdownMenuItem(value: 15, child: Text('15 min')),
                ],
                onChanged: (v) => _set(_cfg.copyWith(lockAfterMinutes: v ?? 5)),
              ),
            ]),
          Row(children: [
            Expanded(
              child: Row(children: [
                Flexible(child: Text(_hasAppPin == true ? 'App PIN: set' : 'App PIN: not set')),
                const HelpButton(
                    title: 'App PIN',
                    text: 'A backup way to unlock, for when the fingerprint prompt offers no PIN option or there is '
                        'no screen lock / Windows Hello. Stored only as a salted hash on this device; never shared or '
                        'exported. 5 wrong tries cancel the unlock.',
                    small: true),
              ]),
            ),
            TextButton(onPressed: _setPin, child: Text(_hasAppPin == true ? 'Change' : 'Set PIN')),
            if (_hasAppPin == true) TextButton(onPressed: _removePin, child: const Text('Remove')),
          ]),
          _switch('Allow outside test services', _cfg.externalTests, (v) => _set(_cfg.copyWith(externalTests: v)),
              help: 'Leak tests need a server on the internet to say where your traffic and DNS really come from '
                  '(ipify, ipwho.is, bash.ws, Akamai, Cloudflare - all HTTPS). On the VPN they only see the '
                  'VPN exit. Off = the Tests page runs router-side checks only.'),
          Row(children: [
            Expanded(
                child: _field('homeCountryCode', 'Home country',
                    help: 'Two-letter code of your ISP\'s country (AU). Seeing it while on the VPN means a leak.',
                    validator: _required)),
            const SizedBox(width: 12),
            Expanded(
                child: _field('vpnCountryCode', 'VPN exit country',
                    help: 'Two-letter code of your VPN servers\' country (US).', validator: _required)),
          ]),
        ],
      ),

      // 7 ---------------------------------------------------------- network
      SettingsSection(
        icon: Icons.lan_outlined,
        title: 'Network layout',
        summary: '${_cfg.networks.length} networks - kill switch tag ${_cfg.killSwitchTag}',
        children: [
          Row(children: [
            Expanded(
                child: _field('directLabel', 'Label while bypassed',
                    help: 'Big status line during a bypass, e.g. Direct (ISP).', validator: _required)),
            const SizedBox(width: 12),
            Expanded(
                child: _field('directNetworkName', 'Direct network',
                    help: 'Which network below always goes straight out (CLEAR). Used for device detection and tests.')),
          ]),
          Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: TextFormField(
              controller: _t['networks'],
              maxLines: null,
              minLines: 3,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
              onChanged: (_) => setState(() => _dirty = true),
              decoration: const InputDecoration(
                labelText: 'House networks',
                helperText: 'One per line: NAME CIDR description',
                suffixIcon: HelpButton(
                    title: 'House networks',
                    text: 'Lets the app work out which network a device is on, e.g.\n'
                        'VPN 10.10.40.0/24 Everything via Proton\nCLEAR 10.10.20.0/24 Direct internet'),
              ),
              validator: (v) => networksFromText(v ?? '') == null ? 'Each line: NAME a.b.c.d/nn [description]' : null,
            ),
          ),
          _field('killSwitchTag', 'Kill switch tag',
              help: 'The tag the router\'s kill switch rule blocks (NO_WAN_EGRESS). The app checks the rule is '
                  'loaded and counts what it blocked.',
              validator: _required),
          _field('killSwitchRuleUuid', 'Kill switch rule UUID (optional)',
              help: 'Only needed if the API user has "Firewall: Rules" but not "Firewall: Rules [new]".'),
        ],
      ),

      // 8 ------------------------------------------------------------ share
      SettingsSection(
        icon: Icons.ios_share,
        title: 'Share settings',
        summary: 'Hand a ready-made setup to someone in your home (no secrets)',
        children: [
          const Text('Exports everything except secrets and personal preferences. The other person adds '
              'their own API key.'),
          const SizedBox(height: 8),
          Wrap(spacing: 12, runSpacing: 12, children: [
            OutlinedButton.icon(onPressed: _export, icon: const Icon(Icons.ios_share), label: const Text('Export...')),
            OutlinedButton.icon(onPressed: _import, icon: const Icon(Icons.download), label: const Text('Import...')),
          ]),
        ],
      ),

      // 9 -------------------------------------------------------------- app
      SettingsSection(
          icon: Icons.system_update_alt,
          title: 'App & updates',
          summary: _cfg.checkUpdates ? 'Checks for updates automatically' : 'Manual updates',
          children: [
            SubSection(title: 'Router changes made by the app', children: [
              for (final e in c.journal.entries.take(10))
                InfoLine('${formatWhen(e.at)}  ${e.ok ? '' : 'FAILED: '}${e.what}${e.detail == null ? '' : ' - ${e.detail}'}'),
              if (c.journal.entries.isEmpty) const InfoLine('None yet.'),
              const InfoLine('The router also keeps every change as a revision under System > Configuration > History, '
                  'where an admin can compare and revert it.'),
            ]),
            SubSection(title: 'Diagnostics', children: [
              Row(children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: () async {
                      await Clipboard.setData(ClipboardData(text: c.diagnostics()));
                      _say('Diagnostics copied - paste them into a bug report or a message.');
                    },
                    icon: const Icon(Icons.bug_report_outlined),
                    label: const Text('Copy diagnostics'),
                  ),
                ),
                const HelpButton(
                    title: 'Copy diagnostics',
                    text: 'Copies what a bug report needs: app version, settings that matter, tunnel status, the '
                        'app\'s recent router changes and recent app errors.\n\nNever included: API key or secret, '
                        'WireGuard keys, the app PIN. Blanked: public IP addresses, domain names and tunnel keys. '
                        'Kept: house addresses like 10.x.x.x. Have a look before you send it.'),
              ]),
            ]),
            if (_autostart != null)
              _switch('Start in the tray when I sign in', _autostart!, (v) async {
                final ok = await WindowsAutostart.setEnabled(v);
                final now = await WindowsAutostart.isEnabled();
                if (!mounted) return;
                setState(() => _autostart = now);
                if (!ok) _say('Could not change the startup setting.', error: true);
              }, subtitle: 'Applies straight away.'),
            if (widget.updates != null) ...[
              _switch('Check for updates automatically', _cfg.checkUpdates, (v) => _set(_cfg.copyWith(checkUpdates: v)),
                  subtitle: 'At start-up and every 12 hours.'),
              UpdateSettingsCard(updates: widget.updates!),
            ],
          ],
        ),
    ];

    return Form(
      key: _form,
      child: Column(children: [
        Expanded(
          child: ListView(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
            children: [
              Row(children: [
                Expanded(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text(widget.firstRun ? 'Welcome to Cybervulcan' : 'Settings', style: t.headlineSmall),
                    const SizedBox(height: 2),
                    Text('Tap a section to open it. Every ? explains the field.',
                        style: t.bodySmall?.copyWith(color: OpnColors.textSoft)),
                  ]),
                ),
                OutlinedButton.icon(
                  onPressed: () => openSetupGuide(context),
                  icon: const Icon(Icons.help_outline),
                  label: const Text('Guide'),
                ),
              ]),
              const SizedBox(height: 16),
              ...sections,
            ],
          ),
        ),
        _SaveBar(
          busy: _busy,
          dirty: _dirty,
          message: _message,
          error: _messageIsError,
          onSave: _save,
          onTest: _testConnection,
          onDismiss: () => setState(() => _message = null),
        ),
      ]),
    );
  }
}

extension _Let<T> on T {
  R let<R>(R Function(T) f) => f(this);
}

/// A fold-out settings group with an icon and a one-line summary.
class SettingsSection extends StatelessWidget {
  const SettingsSection({
    super.key,
    required this.icon,
    required this.title,
    required this.summary,
    required this.children,
    this.initiallyExpanded = false,
  });

  final IconData icon;
  final String title;
  final String summary;
  final List<Widget> children;
  final bool initiallyExpanded;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      clipBehavior: Clip.antiAlias,
      child: ExpansionTile(
        initiallyExpanded: initiallyExpanded,
        // Collapsed sections keep their fields alive so Save validates them all.
        maintainState: true,
        shape: const Border(),
        collapsedShape: const Border(),
        leading: Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: OpnColors.glassCyan.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, color: OpnColors.glassCyan, size: 22),
        ),
        title: Text(title, style: t.titleMedium),
        subtitle: Text(summary, maxLines: 1, overflow: TextOverflow.ellipsis,
            style: t.bodySmall?.copyWith(color: OpnColors.textSoft)),
        childrenPadding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
        expandedCrossAxisAlignment: CrossAxisAlignment.start,
        children: children,
      ),
    );
  }
}

/// A titled block inside a section.
class SubSection extends StatelessWidget {
  const SubSection({super.key, required this.title, required this.children});
  final String title;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) => Container(
        width: double.infinity,
        margin: const EdgeInsets.only(top: 4, bottom: 12),
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 4),
        decoration: BoxDecoration(
          border: Border.all(color: OpnColors.border),
          borderRadius: BorderRadius.circular(12),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(title.toUpperCase(),
              style: Theme.of(context).textTheme.labelSmall?.copyWith(color: OpnColors.muted, letterSpacing: 1.1)),
          const SizedBox(height: 10),
          ...children,
        ]),
      );
}

/// The "?" next to a field: opens a short plain-language explanation.
class HelpButton extends StatelessWidget {
  const HelpButton({super.key, required this.title, required this.text, this.small = false});
  final String title;
  final String text;
  final bool small;

  @override
  Widget build(BuildContext context) => IconButton(
        tooltip: 'What is this?',
        visualDensity: small ? VisualDensity.compact : null,
        iconSize: small ? 18 : 20,
        icon: const Icon(Icons.help_outline, color: OpnColors.muted),
        onPressed: () => showDialog<void>(
          context: context,
          builder: (ctx) => AlertDialog(
            icon: const Icon(Icons.help_outline, color: OpnColors.glassCyan),
            title: Text(title),
            content: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 460),
              child: SingleChildScrollView(child: Text(text)),
            ),
            actions: [FilledButton(onPressed: () => Navigator.pop(ctx), child: const Text('Got it'))],
          ),
        ),
      );
}

class WarningLine extends StatelessWidget {
  const WarningLine(this.text, {super.key});
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

class InfoLine extends StatelessWidget {
  const InfoLine(this.text, {super.key});
  final String text;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Icon(Icons.info_outline, color: OpnColors.glassCyan, size: 18),
          const SizedBox(width: 8),
          Expanded(child: Text(text, style: Theme.of(context).textTheme.bodySmall)),
        ]),
      );
}

/// Save / Test always visible at the bottom, with the last message (long
/// test reports start folded to a one-line summary).
class _SaveBar extends StatefulWidget {
  const _SaveBar({
    required this.busy,
    required this.dirty,
    required this.message,
    required this.error,
    required this.onSave,
    required this.onTest,
    required this.onDismiss,
  });

  final bool busy;
  final bool dirty;
  final String? message;
  final bool error;
  final VoidCallback onSave;
  final VoidCallback onTest;
  final VoidCallback onDismiss;

  @override
  State<_SaveBar> createState() => _SaveBarState();
}

/// "6 OK - 2 skipped" for a connection-test report; null for other messages.
String? summariseReport(String message) {
  final lines = message.split('\n').where((l) => l.trim().isNotEmpty).toList();
  int n(String p) => lines.where((l) => l.startsWith(p)).length;
  final ok = n('OK');
  final fail = n('FAIL') + n('NO PRIVILEGE');
  final warn = n('WARN');
  final fix = n('FIX');
  final skip = n('SKIP');
  if (ok + fail + warn + skip + fix < 3) return null;
  return [
    '$ok OK',
    if (fail > 0) '$fail failed',
    if (fix > 0) '$fix to fix',
    if (warn > 0) '$warn warning${warn == 1 ? '' : 's'}',
    if (skip > 0) '$skip skipped (optional)',
  ].join(' - ');
}

class _SaveBarState extends State<_SaveBar> {
  bool _open = false;

  @override
  void didUpdateWidget(_SaveBar old) {
    super.didUpdateWidget(old);
    if (old.message != widget.message) _open = false;
  }

  @override
  Widget build(BuildContext context) {
    final busy = widget.busy;
    final dirty = widget.dirty;
    final message = widget.message;
    final error = widget.error;
    final onSave = widget.onSave;
    final onTest = widget.onTest;
    final onDismiss = widget.onDismiss;
    final summary = message == null ? null : summariseReport(message);
    final folded = summary != null && !_open;
    return Material(
        color: OpnColors.rail,
        child: SafeArea(
          top: false,
          child: Container(
            decoration: const BoxDecoration(border: Border(top: BorderSide(color: OpnColors.border))),
            padding: const EdgeInsets.fromLTRB(16, 10, 16, 10),
            child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              if (message != null)
                Container(
                  constraints: const BoxConstraints(maxHeight: 150),
                  margin: const EdgeInsets.only(bottom: 10),
                  padding: const EdgeInsets.fromLTRB(12, 6, 4, 6),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(12),
                    color: (error ? OpnColors.red : OpnColors.green).withValues(alpha: 0.12),
                  ),
                  child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Expanded(
                      child: folded
                          ? Padding(
                              padding: const EdgeInsets.only(top: 6),
                              child: Row(children: [
                                Icon(error ? Icons.error_outline : Icons.check_circle_outline,
                                    size: 18, color: error ? OpnColors.red : OpnColors.green),
                                const SizedBox(width: 8),
                                Expanded(child: Text(summary)),
                              ]),
                            )
                          : SingleChildScrollView(
                              child: SelectableText(message,
                                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
                            ),
                    ),
                    if (summary != null)
                      IconButton(
                        visualDensity: VisualDensity.compact,
                        tooltip: _open ? 'Hide details' : 'Show details',
                        icon: Icon(_open ? Icons.expand_less : Icons.expand_more, size: 20),
                        onPressed: () => setState(() => _open = !_open),
                      ),
                    IconButton(visualDensity: VisualDensity.compact, icon: const Icon(Icons.close, size: 18), onPressed: onDismiss),
                  ]),
                ),
              Row(children: [
                if (dirty)
                  const Expanded(
                    child: Text('Unsaved changes', style: TextStyle(color: OpnColors.amber, fontSize: 13)),
                  )
                else
                  const Spacer(),
                OutlinedButton.icon(
                  onPressed: busy ? null : onTest,
                  icon: const Icon(Icons.network_check, size: 18),
                  label: const Text('Test'),
                ),
                const SizedBox(width: 8),
                FilledButton.icon(
                  onPressed: busy ? null : onSave,
                  icon: busy
                      ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                      : const Icon(Icons.save),
                  label: const Text('Save'),
                ),
              ]),
            ]),
          ),
        ),
      );
  }
}
