import 'dart:async';
import 'dart:io';

import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../core/config.dart';
import '../core/controller.dart';
import '../core/network_map.dart';
import '../core/wg_conf.dart';
import '../core/wg_keys.dart';
import 'theme.dart';

/// Shows [text] as a QR code with a copy button.
Future<void> showQrDialog(BuildContext context, {required String title, required String text, String? note}) =>
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: SizedBox(
          width: 300,
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Container(
              color: Colors.white,
              padding: const EdgeInsets.all(12),
              child: QrImageView(
                data: text,
                size: 260,
                backgroundColor: Colors.white,
                errorCorrectionLevel: QrErrorCorrectLevel.L,
                errorStateBuilder: (_, _) => const Padding(
                  padding: EdgeInsets.all(16),
                  child: Text('Too long for a QR code - use Copy or a file instead.',
                      style: TextStyle(color: Colors.black)),
                ),
              ),
            ),
            if (note != null) ...[const SizedBox(height: 12), Text(note)],
          ]),
        ),
        actions: [
          TextButton(
            onPressed: () => copyText(ctx, text, 'Copied'),
            child: const Text('Copy'),
          ),
          FilledButton(onPressed: () => Navigator.pop(ctx), child: const Text('Close')),
        ],
      ),
    );

Future<void> copyText(BuildContext context, String text, String done) async {
  await Clipboard.setData(ClipboardData(text: text));
  if (context.mounted) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(done)));
  }
}

/// Lets the user paste text or open a file. Returns the text, or null.
Future<String?> pasteOrOpenText(BuildContext context, {required String title, required String hint}) {
  final ctrl = TextEditingController();
  return showDialog<String>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text(title),
      content: SizedBox(
        width: 520,
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          TextField(
            controller: ctrl,
            maxLines: 10,
            minLines: 6,
            autocorrect: false,
            enableSuggestions: false,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            decoration: InputDecoration(hintText: hint, border: const OutlineInputBorder()),
          ),
        ]),
      ),
      actions: [
        TextButton.icon(
          icon: const Icon(Icons.folder_open),
          label: const Text('Open file...'),
          onPressed: () async {
            try {
              final f = await openFile(
                acceptedTypeGroups: Platform.isWindows
                    ? const [XTypeGroup(label: 'Settings / WireGuard', extensions: ['json', 'conf', 'txt'])]
                    : const [],
              );
              if (f == null) return;
              final text = await f.readAsString();
              ctrl.text = text.length > 64 * 1024 ? text.substring(0, 64 * 1024) : text;
            } on Object catch (e) {
              if (ctx.mounted) {
                ScaffoldMessenger.of(ctx).showSnackBar(SnackBar(content: Text('Could not open the file: $e')));
              }
            }
          },
        ),
        TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(ctx, ctrl.text), child: const Text('Import')),
      ],
    ),
  ).whenComplete(ctrl.dispose);
}

/// Saves [text] to a file the user picks (Windows). Returns the path or null.
Future<String?> saveTextFile(String suggestedName, String text) async {
  final loc = await getSaveLocation(
    suggestedName: suggestedName,
    acceptedTypeGroups: const [XTypeGroup(label: 'JSON', extensions: ['json'])],
  );
  if (loc == null) return null;
  await File(loc.path).writeAsString(text);
  return loc.path;
}

/// Remote-access (WireGuard) settings: this device's public key, the
/// router's endpoint and key, and import from a wg-quick file.
///
/// Non-secret values are reported through [onChanged] (the page saves them).
/// Secrets (private key, pre-shared key) go straight to secure storage via
/// the controller and are never shown again.
class RemoteAccessEditor extends StatefulWidget {
  const RemoteAccessEditor({
    super.key,
    required this.controller,
    required this.config,
    required this.onChanged,
  });

  final CybervulcanController controller;
  final AppConfig config;
  final ValueChanged<AppConfig> onChanged;

  @override
  State<RemoteAccessEditor> createState() => _RemoteAccessEditorState();
}

class _RemoteAccessEditorState extends State<RemoteAccessEditor> {
  late final Map<String, TextEditingController> _t;
  final _psk = TextEditingController();
  int _generation = 0;
  String? _note;

  @override
  void initState() {
    super.initState();
    _t = {};
    _fill(widget.config);
  }

  void _fill(AppConfig c) {
    final values = {
      'host': c.wgEndpointHost,
      'port': '${c.wgEndpointPort}',
      'server': c.wgServerPublicKey ?? '',
      'address': c.wgAddress,
      'allowed': c.wgAllowedIps,
      'keepalive': '${c.wgKeepalive}',
    };
    for (final e in values.entries) {
      (_t[e.key] ??= TextEditingController()).text = e.value;
    }
  }

  @override
  void dispose() {
    for (final c in _t.values) {
      c.dispose();
    }
    _psk.dispose();
    super.dispose();
  }

  String _v(String k) => _t[k]!.text.trim();

  void _changed() {
    final port = int.tryParse(_v('port'));
    final ka = int.tryParse(_v('keepalive'));
    widget.onChanged(widget.config.copyWith(
      wgEndpointHost: _v('host'),
      wgEndpointPort: port != null && port > 0 && port <= 65535 ? port : null,
      wgServerPublicKey: _v('server').isEmpty ? null : _v('server'),
      clearWgServerPublicKey: _v('server').isEmpty,
      wgAddress: _v('address'),
      wgAllowedIps: _v('allowed').isEmpty ? null : _v('allowed'),
      wgKeepalive: ka != null && ka >= 0 && ka <= 65535 ? ka : null,
    ));
  }

  Future<void> _generate() async {
    final has = widget.controller.wireGuardPublicKey != null;
    if (has) {
      final ok = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Make a new key?'),
          content: const Text('The router admin will have to replace this device\'s public key on '
              'the router, or remote access stops working.'),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
            FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('New key')),
          ],
        ),
      );
      if (ok != true) return;
    }
    await widget.controller.generateWireGuardKey();
    if (mounted) setState(() => _note = 'New key made. Give the public key to the router admin.');
  }

  Future<void> _savePsk({bool remove = false}) async {
    final v = _psk.text.trim();
    if (!remove && !isWireGuardKey(v)) {
      setState(() => _note = 'That is not a WireGuard key (44 characters, base64).');
      return;
    }
    await widget.controller.storeWireGuardSecrets(presharedKey: remove ? null : v, setPsk: true);
    _psk.clear();
    if (mounted) setState(() => _note = remove ? 'Pre-shared key removed.' : 'Pre-shared key stored securely.');
  }

  Future<void> _importConf() async {
    final text = await pasteOrOpenText(context,
        title: 'Import WireGuard configuration',
        hint: '[Interface]\nAddress = 10.10.99.2/32\n...\n[Peer]\nPublicKey = ...\nEndpoint = home.example.com:51830');
    if (text == null || text.trim().isEmpty || !mounted) return;
    final WgQuickImport imp;
    try {
      imp = parseWgQuick(text);
    } on FormatException catch (e) {
      setState(() => _note = e.message);
      return;
    }
    if (imp.privateKey != null || imp.presharedKey != null) {
      await widget.controller.storeWireGuardSecrets(
        privateKey: imp.privateKey,
        presharedKey: imp.presharedKey,
        setPsk: imp.presharedKey != null,
      );
    }
    final next = widget.config.copyWith(
      remoteEnabled: true,
      wgEndpointHost: imp.endpointHost,
      wgEndpointPort: imp.endpointPort,
      wgServerPublicKey: imp.serverPublicKey,
      wgAddress: imp.address,
      wgAllowedIps: imp.allowedIps != null && !imp.allowedIps!.contains('/0') ? imp.allowedIps : null,
      wgKeepalive: imp.keepalive,
    );
    _fill(next);
    widget.onChanged(next);
    if (!mounted) return;
    setState(() {
      _generation++;
      _note = [
        'Imported. Press Save to keep it.',
        if (imp.privateKey != null) 'The private key from the file is now in secure storage.',
        if (imp.presharedKey != null) 'The pre-shared key is now in secure storage.',
        ...imp.warnings,
      ].join(' ');
    });
  }

  Widget _field(String key, String label,
          {String? help, bool number = false, String? Function(String?)? validator}) =>
      Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: TextFormField(
          key: ValueKey('$key-$_generation'),
          controller: _t[key],
          decoration: InputDecoration(labelText: label, helperText: help, helperMaxLines: 3),
          keyboardType: number ? TextInputType.number : TextInputType.text,
          autocorrect: false,
          enableSuggestions: false,
          onChanged: (_) => _changed(),
          validator: validator,
        ),
      );

  @override
  Widget build(BuildContext context) {
    final c = widget.controller;
    final cfg = widget.config;
    final t = Theme.of(context).textTheme;
    final pub = c.wireGuardPublicKey;
    final available = c.link.tunnel.isAvailable;
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(
        'Control the router when you are away from home, through a WireGuard tunnel that only '
        'this app uses. It does not take the system VPN slot, so a VPN app (e.g. Proton) can '
        'stay on. At home the app talks to the router directly.',
        style: t.bodySmall,
      ),
      if (!available)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(c.link.tunnel.unavailableReason ?? 'Not available on this device.',
              style: t.bodySmall?.copyWith(color: OpnColors.amber)),
        ),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        title: const Text('Use remote access when the router is not reachable'),
        value: cfg.remoteEnabled,
        onChanged: (v) => widget.onChanged(cfg.copyWith(remoteEnabled: v)),
      ),
      Card(
        margin: const EdgeInsets.only(bottom: 12),
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('This device\'s public key', style: t.titleSmall),
            const SizedBox(height: 4),
            Text(
              'Give this to the router admin: they add it as a peer on the router. The matching '
              'private key never leaves this device and is never shown.',
              style: t.bodySmall,
            ),
            const SizedBox(height: 8),
            if (pub != null)
              SelectableText(pub, style: const TextStyle(fontFamily: 'monospace', fontSize: 13))
            else
              const Text('No key yet.'),
            const SizedBox(height: 8),
            Wrap(spacing: 8, runSpacing: 8, children: [
              FilledButton.tonalIcon(
                onPressed: _generate,
                icon: const Icon(Icons.key),
                label: Text(pub == null ? 'Generate key' : 'New key...'),
              ),
              if (pub != null)
                OutlinedButton.icon(
                  onPressed: () => copyText(context, pub, 'Public key copied'),
                  icon: const Icon(Icons.copy),
                  label: const Text('Copy'),
                ),
              if (pub != null)
                OutlinedButton.icon(
                  onPressed: () => showQrDialog(context,
                      title: 'Public key', text: pub, note: 'Public key only - safe to share.'),
                  icon: const Icon(Icons.qr_code),
                  label: const Text('QR'),
                ),
            ]),
          ]),
        ),
      ),
      Row(children: [
        Expanded(
          flex: 3,
          child: _field('host', 'Endpoint (home address)',
              help: 'Public name or IP of your home, e.g. home.cybervulcan.com'),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: _field('port', 'Port', number: true, validator: (v) {
            final n = int.tryParse(v ?? '');
            return n != null && n > 0 && n <= 65535 ? null : '1-65535';
          }),
        ),
      ]),
      _field('server', 'Router public key',
          help: 'From the router admin (VPN > WireGuard > Instances, the road-warrior instance).',
          validator: (v) => (v == null || v.trim().isEmpty || isWireGuardKey(v)) ? null : 'Not a WireGuard key'),
      _field('address', 'This device\'s tunnel address',
          help: 'Assigned by the router admin, e.g. 10.10.99.2/32.',
          validator: (v) =>
              (v == null || v.trim().isEmpty || Ipv4Subnet.tryParse(v) != null) ? null : 'e.g. 10.10.99.2/32'),
      _field('allowed', 'Allowed IPs', help: 'Normally just the router: 10.10.10.254/32'),
      _field('keepalive', 'Keepalive (seconds)', number: true, validator: (v) {
        final n = int.tryParse(v ?? '');
        return n != null && n >= 0 && n <= 65535 ? null : '0-65535';
      }),
      Row(children: [
        Expanded(
          child: TextField(
            controller: _psk,
            obscureText: true,
            autocorrect: false,
            enableSuggestions: false,
            decoration: InputDecoration(
              labelText: 'Pre-shared key (optional)',
              helperText: c.hasPresharedKey ? 'Stored securely. Enter a new one to replace it.' : null,
            ),
          ),
        ),
        const SizedBox(width: 8),
        TextButton(onPressed: _savePsk, child: const Text('Store')),
        if (c.hasPresharedKey) TextButton(onPressed: () => _savePsk(remove: true), child: const Text('Remove')),
      ]),
      const SizedBox(height: 12),
      OutlinedButton.icon(
        onPressed: _importConf,
        icon: const Icon(Icons.file_download_outlined),
        label: const Text('Import a WireGuard .conf'),
      ),
      if (_note != null)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(_note!, style: t.bodySmall?.copyWith(color: OpnColors.glassCyan)),
        ),
      if (cfg.remoteEnabled)
        for (final p in c.remoteAccessIssues)
          Padding(
            padding: const EdgeInsets.only(top: 6),
            child: Text('- $p', style: t.bodySmall?.copyWith(color: OpnColors.amber)),
          ),
    ]);
  }
}
