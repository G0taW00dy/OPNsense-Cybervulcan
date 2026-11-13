import 'package:flutter/material.dart';

import '../core/config.dart';
import '../core/controller.dart';
import '../core/settings_transfer.dart';
import '../core/storage.dart';
import 'help_page.dart';
import 'remote_access.dart';
import 'settings_page.dart';
import 'theme.dart';

/// First-run setup on a new device: router address and certificate name,
/// API key, connection test, optional remote access. Everything network-
/// specific can come from a settings export made by the router admin.
class SetupWizard extends StatefulWidget {
  const SetupWizard({super.key, required this.controller});

  final CybervulcanController controller;

  @override
  State<SetupWizard> createState() => _SetupWizardState();
}

class _SetupWizardState extends State<SetupWizard> {
  int _step = 0;
  late AppConfig _cfg;
  final _address = TextEditingController();
  final _certName = TextEditingController();
  final _key = TextEditingController();
  final _secret = TextEditingController();
  final _routerForm = GlobalKey<FormState>();
  bool _busy = false;
  bool _showSecret = false;
  String? _importNote;
  List<String>? _testLines;
  String? _error;
  int _remoteGen = 0;

  @override
  void initState() {
    super.initState();
    _cfg = widget.controller.config;
    _fill();
  }

  void _fill() {
    _address.text = _cfg.baseUrl;
    _certName.text = _cfg.certName;
  }

  @override
  void dispose() {
    for (final c in [_address, _certName, _key, _secret]) {
      c.dispose();
    }
    super.dispose();
  }

  AppConfig _collect() => _cfg.copyWith(
        baseUrl: normaliseRouterAddress(_address.text),
        certName: _certName.text.trim(),
      );

  ApiCredentials get _creds => ApiCredentials(_key.text.trim(), _secret.text.trim());

  Future<void> _import() async {
    final text = await pasteOrOpenText(context,
        title: 'Settings from your router admin',
        hint: 'Paste the settings text (JSON) you were given, or open the file.');
    if (text == null || text.trim().isEmpty || !mounted) return;
    try {
      final r = importSettings(text, _collect());
      setState(() {
        _cfg = r.config;
        _fill();
        _remoteGen++;
        _importNote = [
          'Loaded ${r.applied.length} settings (router address, names, remote access...).',
          ...r.warnings,
        ].join(' ');
      });
    } on FormatException catch (e) {
      setState(() => _importNote = e.message);
    }
  }

  Future<void> _test() async {
    setState(() {
      _busy = true;
      _testLines = null;
    });
    final lines = await testRouterConnection(_collect(), _creds);
    if (!mounted) return;
    setState(() {
      _busy = false;
      _testLines = lines;
    });
  }

  Future<void> _finish() async {
    if (!_creds.isComplete) {
      setState(() {
        _step = 2;
        _error = 'Enter both the API key and the API secret.';
      });
      return;
    }
    setState(() => _busy = true);
    await widget.controller.saveSettings(_collect(), credentials: _creds);
    // HomeShell switches to the main pages once credentials exist.
  }

  void _next() {
    setState(() => _error = null);
    if (_step == 1 && !(_routerForm.currentState?.validate() ?? false)) return;
    if (_step == 2 && !_creds.isComplete) {
      setState(() => _error = 'Enter both the API key and the API secret.');
      return;
    }
    if (_step < 5) setState(() => _step++);
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final ok = _testLines != null && !_testLines!.any((l) => l.startsWith('FAIL'));
    return Stepper(
      currentStep: _step,
      onStepTapped: (i) => setState(() => _step = i),
      onStepContinue: _busy ? null : (_step == 5 ? _finish : _next),
      onStepCancel: _step == 0 || _busy ? null : () => setState(() => _step--),
      controlsBuilder: (context, details) => Padding(
        padding: const EdgeInsets.only(top: 16),
        child: Row(children: [
          FilledButton(
            onPressed: details.onStepContinue,
            child: Text(_step == 5 ? 'Save and start' : (_step == 4 ? 'Next (or skip)' : 'Next')),
          ),
          const SizedBox(width: 8),
          if (_step > 0) TextButton(onPressed: details.onStepCancel, child: const Text('Back')),
          const Spacer(),
          if (_busy) const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2)),
        ]),
      ),
      steps: [
        Step(
          title: const Text('Welcome'),
          isActive: _step >= 0,
          content: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('Cybervulcan shows and controls your OPNsense router: VPN status, failover, '
                'whole-house VPN bypass and more.', style: t.bodyMedium),
            const SizedBox(height: 8),
            const Text('If the router admin gave you a settings file or text, load it now - it fills '
                'in the router address, names and remote access for you. It never contains passwords '
                'or keys.'),
            const SizedBox(height: 12),
            Wrap(spacing: 12, runSpacing: 8, children: [
              OutlinedButton.icon(
                onPressed: _import,
                icon: const Icon(Icons.download),
                label: const Text('Load settings from admin...'),
              ),
              TextButton.icon(
                onPressed: () => openSetupGuide(context),
                icon: const Icon(Icons.help_outline),
                label: const Text('Setup guide'),
              ),
            ]),
            if (_importNote != null)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text(_importNote!, style: const TextStyle(color: OpnColors.glassCyan)),
              ),
          ]),
        ),
        Step(
          title: const Text('Router'),
          isActive: _step >= 1,
          content: Form(
            key: _routerForm,
            child: Column(children: [
              TextFormField(
                controller: _address,
                decoration: const InputDecoration(
                  labelText: 'Router address',
                  helperText: 'Where the app connects, e.g. 10.10.10.254 (https is assumed)',
                ),
                validator: validateRouterAddress,
                onChanged: (_) => setState(() {}),
              ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _certName,
                decoration: const InputDecoration(
                  labelText: 'Certificate name',
                  helperText: 'The router\'s certificate must be valid for this name, e.g. '
                      'router.cybervulcan.com. If not, the app refuses to connect and never sends '
                      'your API key.',
                  helperMaxLines: 3,
                ),
                validator: validateCertName,
              ),
              if (normaliseRouterAddress(_address.text).startsWith('http://'))
                const Padding(
                  padding: EdgeInsets.only(top: 12),
                  child: Text('Plain http:// sends the API key unencrypted and cannot prove this is '
                      'your router. Only use it on a test router.',
                      style: TextStyle(color: OpnColors.amber)),
                ),
            ]),
          ),
        ),
        Step(
          title: const Text('API key'),
          isActive: _step >= 2,
          content: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Your own API key from the router admin (each person gets their own). It is '
                'kept in this device\'s secure storage and only ever sent to your router.'),
            const SizedBox(height: 12),
            TextField(
              controller: _key,
              autocorrect: false,
              enableSuggestions: false,
              decoration: const InputDecoration(labelText: 'API key'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _secret,
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
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text(_error!, style: const TextStyle(color: OpnColors.red)),
              ),
          ]),
        ),
        Step(
          title: const Text('Test connection'),
          isActive: _step >= 3,
          content: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Checks the router\'s certificate first, then each feature the API key may use. '
                'This needs you to be at home. Lines marked "optional" can fail.'),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: _busy ? null : _test,
              icon: const Icon(Icons.network_check),
              label: const Text('Test now'),
            ),
            if (_testLines != null)
              Container(
                margin: const EdgeInsets.only(top: 12),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(12),
                  color: (ok ? Colors.green : Colors.red).withValues(alpha: 0.12),
                ),
                child: SelectableText(_testLines!.join('\n'),
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
              ),
          ]),
        ),
        Step(
          title: const Text('Remote access (optional)'),
          isActive: _step >= 4,
          content: RemoteAccessEditor(
            key: ValueKey('wizard-remote-$_remoteGen'),
            controller: widget.controller,
            config: _cfg,
            onChanged: (c) => setState(() => _cfg = c.copyWith(
                  baseUrl: normaliseRouterAddress(_address.text),
                  certName: _certName.text.trim(),
                )),
          ),
        ),
        Step(
          title: const Text('Done'),
          isActive: _step >= 5,
          content: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('Router: ${normaliseRouterAddress(_address.text)}'),
            Text('Certificate name: ${_certName.text.trim().isEmpty ? '(the address)' : _certName.text.trim()}'),
            Text('Remote access: ${_cfg.remoteEnabled ? 'on' : 'off'}'),
            const SizedBox(height: 8),
            const Text('Everything else (gateway and alias names, networks, labels) can be changed '
                'later in Settings.'),
          ]),
        ),
      ],
    );
  }
}
