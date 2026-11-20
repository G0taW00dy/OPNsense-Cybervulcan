import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';

import '../core/storage.dart';

/// App lock: the device's own fingerprint / face / PIN / Windows Hello, with
/// an optional app PIN as backup (for devices or prompts that only offer a
/// fingerprint). Cybervulcan never sees the fingerprint or the device PIN;
/// for the app PIN it stores only a salted SHA-256.
class AppLock {
  AppLock({required this.store, required this.context, LocalAuthentication? auth})
      : _auth = auth ?? LocalAuthentication();

  final SecretStore store;

  /// Where to show the app-PIN dialog (the app's navigator).
  final BuildContext? Function() context;
  final LocalAuthentication _auth;

  /// True when this device has a screen lock / Windows Hello to ask for.
  Future<bool> supported() async {
    try {
      return await _auth.isDeviceSupported();
    } on Object {
      return false;
    }
  }

  Future<bool> hasAppPin() async => (await store.readAppPinHash())?.contains(':') ?? false;

  /// Something can unlock the app: the system lock or an app PIN.
  Future<bool> available() async => await supported() || await hasAppPin();

  /// System prompt (fingerprint, face or the device PIN/pattern), then the
  /// app PIN if one is set and the system prompt was cancelled or missing.
  Future<bool> authorize(String reason) async {
    if (await supported()) {
      try {
        // biometricOnly: false = the prompt also offers the device PIN.
        if (await _auth.authenticate(localizedReason: reason, biometricOnly: false, persistAcrossBackgrounding: true)) {
          return true;
        }
      } on Object {
        // Fall through to the app PIN.
      }
    }
    if (!await hasAppPin()) return false;
    final ctx = context();
    if (ctx == null || !ctx.mounted) return false;
    final stored = (await store.readAppPinHash())!;
    if (!ctx.mounted) return false;
    final ok = await showDialog<bool>(
      context: ctx,
      barrierDismissible: false,
      builder: (_) => _PinDialog(title: reason, check: (pin) => verifyPin(pin, stored)),
    );
    return ok ?? false;
  }

  /// Asks for a new app PIN twice and stores it. Returns false if cancelled.
  Future<bool> setAppPin(BuildContext context) async {
    final pin = await showDialog<String>(context: context, builder: (_) => const _NewPinDialog());
    if (pin == null) return false;
    await store.writeAppPinHash(hashPin(pin));
    return true;
  }

  Future<void> removeAppPin() => store.writeAppPinHash(null);
}

/// "salt:sha256(salt:pin)" with a random 16-byte salt.
String hashPin(String pin, {String? salt}) {
  final s = salt ?? base64Url.encode(List<int>.generate(16, (_) => Random.secure().nextInt(256)));
  final h = sha256.convert(utf8.encode('$s:$pin')).toString();
  return '$s:$h';
}

bool verifyPin(String pin, String stored) {
  final i = stored.indexOf(':');
  if (i <= 0) return false;
  final expected = hashPin(pin, salt: stored.substring(0, i));
  // Constant-time compare.
  if (expected.length != stored.length) return false;
  var diff = 0;
  for (var k = 0; k < expected.length; k++) {
    diff |= expected.codeUnitAt(k) ^ stored.codeUnitAt(k);
  }
  return diff == 0;
}

bool validPin(String pin) => RegExp(r'^\d{4,8}$').hasMatch(pin);

class _PinDialog extends StatefulWidget {
  const _PinDialog({required this.title, required this.check});
  final String title;
  final bool Function(String pin) check;

  @override
  State<_PinDialog> createState() => _PinDialogState();
}

class _PinDialogState extends State<_PinDialog> {
  final _c = TextEditingController();
  int _wrong = 0;
  String? _error;

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  void _submit() {
    if (widget.check(_c.text.trim())) {
      Navigator.pop(context, true);
      return;
    }
    _wrong++;
    _c.clear();
    if (_wrong >= 5) {
      Navigator.pop(context, false);
      return;
    }
    setState(() => _error = 'Wrong PIN (${5 - _wrong} tries left)');
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
        icon: const Icon(Icons.lock_outline),
        title: Text(widget.title),
        content: TextField(
          controller: _c,
          autofocus: true,
          obscureText: true,
          keyboardType: TextInputType.number,
          inputFormatters: [FilteringTextInputFormatter.digitsOnly, LengthLimitingTextInputFormatter(8)],
          decoration: InputDecoration(labelText: 'App PIN', errorText: _error),
          onSubmitted: (_) => _submit(),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(onPressed: _submit, child: const Text('Unlock')),
        ],
      );
}

class _NewPinDialog extends StatefulWidget {
  const _NewPinDialog();

  @override
  State<_NewPinDialog> createState() => _NewPinDialogState();
}

class _NewPinDialogState extends State<_NewPinDialog> {
  final _a = TextEditingController();
  final _b = TextEditingController();
  String? _error;

  @override
  void dispose() {
    _a.dispose();
    _b.dispose();
    super.dispose();
  }

  void _save() {
    if (!validPin(_a.text)) {
      setState(() => _error = '4 to 8 digits');
      return;
    }
    if (_a.text != _b.text) {
      setState(() => _error = 'The two PINs differ');
      return;
    }
    Navigator.pop(context, _a.text);
  }

  @override
  Widget build(BuildContext context) {
    TextField f(TextEditingController c, String label) => TextField(
          controller: c,
          obscureText: true,
          keyboardType: TextInputType.number,
          inputFormatters: [FilteringTextInputFormatter.digitsOnly, LengthLimitingTextInputFormatter(8)],
          decoration: InputDecoration(labelText: label),
        );
    return AlertDialog(
      icon: const Icon(Icons.pin_outlined),
      title: const Text('Set an app PIN'),
      content: Column(mainAxisSize: MainAxisSize.min, children: [
        const Text('A backup for when the fingerprint prompt has no PIN option. 4 to 8 digits; '
            'don\'t reuse your bank PIN.'),
        const SizedBox(height: 8),
        f(_a, 'New PIN'),
        f(_b, 'Repeat PIN'),
        if (_error != null)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
          ),
      ]),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        FilledButton(onPressed: _save, child: const Text('Save PIN')),
      ],
    );
  }
}
