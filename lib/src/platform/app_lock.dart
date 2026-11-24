import 'dart:async';
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
    // v2.2.5 (audit L2): wrong PINs count across dialogs and restarts; after
    // 5 the PIN is locked for a while, doubling each further time.
    var (fails, until) = await store.readPinFailures();
    if (!ctx.mounted) return false;
    if (until != null && until.isAfter(DateTime.now())) {
      final mins = until.difference(DateTime.now()).inMinutes + 1;
      await showDialog<void>(
        context: ctx,
        builder: (c) => AlertDialog(
          title: const Text('App PIN locked'),
          content: Text('Too many wrong PINs. Try again in about $mins minute${mins == 1 ? '' : 's'}.'),
          actions: [TextButton(onPressed: () => Navigator.pop(c), child: const Text('OK'))],
        ),
      );
      return false;
    }
    final ok = await showDialog<bool>(
      context: ctx,
      barrierDismissible: false,
      builder: (_) => _PinDialog(
        title: reason,
        triesLeft: fails >= pinFreeTries ? 1 : pinFreeTries - fails,
        check: (pin) {
          final good = verifyPin(pin, stored);
          if (good) {
            fails = 0;
            unawaited(store.writePinFailures(0, null));
            if (isLegacyPinHash(stored)) unawaited(store.writeAppPinHash(hashPin(pin)));
          } else {
            fails++;
            unawaited(store.writePinFailures(fails, pinLockUntil(fails, DateTime.now())));
          }
          return good;
        },
      ),
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

/// v2.2.5 (audit L2): PBKDF2-HMAC-SHA256 iterations for the app PIN.
const pinIterations = 60000;

/// "p2-<iterations>-<salt>:<PBKDF2-HMAC-SHA256(pin, salt)>" with a random
/// 16-byte salt. PINs saved by older versions ("salt:sha256(salt:pin)") are
/// still accepted by [verifyPin] and rewritten in this form on the next
/// successful unlock.
String hashPin(String pin, {String? salt, int iterations = pinIterations}) {
  final s = salt ?? base64Url.encode(List<int>.generate(16, (_) => Random.secure().nextInt(256)));
  return 'p2-$iterations-$s:${_hex(pbkdf2Sha256(utf8.encode(pin), utf8.encode(s), iterations, 32))}';
}

/// The pre-2.2.5 form, for checking old stored PINs only.
String _legacyHashPin(String pin, String salt) => '$salt:${sha256.convert(utf8.encode('$salt:$pin'))}';

/// True when [stored] is in the pre-2.2.5 form (should be rewritten).
bool isLegacyPinHash(String stored) => !stored.startsWith('p2-');

/// PBKDF2 (RFC 8018) with HMAC-SHA256.
List<int> pbkdf2Sha256(List<int> password, List<int> salt, int iterations, int length) {
  final hmac = Hmac(sha256, password);
  final out = <int>[];
  for (var block = 1; out.length < length; block++) {
    var u = hmac.convert([...salt, block >> 24 & 0xff, block >> 16 & 0xff, block >> 8 & 0xff, block & 0xff]).bytes;
    final t = List<int>.of(u);
    for (var i = 1; i < iterations; i++) {
      u = hmac.convert(u).bytes;
      for (var j = 0; j < t.length; j++) {
        t[j] ^= u[j];
      }
    }
    out.addAll(t);
  }
  return out.sublist(0, length);
}

String _hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

bool verifyPin(String pin, String stored) {
  final i = stored.indexOf(':');
  if (i <= 0) return false;
  final head = stored.substring(0, i);
  final String expected;
  if (head.startsWith('p2-')) {
    final parts = head.split('-');
    final iter = parts.length >= 3 ? int.tryParse(parts[1]) : null;
    if (iter == null || iter < 1 || iter > 10000000) return false;
    expected = hashPin(pin, salt: parts.sublist(2).join('-'), iterations: iter);
  } else {
    expected = _legacyHashPin(pin, head);
  }
  // Constant-time compare.
  if (expected.length != stored.length) return false;
  var diff = 0;
  for (var k = 0; k < expected.length; k++) {
    diff |= expected.codeUnitAt(k) ^ stored.codeUnitAt(k);
  }
  return diff == 0;
}

bool validPin(String pin) => RegExp(r'^\d{4,8}$').hasMatch(pin);

/// Wrong PINs allowed before the first lock-out.
const pinFreeTries = 5;

/// When the PIN unlocks again after [fails] wrong tries: free for the first
/// [pinFreeTries], then 1 min, doubling each time, at most 1 hour.
DateTime? pinLockUntil(int fails, DateTime now) {
  if (fails < pinFreeTries) return null;
  final minutes = 1 << (fails - pinFreeTries).clamp(0, 6);
  return now.add(Duration(minutes: minutes > 60 ? 60 : minutes));
}

class _PinDialog extends StatefulWidget {
  const _PinDialog({required this.title, required this.check, this.triesLeft = pinFreeTries});
  final String title;
  final bool Function(String pin) check;
  final int triesLeft;

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
    if (_wrong >= widget.triesLeft) {
      Navigator.pop(context, false);
      return;
    }
    setState(() => _error = 'Wrong PIN (${widget.triesLeft - _wrong} tries left)');
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
