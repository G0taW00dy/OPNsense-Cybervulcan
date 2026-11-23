import 'dart:convert';

import 'config.dart';

/// Settings hand-over between devices (admin -> another user), as JSON text,
/// a file or a QR code. Secrets are never part of it: no API key or secret,
/// no WireGuard private or pre-shared key. Those are entered separately on
/// each device and live in its secure storage only.

const settingsExportKind = 'cybervulcan-settings';

/// Settings that only make sense on the device they were made on, or are a
/// personal preference. Not exported, never imported.
const _deviceOnly = {
  'pcIpOverride',
  'notifyOnBypass',
  'notifyOnFailover',
  'checkUpdates',
  'configVersion',
  // v2.0 personal preferences.
  'appLock',
  'alertNewDevices',
  'schedBypassEnabled',
  'schedDays',
  'schedStart',
  'schedMinutes',
  'backupReminderDays',
  'serverSwitcherEnabled',
  'autoBestNightly',
  'externalTests',
  'lockAfterMinutes',
  // v2.1 per-device choices.
  'shaperAutoTune',
  'protonReminder',
  'remoteMode',
  // v2.2.5 (audit L1): a certificate pin is never taken from a file or QR
  // code - with it, a tampered file could point the app at another server
  // and vouch for its certificate. Each device confirms the certificate itself.
  'pinnedCertSha256',
};

/// Every key that may be imported (the non-secret settings).
final Set<String> importableKeys = {
  for (final k in const AppConfig().toJson().keys)
    if (!_deviceOnly.contains(k)) k,
};

/// Key names that look like secrets. Rejected on import even if a future
/// version (or a hand-edited file) adds them.
final _secretLike = RegExp(r'secret|password|private|preshared|psk|token|apikey|api_key',
    caseSensitive: false);

String exportSettings(AppConfig cfg, {bool pretty = true}) {
  final all = cfg.toJson();
  final settings = <String, dynamic>{
    for (final e in all.entries)
      if (importableKeys.contains(e.key) && !_secretLike.hasMatch(e.key)) e.key: e.value,
  };
  final doc = {
    'kind': settingsExportKind,
    'version': currentConfigVersion,
    'note': 'No secrets: enter the API key/secret (and generate a WireGuard key) on each device.',
    'settings': settings,
  };
  return pretty ? const JsonEncoder.withIndent('  ').convert(doc) : jsonEncode(doc);
}

class SettingsImport {
  const SettingsImport(this.config, {this.applied = const [], this.ignored = const [], this.warnings = const []});

  final AppConfig config;
  final List<String> applied;
  final List<String> ignored;
  final List<String> warnings;
}

/// Merges exported settings into [current]. Unknown, device-only and
/// secret-looking keys are ignored (and reported). Throws [FormatException]
/// when the text is not a settings export.
SettingsImport importSettings(String text, AppConfig current) {
  final Object? doc;
  try {
    doc = jsonDecode(text.trim());
  } on FormatException {
    throw const FormatException('Not valid JSON. Paste the whole text you were given.');
  }
  if (doc is! Map) throw const FormatException('Not a Cybervulcan settings export.');
  final Object? inner = doc['kind'] == settingsExportKind ? doc['settings'] : doc;
  if (inner is! Map) throw const FormatException('Not a Cybervulcan settings export.');

  final applied = <String>[];
  final ignored = <String>[];
  final warnings = <String>[];
  final incoming = <String, dynamic>{};
  for (final e in inner.entries) {
    final k = '${e.key}';
    if (_secretLike.hasMatch(k)) {
      ignored.add(k);
      warnings.add('"$k" looks like a secret and was ignored. Secrets are never imported '
          'from settings - enter them on this device.');
    } else if (importableKeys.contains(k)) {
      incoming[k] = e.value;
      applied.add(k);
    } else {
      ignored.add(k);
    }
  }
  if (applied.isEmpty) throw const FormatException('No Cybervulcan settings found in that text.');

  // v2.2.5 (audit L1): say so when the import changes where the app connects.
  final cur = current.toJson();
  final defaults = const AppConfig().toJson();
  for (final k in const ['baseUrl', 'certName']) {
    final was = '${cur[k] ?? ''}'.trim();
    final now = incoming.containsKey(k) ? '${incoming[k] ?? ''}'.trim() : was;
    // A fresh device (still on the built-in default) has nothing to protect.
    if (was.isNotEmpty && was != '${defaults[k] ?? ''}'.trim() && now != was) {
      warnings.add(k == 'baseUrl'
          ? 'The router address changes from $was to $now. Only save this if you trust where these settings came from.'
          : 'The certificate name changes from $was to $now. Only save this if you trust where these settings came from.');
    }
  }

  final merged = {
    ...current.toJson(),
    ...incoming,
    // Imported files always carry the v1.1 meaning of certName.
    'configVersion': currentConfigVersion,
  };
  return SettingsImport(AppConfig.fromJson(merged),
      applied: applied, ignored: ignored, warnings: warnings);
}
