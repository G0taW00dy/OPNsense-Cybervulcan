import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'bypass.dart';
import 'config.dart';

/// API key + secret, kept only in OS secure storage:
/// Windows Credential Manager/DPAPI, Android Keystore-backed storage.
class ApiCredentials {
  const ApiCredentials(this.key, this.secret);
  final String key;
  final String secret;

  bool get isComplete => key.isNotEmpty && secret.isNotEmpty;
}

class SecretStore {
  SecretStore([FlutterSecureStorage? storage]) : _s = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _s;
  static const _kKey = 'opnsense_api_key';
  static const _kSecret = 'opnsense_api_secret';

  Future<ApiCredentials?> read() async {
    final k = await _s.read(key: _kKey);
    final s = await _s.read(key: _kSecret);
    if (k == null || s == null || k.isEmpty || s.isEmpty) return null;
    return ApiCredentials(k, s);
  }

  Future<void> write(ApiCredentials c) async {
    await _s.write(key: _kKey, value: c.key.trim());
    await _s.write(key: _kSecret, value: c.secret.trim());
  }

  Future<void> clear() async {
    await _s.delete(key: _kKey);
    await _s.delete(key: _kSecret);
  }

  // ---- WireGuard (remote access). Never shown, exported or logged.
  static const _kWgPrivate = 'wg_private_key';
  static const _kWgPsk = 'wg_preshared_key';

  Future<WireGuardSecrets> readWireGuard() async => WireGuardSecrets(
        privateKey: await _s.read(key: _kWgPrivate),
        presharedKey: await _s.read(key: _kWgPsk),
      );

  Future<void> writeWireGuardPrivateKey(String key) => _s.write(key: _kWgPrivate, value: key.trim());

  /// Empty or null removes the pre-shared key.
  Future<void> writeWireGuardPresharedKey(String? key) async {
    final k = key?.trim() ?? '';
    if (k.isEmpty) {
      await _s.delete(key: _kWgPsk);
    } else {
      await _s.write(key: _kWgPsk, value: k);
    }
  }

  Future<void> clearWireGuard() async {
    await _s.delete(key: _kWgPrivate);
    await _s.delete(key: _kWgPsk);
  }
}

/// This app's WireGuard secrets (from secure storage).
class WireGuardSecrets {
  const WireGuardSecrets({this.privateKey, this.presharedKey});

  final String? privateKey;
  final String? presharedKey;

  bool get hasPrivateKey => privateKey != null && privateKey!.isNotEmpty;
}

class PrefsStore implements KeyValueStore {
  PrefsStore(this._p);
  final SharedPreferences _p;

  static Future<PrefsStore> open() async {
    final p = await SharedPreferences.getInstance();
    // Another isolate (Android widget/tile callback) may have written.
    await p.reload();
    return PrefsStore(p);
  }

  @override
  String? getString(String key) => _p.getString(key);

  @override
  Future<void> setString(String key, String value) => _p.setString(key, value);

  @override
  Future<void> remove(String key) => _p.remove(key);

  // Kept as "v1" so settings from 1.0.x load (and migrate) unchanged.
  static const _configKey = 'app_config_v1';

  static const trayHintKey = 'tray_hint_shown';

  bool flag(String key) => _p.getString(key) == '1';

  Future<void> setFlag(String key) => _p.setString(key, '1');

  AppConfig loadConfig() => AppConfig.decode(_p.getString(_configKey));

  Future<void> saveConfig(AppConfig c) => _p.setString(_configKey, c.encode());
}
