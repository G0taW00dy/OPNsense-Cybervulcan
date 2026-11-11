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

  static const _configKey = 'app_config_v1';

  AppConfig loadConfig() => AppConfig.decode(_p.getString(_configKey));

  Future<void> saveConfig(AppConfig c) => _p.setString(_configKey, c.encode());
}
