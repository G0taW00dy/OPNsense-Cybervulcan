import 'package:local_auth/local_auth.dart';

/// App lock (v2.0): the device's own fingerprint / face / PIN / Windows Hello.
/// Cybervulcan never sees or stores the biometric or the PIN.
class AppLock {
  AppLock([LocalAuthentication? auth]) : _auth = auth ?? LocalAuthentication();

  final LocalAuthentication _auth;

  /// True when this device has a screen lock / Windows Hello to ask for.
  Future<bool> supported() async {
    try {
      return await _auth.isDeviceSupported();
    } on Object {
      return false;
    }
  }

  /// Shows the system prompt. Any error counts as "not unlocked".
  Future<bool> authorize(String reason) async {
    try {
      return await _auth.authenticate(localizedReason: reason, persistAcrossBackgrounding: true);
    } on Object {
      return false;
    }
  }
}
