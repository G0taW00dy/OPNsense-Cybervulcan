import 'dart:io';

/// "Start in the tray when I sign in" on Windows: the same per-user Run key
/// value the installer's autostart option writes, so both stay in step.
class WindowsAutostart {
  static const _runKey = r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';
  static const _valueName = 'Cybervulcan';

  static bool get supported => Platform.isWindows;

  static Future<bool> isEnabled() async {
    if (!supported) return false;
    final r = await Process.run('reg', ['query', _runKey, '/v', _valueName]);
    return r.exitCode == 0;
  }

  /// Returns true if the change was applied.
  static Future<bool> setEnabled(bool on) async {
    if (!supported) return false;
    final args = on
        ? [
            'add', _runKey, '/v', _valueName, '/t', 'REG_SZ', //
            '/d', '"${Platform.resolvedExecutable}" --minimized', '/f',
          ]
        : ['delete', _runKey, '/v', _valueName, '/f'];
    final r = await Process.run('reg', args);
    return r.exitCode == 0;
  }
}
