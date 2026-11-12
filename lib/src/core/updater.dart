import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';

/// The running version. CI passes it with `--dart-define=APP_VERSION=x.y.z`
/// (same value as `--build-name`); local builds fall back to pubspec's.
const appVersion = String.fromEnvironment('APP_VERSION', defaultValue: '1.0.1');

/// Where releases are published, as `owner/repo`. Must be a repo whose
/// releases can be read without signing in (public). Override at build time
/// with `--dart-define=UPDATE_REPO=owner/repo`, e.g. a public releases-only
/// repo if the code repo goes private.
const updateRepo =
    String.fromEnvironment('UPDATE_REPO', defaultValue: 'G0taW00dy/OPNsense-Cybervulcan');

enum UpdateTarget { windows, android }

/// Compares dotted versions numerically (`1.10.0` > `1.9.2`). A leading `v`,
/// a `-pre` suffix and `+build` metadata are ignored.
int compareVersions(String a, String b) {
  List<int> parts(String v) {
    var s = v.trim();
    if (s.startsWith('v') || s.startsWith('V')) s = s.substring(1);
    s = s.split('+').first.split('-').first;
    return [for (final p in s.split('.')) int.tryParse(p) ?? 0];
  }

  final x = parts(a);
  final y = parts(b);
  for (var i = 0; i < (x.length > y.length ? x.length : y.length); i++) {
    final d = (i < x.length ? x[i] : 0) - (i < y.length ? y[i] : 0);
    if (d != 0) return d.sign;
  }
  return 0;
}

class ReleaseAsset {
  const ReleaseAsset({required this.name, required this.url, this.sha256});

  final String name;
  final Uri url;

  /// Lower-case hex SHA-256 from GitHub's asset `digest`, when present.
  final String? sha256;
}

class ReleaseInfo {
  const ReleaseInfo({
    required this.version,
    required this.pageUrl,
    this.asset,
    this.notes = '',
  });

  final String version;
  final Uri pageUrl;

  /// The installer (.exe) or APK for this platform; null if the release has none.
  final ReleaseAsset? asset;
  final String notes;

  /// Parses a GitHub `releases/latest` response. Returns null for drafts,
  /// pre-releases or malformed data.
  static ReleaseInfo? fromGitHub(Map<String, dynamic> j, UpdateTarget target) {
    if (j['draft'] == true || j['prerelease'] == true) return null;
    final tag = j['tag_name'];
    final page = Uri.tryParse('${j['html_url'] ?? ''}');
    if (tag is! String || tag.isEmpty || page == null || !_isGitHub(page)) return null;
    final ext = target == UpdateTarget.windows ? '.exe' : '.apk';
    ReleaseAsset? asset;
    final assets = j['assets'];
    if (assets is List) {
      for (final a in assets.whereType<Map<String, dynamic>>()) {
        final name = a['name'];
        final url = Uri.tryParse('${a['browser_download_url'] ?? ''}');
        if (name is! String || !name.toLowerCase().endsWith(ext) || url == null || !_isGitHub(url)) {
          continue;
        }
        final digest = a['digest'];
        final sha = digest is String && digest.startsWith('sha256:')
            ? digest.substring(7).toLowerCase()
            : null;
        asset = ReleaseAsset(name: name, url: url, sha256: sha);
        break;
      }
    }
    final version = tag.startsWith('v') || tag.startsWith('V') ? tag.substring(1) : tag;
    return ReleaseInfo(version: version, pageUrl: page, asset: asset, notes: '${j['body'] ?? ''}');
  }
}

bool _isGitHub(Uri u) => u.scheme == 'https' && (u.host == 'github.com' || u.host.endsWith('.github.com'));

class UpdateException implements Exception {
  UpdateException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// Checks GitHub Releases for a newer version and, on Windows, downloads and
/// runs the installer. On Android the APK link is opened in the browser.
class UpdateService extends ChangeNotifier {
  UpdateService({
    required this.target,
    http.Client? client,
    this.repo = updateRepo,
    this.currentVersion = appVersion,
    this.checkEvery = const Duration(hours: 12),
    bool Function()? autoCheck,
  })  : _http = client ?? http.Client(),
        _autoCheck = autoCheck ?? (() => true);

  final bool Function() _autoCheck;

  final UpdateTarget target;
  final String repo;
  final String currentVersion;
  final Duration checkEvery;
  final http.Client _http;

  ReleaseInfo? available;
  bool checking = false;
  String? error;
  DateTime? lastChecked;

  /// 0..1 while the installer downloads, null otherwise.
  double? downloadProgress;

  /// Windows: closes the app cleanly (tray icon, window) before the installer
  /// runs. Set by main(); falls back to exit(0).
  Future<void> Function()? quitApp;

  final _found = StreamController<ReleaseInfo>.broadcast();

  /// Fires once per newly found version (for a notification).
  Stream<ReleaseInfo> get found => _found.stream;
  String? _announced;
  Timer? _timer;

  /// Starts automatic checks. Each one is skipped while [autoCheck] is false
  /// (Settings > Updates); "Check now" always works.
  void start() {
    if (_autoCheck()) unawaited(check());
    _timer = Timer.periodic(checkEvery, (_) {
      if (_autoCheck()) unawaited(check());
    });
  }

  Future<void> check() async {
    if (checking) return;
    checking = true;
    error = null;
    notifyListeners();
    try {
      final res = await _http.get(
        Uri.https('api.github.com', '/repos/$repo/releases/latest'),
        headers: {
          'Accept': 'application/vnd.github+json',
          'User-Agent': 'Cybervulcan/$currentVersion',
        },
      ).timeout(const Duration(seconds: 15));
      lastChecked = DateTime.now();
      if (res.statusCode == 404) {
        available = null; // no release yet, or the repo is private
        return;
      }
      if (res.statusCode != 200) {
        throw UpdateException('GitHub answered ${res.statusCode}');
      }
      final info = ReleaseInfo.fromGitHub(jsonDecode(res.body) as Map<String, dynamic>, target);
      available = info != null && compareVersions(info.version, currentVersion) > 0 ? info : null;
      final a = available;
      if (a != null && a.version != _announced) {
        _announced = a.version;
        _found.add(a);
      }
    } on UpdateException catch (e) {
      error = e.message;
    } on Object catch (e) {
      error = 'Update check failed: $e';
    } finally {
      checking = false;
      notifyListeners();
    }
  }

  static const _android = MethodChannel('au.cybervulcan.opnsense/updater');

  /// Installs [available]. Windows downloads and runs the installer (the app
  /// closes and reopens). Android downloads the APK into the app's cache,
  /// checks its SHA-256 and opens Android's installer, where you tap Update.
  /// Android never lets a sideloaded app update itself silently.
  Future<void> install() async {
    final r = available;
    if (r == null) return;
    try {
      if (target == UpdateTarget.windows) {
        final file = await downloadInstaller(r);
        await runInstallerAndQuit(file, quitApp ?? () async => exit(0));
      } else {
        final allowed = await _android.invokeMethod<bool>('canInstall') ?? false;
        if (!allowed) {
          await _android.invokeMethod<void>('openInstallSettings');
          throw UpdateException('Turn on "Allow from this source" for Cybervulcan in the screen '
              'that just opened, come back, then tap Install now again.');
        }
        final dirPath = await _android.invokeMethod<String>('updatesDir');
        if (dirPath == null) throw UpdateException('No folder for the update download.');
        final file = await downloadInstaller(r, into: Directory(dirPath));
        await _android.invokeMethod<bool>('installApk', {'path': file.path});
      }
    } on UpdateException catch (e) {
      error = e.message;
      notifyListeners();
    } on Object catch (e) {
      error = 'Update failed: $e';
      notifyListeners();
    }
  }

  /// Opens the release notes on GitHub.
  Future<void> openReleasePage() async {
    final r = available;
    if (r != null) await launchUrl(r.pageUrl, mode: LaunchMode.externalApplication);
  }

  /// Downloads the installer/APK (to a new temp folder, or into [into] after
  /// emptying it), checks its SHA-256 against GitHub's digest and returns it.
  Future<File> downloadInstaller(ReleaseInfo r, {Directory? into}) async {
    final asset = r.asset;
    if (asset == null) throw UpdateException('This release has no installer attached.');
    // Fail closed: never run an installer whose checksum cannot be checked.
    final want = asset.sha256;
    if (want == null || !RegExp(r'^[0-9a-f]{64}$').hasMatch(want)) {
      throw UpdateException('This release has no SHA-256 digest - not installing. '
          'Download it manually from the release page.');
    }
    downloadProgress = 0;
    error = null;
    notifyListeners();
    try {
      final res = await _http.send(http.Request('GET', asset.url));
      if (res.statusCode != 200) throw UpdateException('Download failed (${res.statusCode}).');
      final total = res.contentLength ?? 0;
      final Directory dir;
      if (into != null) {
        dir = into;
        await dir.create(recursive: true);
        await for (final old in dir.list()) {
          await old.delete(recursive: true); // never leave an older APK lying around
        }
      } else {
        dir = await Directory.systemTemp.createTemp('cybervulcan-update-');
      }
      final safeName = asset.name.replaceAll(RegExp(r'[^A-Za-z0-9._-]'), '_');
      final file = File('${dir.path}${Platform.pathSeparator}$safeName');
      final sink = file.openWrite();
      final hashOut = _DigestSink();
      final hasher = sha256.startChunkedConversion(hashOut);
      var received = 0;
      await for (final chunk in res.stream) {
        sink.add(chunk);
        hasher.add(chunk);
        received += chunk.length;
        if (total > 0) {
          downloadProgress = received / total;
          notifyListeners();
        }
      }
      await sink.close();
      hasher.close();
      if (hashOut.value.toString() != want) {
        await file.delete();
        throw UpdateException('Downloaded installer failed its checksum check - not installing.');
      }
      return file;
    } finally {
      downloadProgress = null;
      notifyListeners();
    }
  }

  /// Windows: starts the installer silently a few seconds from now (so this
  /// app has exited and released its single-instance mutex), then calls
  /// [quitApp]. The installer relaunches the app when it finishes.
  Future<void> runInstallerAndQuit(File installer, Future<void> Function() quitApp) async {
    // Refuse paths that cmd.exe would reinterpret inside a batch file
    // (% expansion, quotes) or mangle (non-ASCII: batch files are read in the
    // OEM code page).
    if (RegExp(r'[%"^!\r\n]|[^\x20-\x7E]').hasMatch(installer.path)) {
      throw UpdateException('Unusual temp folder path - install the update manually.');
    }
    // Absolute System32 paths: never resolve cmd/ping from the current or
    // application directory.
    final sys32 = '${Platform.environment['SystemRoot'] ?? r'C:\Windows'}\\System32';
    final script = File('${installer.parent.path}${Platform.pathSeparator}run-update.cmd');
    await script.writeAsString([
      '@echo off',
      '"$sys32\\PING.EXE" -n 4 127.0.0.1 >nul',
      'start "" "${installer.path}" /SILENT /SUPPRESSMSGBOXES /NORESTART',
      '',
    ].join('\r\n'));
    await Process.start('$sys32\\cmd.exe', ['/c', script.path],
        mode: ProcessStartMode.detached, workingDirectory: installer.parent.path);
    await quitApp();
  }

  @override
  void dispose() {
    _timer?.cancel();
    _http.close();
    unawaited(_found.close());
    super.dispose();
  }
}

class _DigestSink implements Sink<Digest> {
  late Digest value;
  @override
  void add(Digest data) => value = data;
  @override
  void close() {}
}
