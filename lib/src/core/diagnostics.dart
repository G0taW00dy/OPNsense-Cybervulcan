import 'dart:convert';
import 'dart:io';

import 'bypass.dart' show KeyValueStore;
import 'change_journal.dart';
import 'config.dart';
import 'house_state.dart';

/// "Copy diagnostics" (v2.1): what a bug report needs, nothing private.
///
/// Never included: API key/secret, WireGuard keys, the app PIN, certificate
/// pins. Blanked: public IP addresses, domain names, tunnel public keys.
/// Kept: private (house) addresses like 10.x/192.168.x - they are the same
/// on every install of this setup and are what bugs are usually about.

/// Recent app errors (uncaught exceptions), newest first, already redacted.
class ErrorLog {
  ErrorLog(this._store, {this.max = 8});
  static const key = 'recent_errors_v1';
  final KeyValueStore _store;
  final int max;

  List<String> get entries {
    try {
      final raw = jsonDecode(_store.getString(key) ?? '[]');
      return raw is List ? [for (final e in raw) '$e'] : const [];
    } on FormatException {
      return const [];
    }
  }

  Future<void> add(Object error, StackTrace? stack, {DateTime? at}) async {
    final when = (at ?? DateTime.now()).toUtc().toIso8601String();
    final frames = (stack?.toString() ?? '').split('\n').where((l) => l.trim().isNotEmpty).take(12).join('\n');
    var text = redact('$when $error\n$frames');
    if (text.length > 2000) text = '${text.substring(0, 2000)}...';
    await _store.setString(key, jsonEncode([text, ...entries].take(max).toList()));
  }

  Future<void> clear() => _store.remove(key);
}

final _ipv4 = RegExp(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b');
final _wgKey = RegExp(r'\b[A-Za-z0-9+/]{43}=');
// Long API key/secret-like tokens (OPNsense keys are ~80 chars of base64).
final _longToken = RegExp(r'\b[A-Za-z0-9+/]{40,}={0,2}');
// IPv6 addresses (anything with 2+ colons and hex groups); link-local and
// unique-local (fe80::/10, fc00::/7) are kept.
final _ipv6 = RegExp(r'(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}(?::?[0-9a-fA-F]{1,4}|:)(?![\w:])');
// Real-looking host names only (common TLDs + 2-letter country codes), so
// code references like `ApiErrorKind.forbidden` in error texts survive.
final _domain = RegExp(
    r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|app|me|info|biz|xyz|cloud|online|site|'
    r'tech|arpa|local|lan|home|[a-z]{2})\b',
    caseSensitive: false);

/// Hosts that are part of how the app works, not the person's own names.
const _publicServiceHosts = {
  'bash.ws', 'speed.cloudflare.com', 'api.ipify.org', 'api6.ipify.org', 'ipwho.is', 'whoami.akamai.net',
  'api.mullvad.net', 'github.com', 'api.github.com', 'example.com', 'router.example.com',
};

bool _privateV4(int a, int b) =>
    a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 100 && b >= 64 && b <= 127) || a == 0;

/// Blanks public IPv4 addresses, domain names and WireGuard keys.
String redact(String s) {
  var out = s.replaceAll(_wgKey, '<key>').replaceAll(_longToken, '<token>');
  out = out.replaceAllMapped(_ipv6, (m) {
    final h = m.group(0)!.toLowerCase();
    // Clock times like 12:17:39 look similar: real IPv6 has :: or a hex letter.
    if (!h.contains('::') && !RegExp('[a-f]').hasMatch(h)) return m.group(0)!;
    return h.startsWith('fe8') || h.startsWith('fc') || h.startsWith('fd') ? m.group(0)! : '<public-ip6>';
  });
  out = out.replaceAllMapped(_ipv4, (m) {
    final p = [for (var i = 1; i <= 4; i++) int.parse(m.group(i)!)];
    if (p.any((x) => x > 255)) return m.group(0)!;
    return _privateV4(p[0], p[1]) ? m.group(0)! : '<public-ip>';
  });
  out = out.replaceAllMapped(_domain, (m) {
    final h = m.group(0)!.toLowerCase();
    // Dart files and similar look like domains; keep them.
    if (RegExp(r'\.(dart|kt|go|so|dll|exe|json|yaml|conf|txt)$').hasMatch(h)) return m.group(0)!;
    return _publicServiceHosts.contains(h) ? m.group(0)! : '<domain>';
  });
  return out;
}

/// Settings that matter for bugs; personal values are redacted.
Map<String, Object?> _configSummary(AppConfig c) => {
      'router': c.isPlainHttp ? 'http' : 'https',
      'routerIsName': c.routerAddressIsName,
      'certPinned': c.pinnedCertSha256 != null,
      'gateways': '${c.mainGateway} / ${c.backupGateway}',
      'aliases': '${c.bypassAlias} / ${c.pcModeAlias}',
      'killSwitchTag': c.killSwitchTag,
      'provider': c.providerId,
      'serverSwitcher': c.serverSwitcherEnabled,
      'instances': '${c.mainWgInstance} / ${c.backupWgInstance}',
      'remote': c.remoteEnabled ? '${c.transport}/${c.mode}${c.tailscaleBuiltIn ? '/builtin-ts' : ''}' : 'off',
      'appLock': c.appLock,
      'shaperAutoTune': c.shaperAutoTune,
      'externalTests': c.externalTests,
      'networks': [for (final n in c.networks) '${n.name} ${n.cidr}'],
      'pollSeconds': c.pollInterval.inSeconds,
    };

String buildDiagnostics({
  required String appVersion,
  required AppConfig config,
  required HouseSnapshot snapshot,
  required List<ChangeEntry> changes,
  required List<String> errors,
  String? linkStatus,
  String? lastError,
}) {
  final b = StringBuffer()
    ..writeln('Cybervulcan diagnostics')
    ..writeln('App $appVersion on ${Platform.operatingSystem} ${Platform.operatingSystemVersion}')
    ..writeln('Generated ${DateTime.now().toUtc().toIso8601String()}')
    ..writeln()
    ..writeln('## Settings (personal values removed)')
    ..writeln(const JsonEncoder.withIndent('  ').convert(_configSummary(config)))
    ..writeln()
    ..writeln('## Status')
    ..writeln('configured=${snapshot.configured} reachable=${snapshot.reachable} exit=${snapshot.exit.name} '
        'bypass=${snapshot.bypassActive}')
    ..writeln('main: ${snapshot.main?.statusText ?? '-'} ${snapshot.main?.delayMs?.toStringAsFixed(0) ?? '-'} ms '
        'loss ${snapshot.main?.lossPercent ?? '-'} %')
    ..writeln('backup: ${snapshot.backup?.statusText ?? '-'} ${snapshot.backup?.delayMs?.toStringAsFixed(0) ?? '-'} ms '
        'loss ${snapshot.backup?.lossPercent ?? '-'} %');
  if (linkStatus != null) b.writeln('link: $linkStatus');
  if (lastError != null) b.writeln('last error: $lastError');
  b
    ..writeln()
    ..writeln('## Recent router changes by the app');
  if (changes.isEmpty) b.writeln('(none)');
  for (final c in changes.take(15)) {
    b.writeln('${c.at.toUtc().toIso8601String()} ${c.ok ? 'OK  ' : 'FAIL'} ${c.what}${c.detail == null ? '' : ' - ${c.detail}'}');
  }
  b
    ..writeln()
    ..writeln('## Recent app errors');
  if (errors.isEmpty) b.writeln('(none)');
  for (final e in errors) {
    b
      ..writeln(e)
      ..writeln('--');
  }
  return redact(b.toString());
}
