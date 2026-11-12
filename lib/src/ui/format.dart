import '../api/opnsense_client.dart';
import '../core/bypass.dart';
import '../core/config.dart';
import '../core/house_state.dart';

String formatDuration(Duration d) {
  if (d.isNegative) d = Duration.zero;
  final h = d.inHours;
  final m = d.inMinutes.remainder(60);
  final s = d.inSeconds.remainder(60);
  if (h > 0) return '${h}h ${m.toString().padLeft(2, '0')}m';
  if (m > 0) return '${m}m ${s.toString().padLeft(2, '0')}s';
  return '${s}s';
}

/// Label for a bypass duration choice.
String bypassDurationLabel(Duration d) =>
    isNoLimitDuration(d) ? 'Until I turn it off' : formatDuration(d);

String formatClock(DateTime t) {
  final l = t.toLocal();
  return '${l.hour.toString().padLeft(2, '0')}:${l.minute.toString().padLeft(2, '0')}';
}

String exitLabel(ProtonExit e, AppConfig cfg) => switch (e) {
      ProtonExit.main => '${cfg.mainLabel} (main)',
      ProtonExit.backup => '${cfg.backupLabel} (backup)',
      ProtonExit.none => 'No VPN exit',
      ProtonExit.unknown => 'Unknown',
    };

String errorHint(OpnsenseException e) => switch (e.kind) {
      ApiErrorKind.unauthorized => 'API key/secret rejected - check Settings.',
      ApiErrorKind.forbidden => 'The API user is missing a privilege (${e.endpoint}).',
      ApiErrorKind.notFound => 'Endpoint not found - check the base URL / OPNsense version.',
      ApiErrorKind.untrustedCertificate =>
        'Router certificate not trusted - re-run "Trust certificate" in Settings.',
      ApiErrorKind.network => 'Router unreachable: ${e.message}',
      ApiErrorKind.server => 'Router error: ${e.message}',
      ApiErrorKind.badResponse => e.message,
    };

/// One-line summary used by the tray tooltip, widget and header.
String headline(HouseSnapshot s, AppConfig cfg) {
  if (!s.configured) return 'Not set up';
  final err = s.error;
  if (err != null) return errorHint(err);
  if (s.bypassActive ?? false) {
    final e = s.bypassExpiresAt;
    final when = isNoLimitExpiry(e) ? ' - no time limit' : (e != null ? ' until ${formatClock(e)}' : '');
    return 'VPN BYPASS ON (whole house)$when';
  }
  final g = s.activeGateway;
  final ping = g?.delayMs != null ? ', ${g!.delayMs!.toStringAsFixed(0)} ms' : '';
  return switch (s.exit) {
    ProtonExit.main => 'VPN OK via ${cfg.mainLabel}$ping',
    ProtonExit.backup => 'FAILOVER: via ${cfg.backupLabel}$ping',
    ProtonExit.none => 'Both tunnels DOWN - kill switch tripped',
    ProtonExit.unknown => 'Gateways ${cfg.mainGateway}/${cfg.backupGateway} not found',
  };
}
