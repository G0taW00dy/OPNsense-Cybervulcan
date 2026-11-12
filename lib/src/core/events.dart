import 'bypass.dart';
import 'config.dart';
import 'house_state.dart';

enum AlertKind {
  failover,
  failback,
  bothDown,
  vpnRestored,
  bypassStarted,
  bypassEnded,
  bypassReminder,
  updateAvailable,
}

class AlertEvent {
  const AlertEvent(this.kind, this.title, this.body);

  final AlertKind kind;
  final String title;
  final String body;

  @override
  String toString() => 'AlertEvent($kind: $title)';
}

String _fmtTime(DateTime t) {
  final l = t.toLocal();
  return '${l.hour.toString().padLeft(2, '0')}:${l.minute.toString().padLeft(2, '0')}';
}

/// Pure diff of two snapshots -> notifications to raise.
/// Transitions to/from "unknown" (router unreachable) never alert, so a
/// flaky LAN link or the phone leaving home Wi-Fi does not spam.
List<AlertEvent> diffSnapshots(HouseSnapshot? prev, HouseSnapshot next, AppConfig cfg) {
  if (prev == null) return const [];
  final events = <AlertEvent>[];
  final a = prev.exit;
  final b = next.exit;

  if (cfg.notifyOnFailover && a != ProtonExit.unknown && b != ProtonExit.unknown && a != b) {
    if (a == ProtonExit.main && b == ProtonExit.backup) {
      events.add(AlertEvent(AlertKind.failover, 'Failed over to ${cfg.backupLabel}',
          '${cfg.mainLabel} tunnel is down. The house is now using the ${cfg.backupLabel} backup.'));
    } else if (a == ProtonExit.backup && b == ProtonExit.main) {
      events.add(AlertEvent(AlertKind.failback, 'Back on ${cfg.mainLabel}',
          '${cfg.mainLabel} tunnel recovered; traffic failed back from ${cfg.backupLabel}.'));
    } else if (b == ProtonExit.none) {
      events.add(const AlertEvent(AlertKind.bothDown, 'Both VPN tunnels down',
          'Kill switch tripped: the VPN network has no internet until a Proton tunnel recovers.'));
    } else if (a == ProtonExit.none) {
      final via = b == ProtonExit.main ? cfg.mainLabel : cfg.backupLabel;
      events.add(AlertEvent(AlertKind.vpnRestored, 'VPN restored',
          'Internet is back on the VPN network via $via.'));
    }
  }

  final wasBypass = prev.bypassActive;
  final isBypass = next.bypassActive;
  if (cfg.notifyOnBypass && wasBypass != null && isBypass != null && wasBypass != isBypass) {
    if (isBypass) {
      final until = next.bypassExpiresAt;
      events.add(AlertEvent(
          AlertKind.bypassStarted,
          'VPN bypass ON for the whole house',
          'Everyone on the VPN network now goes direct'
              '${isNoLimitExpiry(until) ? ' until someone turns it off' : until != null ? ' until ${_fmtTime(until)}' : ''}.'));
    } else {
      events.add(const AlertEvent(AlertKind.bypassEnded, 'VPN bypass ended',
          'The VPN network is back on Proton.'));
    }
  }
  return events;
}
