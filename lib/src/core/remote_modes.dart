/// v2.1 remote-access modes beyond "app only", and the phone's VPN-app
/// reminder. Pure logic (no platform calls) so it is unit-tested; the
/// platform side is lib/src/platform/vpn_modes.dart.
///
/// Modes ([AppConfig.mode]):
/// - `app`: only this app talks to the router (in-app tunnel, no VPN slot).
/// - `home`: a system VPN routes only the home devices (+ the router) into
///   the tunnel, so e.g. the NAS apps work from anywhere.
/// - `everything`: a system VPN routes all traffic to the house, where it
///   leaves through the house's VPN tunnels. IPv6 is routed in and dropped.
library;

import '../net/router_link.dart' show LinkState, LinkStatus;
import 'config.dart';
import 'network_map.dart';

/// Human labels used by Settings and the Status page.
const remoteModeLabels = {
  'app': 'App only',
  'home': 'Home devices only',
  'everything': 'Everything via home',
};

/// Short label for the status line ("Home devices" / "Everything").
String homeLinkLabel(String mode) => mode == 'everything' ? 'Everything' : 'Home devices';

/// Validates the "Home devices" text (IPv4 addresses or CIDRs, separated by
/// commas or spaces). Returns a plain-English problem, or null when fine.
/// [required] = the mode needs at least one entry.
String? homeDevicesError(String text, {bool required = false}) {
  final parts = [for (final p in text.split(RegExp(r'[,\s]+'))) if (p.trim().isNotEmpty) p.trim()];
  if (parts.isEmpty) return required ? 'Add at least one home device, e.g. the NAS (10.10.10.5)' : null;
  for (final p in parts) {
    final s = Ipv4Subnet.tryParse(p);
    final ip = ipv4ToInt(p.split('/').first);
    if (s == null || ip == null || (p.contains('/') && p.split('/')[1].isEmpty)) {
      return '"$p" is not an IPv4 address or CIDR (e.g. 10.10.10.5 or 10.10.10.0/24)';
    }
    if (s.prefix < 8) return '"$p" is far too wide - list home addresses or subnets only (/8 or narrower)';
    final first = ip >> 24;
    if (first == 0 || first == 127 || first >= 224 || (first == 169 && ((ip >> 16) & 0xff) == 254)) {
      return '"$p" is not a home device address';
    }
  }
  return null;
}

List<String> _dedupe(Iterable<String> xs) {
  final seen = <String>{};
  return [for (final x in xs) if (seen.add(x)) x];
}

/// Routes the system VPN asks the OS for.
/// home -> the home devices + the router (/32); everything -> default
/// routes for IPv4 and IPv6 (IPv6 is then dropped inside, so it can't leak).
List<String> systemVpnRoutes(AppConfig cfg) => switch (cfg.mode) {
      'home' => _dedupe([
          ...cfg.homeDeviceCidrs,
          if (cfg.routerTunnelIp != null) '${cfg.routerTunnelIp}/32',
        ]),
      'everything' => const ['0.0.0.0/0', '::/0'],
      _ => const [],
    };

/// Destinations the VPN core may connect to (others are refused). For
/// `everything` IPv4 only: IPv6 is routed in but refused.
List<String> systemVpnAllowed(AppConfig cfg) => switch (cfg.mode) {
      'everything' => const ['0.0.0.0/0'],
      _ => [for (final r in systemVpnRoutes(cfg)) if (!r.contains(':')) r],
    };

/// DNS server the system VPN announces: the router for `everything` (so
/// lookups go through the house like everything else), none for `home`
/// (the phone keeps its normal DNS).
String? systemVpnDns(AppConfig cfg) => cfg.mode == 'everything' ? cfg.routerTunnelIp : null;

/// AllowedIPs of the in-app WireGuard tunnel: the configured list plus what
/// the mode needs, so the user does not have to edit AllowedIPs by hand.
/// (WireGuard only carries packets for AllowedIPs.) Unchanged for `app`.
List<String> tunnelAllowedIps(AppConfig cfg) {
  final base = cfg.wgAllowedIpList;
  if (!cfg.remoteEnabled) return base;
  return switch (cfg.mode) {
    'home' => _dedupe([...base, ...cfg.homeDeviceCidrs]),
    'everything' => _dedupe([...base, '0.0.0.0/0']),
    _ => base,
  };
}

/// Problems that stop the chosen mode from working (empty = ready).
List<String> remoteModeProblems(AppConfig cfg) => [
      if (cfg.mode != 'app' && !cfg.remoteEnabled) 'Turn on remote access (WireGuard) first.',
      if (cfg.mode == 'home') ?homeDevicesError(cfg.homeDevices, required: true),
      if (cfg.mode != 'app' && cfg.routerTunnelIp == null) 'Set the router\'s LAN IP.',
    ];

/// Whether the system VPN should be up right now: a VPN mode is chosen and
/// the app is away from home with the WireGuard tunnel connected. At home
/// (router answers directly) it is off: the devices are reachable anyway.
bool wantsSystemVpn(AppConfig cfg, LinkStatus? link) =>
    cfg.remoteEnabled &&
    cfg.mode != 'app' &&
    remoteModeProblems(cfg).isEmpty &&
    link != null &&
    link.connected &&
    (link.viaTunnel || link.builtInTailscale);

// ---------------------------------------------------------------- reminder

enum Place { unknown, home, away }

/// Where the phone is according to the router link: home = the router
/// answered directly; away = it did not (or only through remote access);
/// unknown = not set up / wrong certificate (no conclusion).
Place placeFromLink(LinkStatus? link) {
  if (link == null) return Place.unknown;
  if (link.connected) return link.remote ? Place.away : Place.home;
  return link.state == LinkState.notHome ? Place.away : Place.unknown;
}

/// Reminder state between polls (immutable).
class ReminderState {
  const ReminderState({this.place = Place.unknown, this.candidate = Place.unknown, this.seen = 0, this.lastNotified});

  /// Place confirmed by [ReminderPolicy.confirmations] polls in a row.
  final Place place;

  /// Place seen most recently that differs from [place].
  final Place candidate;
  final int seen;
  final DateTime? lastNotified;
}

class ReminderPolicy {
  const ReminderPolicy({this.confirmations = 2, this.cooldown = const Duration(minutes: 20)});

  /// Polls in a row a new place must be seen before it counts (Wi-Fi edge).
  final int confirmations;

  /// No second reminder within this time.
  final Duration cooldown;
}

/// Which reminder to show.
enum ReminderKind { turnOff, turnOn }

/// One step of the reminder: the new state and, on a confirmed transition,
/// the reminder to show. Only transitions remind (never the first reading),
/// only when the VPN app is in the "wrong" state for the new place, and at
/// most once per cooldown.
(ReminderState, ReminderKind?) reminderStep(
  ReminderState s, {
  required Place now,
  required bool otherVpnActive,
  required DateTime at,
  ReminderPolicy policy = const ReminderPolicy(),
}) {
  if (now == Place.unknown || now == s.place) {
    return (ReminderState(place: s.place, lastNotified: s.lastNotified), null);
  }
  final seen = now == s.candidate ? s.seen + 1 : 1;
  if (seen < policy.confirmations) {
    return (ReminderState(place: s.place, candidate: now, seen: seen, lastNotified: s.lastNotified), null);
  }
  // Confirmed move to `now`.
  final first = s.place == Place.unknown;
  ReminderKind? kind;
  if (!first) {
    if (now == Place.home && otherVpnActive) kind = ReminderKind.turnOff;
    if (now == Place.away && !otherVpnActive) kind = ReminderKind.turnOn;
  }
  final last = s.lastNotified;
  if (kind != null && last != null && at.difference(last) < policy.cooldown) kind = null;
  return (ReminderState(place: now, lastNotified: kind != null ? at : last), kind);
}

/// Notification text (neutral: names the configured VPN, not a brand).
(String, String) reminderText(ReminderKind k, AppConfig cfg) {
  final name = cfg.vpnName.trim().isEmpty ? 'your VPN' : cfg.vpnName.trim();
  return switch (k) {
    ReminderKind.turnOff => (
        'You\'re home - you can turn your VPN app off',
        'The house already sends everything through $name.',
      ),
    ReminderKind.turnOn => (
        'You\'ve left home - turn your VPN app back on',
        'Away from the house this phone is not protected by $name until you turn it on.',
      ),
  };
}
