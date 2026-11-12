import '../api/opnsense_client.dart';
import 'config.dart';
import 'network_map.dart';
import 'states.dart';

/// Tiny key/value abstraction so the logic is testable without plugins.
abstract class KeyValueStore {
  String? getString(String key);
  Future<void> setString(String key, String value);
  Future<void> remove(String key);
}

class MemoryStore implements KeyValueStore {
  final Map<String, String> data = {};
  @override
  String? getString(String key) => data[key];
  @override
  Future<void> setString(String key, String value) async {
    data[key] = value;
  }

  @override
  Future<void> remove(String key) async {
    data.remove(key);
  }
}

// ----------------------------------------------------------- expiry marker
//
// The bypass deadline is stored *on the router* as an extra entry in the
// runtime BYPASS_ALL table: 240.0.0.0/4 (reserved, never a real source on the
// LAN) + the expiry time in epoch minutes (28 bits, good until year 2480).
// Every device running Cybervulcan sees the same deadline and the marker
// disappears with the table on router reboot - exactly like the bypass itself.

const _markerBase = 0xF0000000; // 240.0.0.0

String encodeExpiryMarker(DateTime expiry) {
  final minutes = (expiry.toUtc().millisecondsSinceEpoch / 60000).ceil();
  if (minutes < 0 || minutes >= (1 << 28)) {
    throw ArgumentError.value(expiry, 'expiry', 'out of marker range');
  }
  return intToIpv4(_markerBase | minutes);
}

/// Returns the expiry encoded in a table entry, or null if it is not a marker.
DateTime? decodeExpiryMarker(String entry) {
  final ip = ipv4ToInt(entry.split('/').first);
  if (ip == null || (ip & 0xF0000000) != _markerBase) return null;
  final minutes = ip & 0x0FFFFFFF;
  return DateTime.fromMillisecondsSinceEpoch(minutes * 60000, isUtc: true);
}

class BypassState {
  const BypassState({required this.active, this.expiresAt, this.markers = const []});

  final bool active;
  final DateTime? expiresAt;
  final List<String> markers;

  /// Remaining time, never negative; null when no deadline is known.
  Duration? remaining(DateTime now) {
    final e = expiresAt;
    if (e == null) return null;
    final d = e.difference(now);
    return d.isNegative ? Duration.zero : d;
  }
}

const localExpiryKey = 'bypass_expires_at';

/// "No time limit" bypass: the deadline is set ~400 years ahead (still inside
/// the marker's 28-bit range), so it never expires and only ends when someone
/// turns it off. Everything else (marker, local copy) works unchanged.
const bypassNoLimit = Duration(days: 365 * 400);

/// True for a deadline created with [bypassNoLimit].
bool isNoLimitExpiry(DateTime? expiry) => expiry != null && expiry.toUtc().year >= 2300;

/// True for a configured/selected duration meaning "no time limit".
bool isNoLimitDuration(Duration d) => d >= const Duration(days: 365 * 100);

/// Derives the bypass state from the raw table entries (+ local fallback).
BypassState readBypassState(List<String> entries, AppConfig cfg, {String? localExpiryIso}) {
  final active = entries.any((e) => tableEntryMatches(e, cfg.bypassNetwork));
  final markers = <String>[];
  DateTime? expiry;
  for (final e in entries) {
    final m = decodeExpiryMarker(e);
    if (m != null) {
      markers.add(e.split('/').first);
      // If several markers exist (two devices raced), the earliest wins.
      if (expiry == null || m.isBefore(expiry)) expiry = m;
    }
  }
  if (expiry == null && localExpiryIso != null) {
    expiry = DateTime.tryParse(localExpiryIso)?.toUtc();
  }
  return BypassState(active: active, expiresAt: active ? expiry : null, markers: markers);
}

enum EnforceAction { none, expiredTurnedOff, adoptedWithNewDeadline, clearedStaleLocal }

/// Whole-house VPN bypass: on = add the VPN network to BYPASS_ALL,
/// off = flush it. Expiry is enforced on every poll and at app start.
class BypassManager {
  BypassManager({
    required this.client,
    required this.config,
    required this.store,
    DateTime Function()? clock,
  }) : clock = clock ?? DateTime.now;

  final OpnsenseClient client;
  final AppConfig config;
  final KeyValueStore store;
  final DateTime Function() clock;

  /// Result of the pf state kill done by the last [turnOn]/[turnOff].
  StateKillResult? lastKill;

  Future<BypassState> read() async {
    final entries = await client.aliasList(config.bypassAlias);
    return readBypassState(entries, config, localExpiryIso: store.getString(localExpiryKey));
  }

  Future<BypassState> turnOn({Duration? duration}) async {
    final d = duration ?? config.bypassDuration;
    final expiry = clock().toUtc().add(d);
    final before = await client.aliasList(config.bypassAlias);
    // Write the deadline first, so a crash between calls can never leave a
    // bypass on the router without an expiry.
    await store.setString(localExpiryKey, expiry.toIso8601String());
    if (config.useExpiryMarker) {
      final marker = encodeExpiryMarker(expiry);
      await client.aliasAdd(config.bypassAlias, marker);
      for (final e in before) {
        if (decodeExpiryMarker(e) != null && e.split('/').first != marker) {
          await client.aliasDelete(config.bypassAlias, e.split('/').first);
        }
      }
    }
    await client.aliasAdd(config.bypassAlias, config.bypassNetwork);
    final after = await read();
    if (!after.active) {
      throw OpnsenseException(ApiErrorKind.server,
          'Router accepted the request but ${config.bypassNetwork} is not in ${config.bypassAlias}');
    }
    // Existing VPN connections would otherwise stay on Proton.
    lastKill = await killStatesFor(client, config.bypassNetwork);
    return after;
  }

  Future<BypassState> turnOff() async {
    try {
      await client.aliasFlush(config.bypassAlias);
    } on OpnsenseException catch (e) {
      if (e.kind != ApiErrorKind.forbidden && e.kind != ApiErrorKind.notFound &&
          e.kind != ApiErrorKind.server) {
        rethrow;
      }
      // Fallback: remove entries one by one.
      for (final entry in await client.aliasList(config.bypassAlias)) {
        await client.aliasDelete(config.bypassAlias, entry);
      }
    }
    await store.remove(localExpiryKey);
    final after = await read();
    if (after.active) {
      throw OpnsenseException(ApiErrorKind.server,
          '${config.bypassNetwork} is still in ${config.bypassAlias} after removal');
    }
    // Direct connections must not outlive the bypass (also on auto-expiry).
    lastKill = await killStatesFor(client, config.bypassNetwork);
    return after;
  }

  /// Called at start-up and on every poll.
  Future<(EnforceAction, BypassState)> enforce(BypassState state) async {
    final now = clock().toUtc();
    if (!state.active) {
      if (store.getString(localExpiryKey) != null) {
        await store.remove(localExpiryKey);
        return (EnforceAction.clearedStaleLocal, state);
      }
      return (EnforceAction.none, state);
    }
    final expiry = state.expiresAt;
    if (expiry == null) {
      // Turned on elsewhere (e.g. GUI) with no deadline: give it one. Never
      // "no time limit" here - nobody confirmed a whole-house bypass on this
      // device, so cap it at the normal default.
      final adopt = isNoLimitDuration(config.bypassDuration)
          ? const Duration(hours: 2)
          : config.bypassDuration;
      final newExpiry = now.add(adopt);
      await store.setString(localExpiryKey, newExpiry.toIso8601String());
      if (config.useExpiryMarker) {
        await client.aliasAdd(config.bypassAlias, encodeExpiryMarker(newExpiry));
      }
      return (
        EnforceAction.adoptedWithNewDeadline,
        BypassState(active: true, expiresAt: newExpiry, markers: state.markers),
      );
    }
    if (!now.isBefore(expiry)) {
      final after = await turnOff();
      return (EnforceAction.expiredTurnedOff, after);
    }
    return (EnforceAction.none, state);
  }
}
