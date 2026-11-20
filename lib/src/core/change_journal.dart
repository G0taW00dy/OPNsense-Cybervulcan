import 'dart:convert';

import 'bypass.dart' show KeyValueStore;

/// Router safety net (v2.1), part 1: a short journal of every change the app
/// made on the router, so "what did the app do last night?" has an answer.
///
/// The other parts live with each change: a server switch remembers the old
/// server, waits for a real handshake and puts the old one back if the new
/// one never answers; the shaper tuner keeps the original limits so they can
/// be restored. OPNsense itself also keeps every API change as a config
/// revision (System > Configuration > History), which the admin can revert.
/// The app deliberately does NOT download full config backups: that would
/// need a privilege that can read every secret on the router.
class ChangeEntry {
  const ChangeEntry({required this.at, required this.what, required this.ok, this.detail});

  final DateTime at;
  final String what;
  final bool ok;
  final String? detail;

  Map<String, Object?> toJson() =>
      {'at': at.toUtc().toIso8601String(), 'what': what, 'ok': ok, if (detail != null) 'detail': detail};

  static ChangeEntry? fromJson(Object? j) {
    if (j is! Map) return null;
    final at = DateTime.tryParse('${j['at']}');
    if (at == null || j['what'] is! String) return null;
    return ChangeEntry(at: at, what: j['what'] as String, ok: j['ok'] == true, detail: j['detail'] as String?);
  }
}

class ChangeJournal {
  ChangeJournal(this._store, {this.max = 40});

  static const key = 'router_changes_v1';
  final KeyValueStore _store;
  final int max;

  List<ChangeEntry> get entries {
    try {
      final raw = jsonDecode(_store.getString(key) ?? '[]');
      if (raw is! List) return const [];
      return [for (final e in raw) ?ChangeEntry.fromJson(e)];
    } on FormatException {
      return const [];
    }
  }

  Future<void> add(String what, {required bool ok, String? detail, DateTime? at}) async {
    final list = [ChangeEntry(at: at ?? DateTime.now(), what: what, ok: ok, detail: detail), ...entries];
    await _store.setString(key, jsonEncode([for (final e in list.take(max)) e.toJson()]));
  }

  Future<void> clear() => _store.remove(key);
}
