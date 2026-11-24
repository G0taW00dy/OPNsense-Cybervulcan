/// Saved shaper settings (v2.1.13).
///
/// * Presets: named limits for both paths, e.g. "NBN 500", "Boost 1000/100"
///   (a paid speed-boost day) or "Away mode" (a slower plan while away). One
///   tap puts them on the router.
/// * City limits: the tunnel's real speed depends on the VPN server's city
///   (Tokyo 413 vs a nearer city), so tunnel limits can be remembered per
///   city and put back by themselves when the main tunnel moves there.
///
/// Kept on this device (preferences), not on the router.
library;

import 'dart:convert';

class ShaperPreset {
  const ShaperPreset({
    required this.name,
    this.tunnelDown,
    this.tunnelUp,
    this.lineDown,
    this.lineUp,
  });

  final String name;

  /// Limits in Mbit/s; null = leave that path as it is.
  final int? tunnelDown, tunnelUp, lineDown, lineUp;

  bool get hasTunnel => tunnelDown != null && tunnelUp != null;
  bool get hasLine => lineDown != null && lineUp != null;

  String get summary => [
        if (hasTunnel) 'tunnel $tunnelDown/$tunnelUp',
        if (hasLine) 'line $lineDown/$lineUp',
      ].join(', ');

  Map<String, dynamic> toJson() => {
        'name': name,
        if (tunnelDown != null) 'td': tunnelDown,
        if (tunnelUp != null) 'tu': tunnelUp,
        if (lineDown != null) 'ld': lineDown,
        if (lineUp != null) 'lu': lineUp,
      };

  static int? _i(Object? v) {
    final n = v is num ? v.toInt() : int.tryParse('${v ?? ''}');
    return n == null || n < 1 || n > 100000 ? null : n;
  }

  static ShaperPreset? fromJson(Object? j) {
    if (j is! Map) return null;
    final name = '${j['name'] ?? ''}'.trim();
    if (name.isEmpty) return null;
    final p = ShaperPreset(name: name, tunnelDown: _i(j['td']), tunnelUp: _i(j['tu']), lineDown: _i(j['ld']), lineUp: _i(j['lu']));
    return p.hasTunnel || p.hasLine ? p : null;
  }
}

const shaperPresetsKey = 'shaper_presets_v1';
const shaperCityLimitsKey = 'shaper_city_limits_v1';

List<ShaperPreset> decodePresets(String? s) {
  try {
    final j = jsonDecode(s ?? '[]');
    return j is List ? [for (final x in j) ?ShaperPreset.fromJson(x)] : const [];
  } on Object {
    return const [];
  }
}

String encodePresets(List<ShaperPreset> list) => jsonEncode([for (final p in list) p.toJson()]);

/// Replaces a preset of the same name (case-insensitive) or adds it.
List<ShaperPreset> upsertPreset(List<ShaperPreset> list, ShaperPreset p) => [
      for (final x in list)
        if (x.name.toLowerCase() != p.name.toLowerCase()) x,
      p,
    ];

String cityKey(String city) => city.trim().toLowerCase();

Map<String, ({int down, int up})> decodeCityLimits(String? s) {
  try {
    final j = jsonDecode(s ?? '{}');
    if (j is! Map) return const {};
    final out = <String, ({int down, int up})>{};
    for (final e in j.entries) {
      final v = e.value;
      if (v is! Map) continue;
      final d = ShaperPreset._i(v['d']), u = ShaperPreset._i(v['u']);
      if (d != null && u != null) out[cityKey('${e.key}')] = (down: d, up: u);
    }
    return out;
  } on Object {
    return const {};
  }
}

String encodeCityLimits(Map<String, ({int down, int up})> m) =>
    jsonEncode({for (final e in m.entries) e.key: {'d': e.value.down, 'u': e.value.up}});
