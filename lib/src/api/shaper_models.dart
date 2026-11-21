/// Traffic shaper models (v2.1 shaper card and auto-tune).
///
/// Shapes verified against OPNsense 26.7 on the house router:
/// * `POST /api/trafficshaper/settings/search_pipes` -> `{rows: [{uuid,
///   enabled, number, bandwidth, bandwidthMetric, description, ...}]}`.
/// * `GET /api/trafficshaper/service/statistics` -> `{status: ok, items: [
///   {type: pipe, pipe: "10002", rules: [...]}, {type: queue, sched_nr:
///   "10002", rules: [{bytes, pkts}]}, ...]}` - queues hang under the pipe
///   whose number equals their `sched_nr`.
library;

int? _int(Object? v) => v is num ? v.toInt() : int.tryParse('${v ?? ''}'.trim());

class ShaperPipe {
  const ShaperPipe({
    required this.uuid,
    required this.number,
    required this.description,
    required this.mbit,
    required this.enabled,
  });

  final String uuid;
  final int? number;
  final String description;

  /// Bandwidth in Mbit/s (converted from the pipe's metric).
  final double mbit;
  final bool enabled;

  factory ShaperPipe.fromJson(Map<String, dynamic> j) {
    final bw = double.tryParse('${j['bandwidth'] ?? ''}'.trim()) ?? 0;
    final metric = '${j['bandwidthMetric'] ?? 'Mbit'}'.toLowerCase();
    final mbit = switch (metric) {
      'bit' => bw / 1e6,
      'kbit' => bw / 1e3,
      'gbit' => bw * 1e3,
      _ => bw,
    };
    return ShaperPipe(
      uuid: '${j['uuid'] ?? ''}',
      number: _int(j['number']),
      description: '${j['description'] ?? ''}',
      mbit: mbit,
      enabled: j['enabled'] == '1' || j['enabled'] == 1 || j['enabled'] == true,
    );
  }

  bool get _vpn => description.toLowerCase().contains('vpn');
  bool get looksVpnDownload => _vpn && description.toLowerCase().contains('down');
  bool get looksVpnUpload => _vpn && description.toLowerCase().contains('up');

  bool get _clear => !_vpn && description.toLowerCase().contains('clear');
  bool get looksClearDownload => _clear && description.toLowerCase().contains('down');
  bool get looksClearUpload => _clear && description.toLowerCase().contains('up') && !description.toLowerCase().contains('down');
}

/// The CLEAR (direct internet) download / upload pipes, by description.
({ShaperPipe down, ShaperPipe up})? findClearPipes(List<ShaperPipe> pipes) {
  final d = pipes.where((p) => p.enabled && p.looksClearDownload).firstOrNull;
  final u = pipes.where((p) => p.enabled && p.looksClearUpload).firstOrNull;
  return d == null || u == null ? null : (down: d, up: u);
}

/// The VPN download / upload pipes, found by description ("VPN download",
/// "VPN upload"), or null when the router has no such pipes.
({ShaperPipe down, ShaperPipe up})? findVpnPipes(List<ShaperPipe> pipes) {
  final d = pipes.where((p) => p.enabled && p.looksVpnDownload).firstOrNull;
  final u = pipes.where((p) => p.enabled && p.looksVpnUpload).firstOrNull;
  return d == null || u == null ? null : (down: d, up: u);
}

Map<int, int> shaperBytesFromStatistics(Map<String, dynamic> json) {
  final out = <int, int>{};
  final items = json['items'];
  if (items is! List) return out;
  int sumRules(Object? rules) {
    var s = 0;
    if (rules is List) {
      for (final r in rules) {
        if (r is Map) s += _int(r['bytes']) ?? 0;
      }
    }
    return s;
  }

  for (final i in items) {
    if (i is! Map) continue;
    final n = i['type'] == 'pipe' ? _int(i['pipe']) : (i['type'] == 'queue' ? _int(i['sched_nr']) : null);
    if (n == null) continue;
    out[n] = (out[n] ?? 0) + sumRules(i['rules']);
  }
  return out;
}

/// Enabled pipes for display: VPN first, then the rest; download before upload.
List<ShaperPipe> shaperDisplayOrder(List<ShaperPipe> pipes) {
  int rank(ShaperPipe p) {
    final d = p.description.toLowerCase();
    return (d.contains('vpn') ? 0 : 2) + (d.contains('up') && !d.contains('down') ? 1 : 0);
  }

  final list = pipes.where((p) => p.enabled).toList();
  list.sort((a, b) {
    final r = rank(a).compareTo(rank(b));
    return r != 0 ? r : a.description.compareTo(b.description);
  });
  return list;
}
