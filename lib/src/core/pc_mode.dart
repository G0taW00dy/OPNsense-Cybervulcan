import 'dart:io';

import '../api/opnsense_client.dart';
import 'config.dart';
import 'network_map.dart';
import 'states.dart';

/// Picks the PC's own LAN IPv4 from its interfaces: prefer the VPN network,
/// then CLEAR, then any configured house network. Returns null if none.
String? choosePcIp(List<String> candidates, AppConfig cfg) {
  int rank(String ip) {
    final net = networkNameFor(ip, cfg.networks);
    if (net == null) return 99;
    if (Ipv4Subnet.tryParse(cfg.bypassNetwork)?.contains(ip) ?? false) return 0;
    if (net == 'CLEAR') return 1;
    return 2;
  }

  final usable = candidates.where((ip) => rank(ip) < 99).toList()
    ..sort((a, b) => rank(a).compareTo(rank(b)));
  return usable.isEmpty ? null : usable.first;
}

Future<String?> detectPcIp(AppConfig cfg) async {
  final override = cfg.pcIpOverride;
  if (override != null && ipv4ToInt(override) != null) return override;
  try {
    final ifaces = await NetworkInterface.list(type: InternetAddressType.IPv4);
    final ips = [
      for (final i in ifaces)
        for (final a in i.addresses)
          if (!a.isLoopback && !a.isLinkLocal) a.address,
    ];
    return choosePcIp(ips, cfg);
  } on Exception {
    return null;
  }
}

bool isPcInClearAlias(List<String> entries, String pcIp) =>
    entries.any((e) => tableEntryMatches(e, pcIp));

/// Switches the PC between VPN (not in alias) and CLEAR (in alias), confirms
/// with the router, then drops the PC's existing pf states so open
/// connections move to the new path. Returns the confirmed CLEAR state and
/// the state-kill outcome.
Future<(bool, StateKillResult)> setPcMode({
  required OpnsenseClient client,
  required AppConfig cfg,
  required String pcIp,
  required bool clear,
}) async {
  if (clear) {
    await client.aliasAdd(cfg.pcModeAlias, pcIp);
  } else {
    await client.aliasDelete(cfg.pcModeAlias, pcIp);
  }
  final confirmed = isPcInClearAlias(await client.aliasList(cfg.pcModeAlias), pcIp);
  if (confirmed != clear) {
    throw OpnsenseException(ApiErrorKind.server,
        'Router did not confirm the switch (${cfg.pcModeAlias} ${confirmed ? 'still contains' : 'does not contain'} $pcIp)');
  }
  return (confirmed, await killStatesFor(client, pcIp));
}
