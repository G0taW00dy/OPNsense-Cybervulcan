import 'package:http/io_client.dart';

import '../api/opnsense_client.dart';
import '../net/router_link.dart';
import 'config.dart';
import 'storage.dart';

/// Builds a router client. Sockets go to the router address (or, when
/// [route] says so, to the in-app WireGuard tunnel) and the certificate is
/// checked against the configured certificate name or pin before any
/// request - and so the API key - is sent.
///
/// Returns null when the configuration or credentials are incomplete.
OpnsenseClient? buildRouterClient(AppConfig cfg, ApiCredentials? creds,
    {RouterRoute Function(RouterTarget target)? route}) {
  final target = RouterTarget.fromConfig(cfg);
  if (target == null || creds == null || !creds.isComplete) return null;
  final pick = route ?? (RouterTarget t) => RouterRoute.direct(t.host, t.port);
  return OpnsenseClient(
    baseUrl: target.requestBase,
    apiKey: creds.key,
    apiSecret: creds.secret,
    httpClient: IOClient(buildRouterHttpClient(target, () => pick(target))),
  );
}
