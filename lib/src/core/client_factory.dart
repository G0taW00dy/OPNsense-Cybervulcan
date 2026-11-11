import 'package:http/io_client.dart';

import '../api/opnsense_client.dart';
import '../api/tls.dart';
import 'config.dart';
import 'storage.dart';

/// Builds a router client honouring the pinned self-signed certificate.
/// Returns null when the configuration or credentials are incomplete.
OpnsenseClient? buildRouterClient(AppConfig cfg, ApiCredentials? creds) {
  final base = cfg.baseUri;
  if (base == null || creds == null || !creds.isComplete) return null;
  return OpnsenseClient(
    baseUrl: base,
    apiKey: creds.key,
    apiSecret: creds.secret,
    httpClient: IOClient(buildPinnedHttpClient(pinnedSha256: cfg.pinnedCertSha256)),
  );
}
