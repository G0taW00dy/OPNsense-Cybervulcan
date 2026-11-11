import 'dart:io';

import 'package:crypto/crypto.dart';

/// Formats a SHA-256 digest as `AB:CD:...` (the same style OPNsense and
/// browsers show for certificate fingerprints).
String formatFingerprint(List<int> digestBytes) => digestBytes
    .map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase())
    .join(':');

/// SHA-256 fingerprint of a DER-encoded certificate.
String certificateFingerprint(X509Certificate cert) =>
    formatFingerprint(sha256.convert(cert.der).bytes);

/// Normalises user/stored fingerprints for comparison (case, separators).
String normaliseFingerprint(String fp) =>
    fp.replaceAll(RegExp(r'[^0-9a-fA-F]'), '').toUpperCase();

bool fingerprintsMatch(String a, String b) =>
    normaliseFingerprint(a).isNotEmpty &&
    normaliseFingerprint(a) == normaliseFingerprint(b);

/// Details of a certificate presented by the router, shown to the user for
/// trust-on-first-use confirmation.
class PresentedCertificate {
  const PresentedCertificate({
    required this.fingerprint,
    required this.subject,
    required this.issuer,
    required this.validFrom,
    required this.validTo,
  });

  final String fingerprint;
  final String subject;
  final String issuer;
  final DateTime validFrom;
  final DateTime validTo;
}

/// Connects to [host]:[port], accepting any certificate *only to read it*,
/// then closes the socket without sending anything (no credentials leave the
/// device). Returns null when the server is not reachable over TLS.
Future<PresentedCertificate?> probeCertificate(
  String host,
  int port, {
  Duration timeout = const Duration(seconds: 6),
}) async {
  X509Certificate? seen;
  try {
    final socket = await SecureSocket.connect(
      host,
      port,
      timeout: timeout,
      onBadCertificate: (cert) {
        seen = cert;
        return true;
      },
    );
    seen ??= socket.peerCertificate;
    await socket.close();
  } on Exception {
    // fall through - seen may still be set if the handshake got that far
  }
  final cert = seen;
  if (cert == null) return null;
  return PresentedCertificate(
    fingerprint: certificateFingerprint(cert),
    subject: cert.subject,
    issuer: cert.issuer,
    validFrom: cert.startValidity,
    validTo: cert.endValidity,
  );
}

/// Builds a [HttpClient] that trusts normal CA-validated certificates and,
/// additionally, exactly one self-signed certificate identified by
/// [pinnedSha256] (when given). Any other invalid certificate is rejected.
HttpClient buildPinnedHttpClient({
  String? pinnedSha256,
  Duration connectionTimeout = const Duration(seconds: 8),
}) {
  final client = HttpClient()
    ..connectionTimeout = connectionTimeout
    ..idleTimeout = const Duration(seconds: 15)
    ..userAgent = 'OPNsense-Cybervulcan';
  client.badCertificateCallback = (cert, host, port) {
    if (pinnedSha256 == null || pinnedSha256.isEmpty) return false;
    return fingerprintsMatch(certificateFingerprint(cert), pinnedSha256);
  };
  return client;
}
