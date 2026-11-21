import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

/// WireGuard key helpers: X25519 (RFC 7748) in pure Dart, so the app can
/// make its own keypair without a native library or a crypto dependency.
///
/// The ladder below uses BigInt and is not constant-time. It only ever runs
/// on this device, once, to derive this app's own public key, so there is no
/// remote timing oracle to worry about.

final _p = (BigInt.one << 255) - BigInt.from(19);
final _a24 = BigInt.from(121665);
final _mask255 = (BigInt.one << 255) - BigInt.one;

BigInt _decodeLe(List<int> b) {
  var r = BigInt.zero;
  for (var i = b.length - 1; i >= 0; i--) {
    r = (r << 8) | BigInt.from(b[i]);
  }
  return r;
}

Uint8List _encodeLe(BigInt v) {
  final out = Uint8List(32);
  var x = v;
  final ff = BigInt.from(0xff);
  for (var i = 0; i < 32; i++) {
    out[i] = (x & ff).toInt();
    x = x >> 8;
  }
  return out;
}

/// X25519(scalar, u) per RFC 7748 section 5.
Uint8List x25519(List<int> scalar, List<int> u) {
  if (scalar.length != 32 || u.length != 32) {
    throw ArgumentError('X25519 needs 32-byte inputs');
  }
  final k = Uint8List.fromList(scalar);
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
  final kn = _decodeLe(k);
  final x1 = _decodeLe(u) & _mask255;
  var x2 = BigInt.one, z2 = BigInt.zero, x3 = x1, z3 = BigInt.one;
  var swap = 0;
  for (var t = 254; t >= 0; t--) {
    final kt = ((kn >> t) & BigInt.one).toInt();
    swap ^= kt;
    if (swap == 1) {
      final tx = x2;
      x2 = x3;
      x3 = tx;
      final tz = z2;
      z2 = z3;
      z3 = tz;
    }
    swap = kt;
    final a = (x2 + z2) % _p;
    final aa = (a * a) % _p;
    final b = (x2 - z2) % _p;
    final bb = (b * b) % _p;
    final e = (aa - bb) % _p;
    final c = (x3 + z3) % _p;
    final d = (x3 - z3) % _p;
    final da = (d * a) % _p;
    final cb = (c * b) % _p;
    final s1 = (da + cb) % _p;
    x3 = (s1 * s1) % _p;
    final s2 = (da - cb) % _p;
    z3 = (x1 * ((s2 * s2) % _p)) % _p;
    x2 = (aa * bb) % _p;
    z2 = (e * ((aa + (_a24 * e) % _p) % _p)) % _p;
  }
  if (swap == 1) {
    final tx = x2;
    x2 = x3;
    x3 = tx;
    final tz = z2;
    z2 = z3;
    z3 = tz;
  }
  final r = (x2 * z2.modPow(_p - BigInt.two, _p)) % _p;
  return _encodeLe(r);
}

final _basePoint = Uint8List(32)..[0] = 9;

/// True for a base64 string that decodes to exactly 32 bytes.
bool isWireGuardKey(String? s) {
  if (s == null) return false;
  try {
    return base64.decode(s.trim()).length == 32;
  } on FormatException {
    return false;
  }
}

/// Public key (base64) for a base64 private key. Throws [FormatException]
/// on a malformed key.
String wireGuardPublicKey(String privateKeyB64) {
  final priv = base64.decode(privateKeyB64.trim());
  if (priv.length != 32) throw const FormatException('Not a WireGuard key');
  return base64.encode(x25519(priv, _basePoint));
}

/// New random private key (base64, clamped like `wg genkey`).
String generateWireGuardPrivateKey([Random? random]) {
  final r = random ?? Random.secure();
  final k = Uint8List(32);
  for (var i = 0; i < 32; i++) {
    k[i] = r.nextInt(256);
  }
  k[0] &= 248;
  k[31] = (k[31] & 127) | 64;
  return base64.encode(k);
}
