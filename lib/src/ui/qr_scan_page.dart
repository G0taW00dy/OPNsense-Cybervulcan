import 'package:flutter/material.dart';
import 'package:flutter_zxing/flutter_zxing.dart';

import 'theme.dart';

/// Full-screen QR scanner (phone). Returns the decoded text, or null.
///
/// Decoding runs on the device with ZXing - nothing is sent anywhere. Used
/// for provider WireGuard configs (the servers page keeps only the [Peer]
/// part and drops the rest, private key included) and, v2.2.1, for this
/// device's own remote-access config from the router's Peer generator
/// (Remote access keeps its private key in secure storage).
class QrScanPage extends StatefulWidget {
  const QrScanPage({super.key, this.title = 'Scan QR code', this.hint});

  final String title;
  final String? hint;

  static Future<String?> scan(BuildContext context, {String title = 'Scan QR code', String? hint}) =>
      Navigator.of(context).push<String>(MaterialPageRoute(builder: (_) => QrScanPage(title: title, hint: hint)));

  @override
  State<QrScanPage> createState() => _QrScanPageState();
}

class _QrScanPageState extends State<QrScanPage> {
  bool _done = false;

  void _onScan(Code code) {
    final text = code.text;
    if (_done || !code.isValid || text == null || text.isEmpty) return;
    _done = true;
    Navigator.of(context).pop(text);
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: Text(widget.title)),
        body: Stack(children: [
          ReaderWidget(
            onScan: _onScan,
            codeFormat: Format.qrCode,
            showGallery: false,
            showToggleCamera: false,
            tryHarder: true,
          ),
          if (widget.hint != null)
            Positioned(
              left: 16,
              right: 16,
              bottom: 24,
              child: Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(color: OpnColors.ink.withValues(alpha: 0.85), borderRadius: BorderRadius.circular(12)),
                child: Text(widget.hint!, style: const TextStyle(color: OpnColors.textSoft)),
              ),
            ),
        ]),
      );
}
