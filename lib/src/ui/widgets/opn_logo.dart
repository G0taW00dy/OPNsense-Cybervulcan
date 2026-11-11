import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../theme.dart';

/// The "OPn" mark: a liquid-glass "O" ring with a "P" whose stem passes
/// through the ring, followed by a lower-case "n". Pure vector drawing.
/// [accent] tints the ring (used to reflect the house status).
class OpnLogo extends StatelessWidget {
  const OpnLogo({super.key, this.size = 48, this.accent, this.showN = true});

  final double size;
  final Color? accent;
  final bool showN;

  @override
  Widget build(BuildContext context) {
    final dark = Theme.of(context).brightness == Brightness.dark;
    return SizedBox(
      width: showN ? size * 1.55 : size,
      height: size,
      child: CustomPaint(
        painter: _OpnPainter(
          accent: accent ?? OpnColors.glassCyan,
          ink: dark ? Colors.white : OpnColors.ink,
          showN: showN,
        ),
      ),
    );
  }
}

class _OpnPainter extends CustomPainter {
  _OpnPainter({required this.accent, required this.ink, required this.showN});

  final Color accent;
  final Color ink;
  final bool showN;

  @override
  void paint(Canvas canvas, Size size) {
    final s = size.height;
    final c = Offset(s / 2, s / 2);
    final r = s * 0.36;
    final ringW = s * 0.15;

    // Soft glow behind the ring.
    canvas.drawCircle(
      c,
      r,
      Paint()
        ..color = accent.withValues(alpha: 0.35)
        ..maskFilter = MaskFilter.blur(BlurStyle.normal, s * 0.08)
        ..style = PaintingStyle.stroke
        ..strokeWidth = ringW,
    );

    // Glass ring: sweep gradient body.
    final ringRect = Rect.fromCircle(center: c, radius: r);
    canvas.drawCircle(
      c,
      r,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = ringW
        ..shader = SweepGradient(
          colors: [
            accent,
            OpnColors.glassBlue,
            accent.withValues(alpha: 0.7),
            Colors.white.withValues(alpha: 0.9),
            accent,
          ],
          stops: const [0, 0.35, 0.6, 0.8, 1],
          transform: const GradientRotation(-math.pi / 2),
        ).createShader(ringRect),
    );

    // Specular highlight (the "liquid" sheen), upper-left arc.
    canvas.drawArc(
      Rect.fromCircle(center: c, radius: r + ringW * 0.18),
      math.pi * 1.05,
      math.pi * 0.45,
      false,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeCap = StrokeCap.round
        ..strokeWidth = ringW * 0.28
        ..color = Colors.white.withValues(alpha: 0.85),
    );

    // The "P": stem passes down through the ring, bowl inside the ring.
    final p = Paint()
      ..color = ink
      ..style = PaintingStyle.stroke
      ..strokeWidth = s * 0.1
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round;
    final stemX = c.dx - r * 0.28;
    final top = c.dy - r * 0.62;
    final bowlBottom = c.dy + r * 0.12;
    final path = Path()
      ..moveTo(stemX, s * 0.97)
      ..lineTo(stemX, top)
      ..lineTo(c.dx + r * 0.05, top)
      ..arcToPoint(Offset(c.dx + r * 0.05, bowlBottom),
          radius: Radius.circular((bowlBottom - top) / 2))
      ..lineTo(stemX, bowlBottom);
    canvas.drawPath(path, p);

    if (showN) {
      // Lower-case "n" to the right of the ring.
      final nLeft = s * 1.02;
      final nRight = s * 1.45;
      final nTop = s * 0.5;
      final nBase = s * 0.86;
      final nPath = Path()
        ..moveTo(nLeft, nBase)
        ..lineTo(nLeft, nTop)
        ..moveTo(nLeft, nTop + (nRight - nLeft) * 0.45)
        ..arcToPoint(Offset(nRight, nTop + (nRight - nLeft) * 0.45),
            radius: Radius.circular((nRight - nLeft) / 2))
        ..lineTo(nRight, nBase);
      canvas.drawPath(nPath, p..strokeWidth = s * 0.09);
    }
  }

  @override
  bool shouldRepaint(_OpnPainter old) =>
      old.accent != accent || old.ink != ink || old.showN != showN;
}
