import 'package:flutter/material.dart';

import '../theme.dart';

/// The Cybervulcan "Vulcan V" mark: a V traced like a circuit. Two lava lines
/// run down from the vents at the top, the cyan tunnel drops through the
/// middle, and all three meet in one glowing exit node. Pure vector drawing.
///
/// [accent] replaces the lava gradient with one solid colour (used to show the
/// house status); null keeps the ember gradient.
class VulcanLogo extends StatelessWidget {
  const VulcanLogo({super.key, this.size = 48, this.accent});

  final double size;
  final Color? accent;

  @override
  Widget build(BuildContext context) => SizedBox.square(
        dimension: size,
        child: CustomPaint(painter: VulcanLogoPainter(accent: accent)),
      );
}

class VulcanLogoPainter extends CustomPainter {
  VulcanLogoPainter({this.accent});

  final Color? accent;

  /// The V in a 100 x 100 design box.
  static const _v = [
    Offset(18, 16),
    Offset(30, 16),
    Offset(30, 30),
    Offset(50, 74),
    Offset(70, 30),
    Offset(70, 16),
    Offset(82, 16),
  ];

  @override
  void paint(Canvas canvas, Size size) {
    final k = size.shortestSide / 100;
    canvas.save();
    canvas.translate((size.width - 100 * k) / 2, (size.height - 100 * k) / 2);
    canvas.scale(k);

    final path = Path()..moveTo(_v.first.dx, _v.first.dy);
    for (final p in _v.skip(1)) {
      path.lineTo(p.dx, p.dy);
    }
    final glowColor = accent ?? OpnColors.ember;

    // Soft glow under the V.
    canvas.drawPath(
      path,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 9
        ..strokeJoin = StrokeJoin.round
        ..strokeCap = StrokeCap.round
        ..color = glowColor.withValues(alpha: 0.45)
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 2.5),
    );

    // The V itself: ember gradient (or a solid status colour).
    final vPaint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 7
      ..strokeJoin = StrokeJoin.round
      ..strokeCap = StrokeCap.round;
    if (accent != null) {
      vPaint.color = accent!;
    } else {
      vPaint.shader = const LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [OpnColors.emberLight, OpnColors.ember, OpnColors.emberDeep],
      ).createShader(const Rect.fromLTWH(0, 16, 100, 60));
    }
    canvas.drawPath(path, vPaint);

    // Cyan tunnel line and its entry ring.
    final cyan = Paint()
      ..color = OpnColors.glassCyan
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round
      ..strokeWidth = 3;
    canvas.drawLine(const Offset(50, 16), const Offset(50, 62), cyan);
    canvas.drawCircle(const Offset(50, 16), 4, cyan..strokeWidth = 2);

    // Vent dots and the glowing exit node.
    final node = Paint()..color = accent ?? OpnColors.emberLight;
    canvas.drawCircle(const Offset(18, 16), 3, node);
    canvas.drawCircle(const Offset(82, 16), 3, node);
    canvas.drawCircle(
      const Offset(50, 84),
      9,
      Paint()
        ..color = glowColor.withValues(alpha: 0.4)
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 3),
    );
    canvas.drawCircle(const Offset(50, 84), 5, node);
    canvas.restore();
  }

  @override
  bool shouldRepaint(VulcanLogoPainter old) => old.accent != accent;
}
