import 'package:flutter/material.dart';

import '../theme.dart';

/// Decorative night scene for the status header: a volcano whose lava runs
/// down as circuit traces. The middle "tunnel" trace is drawn in [accent]
/// (the house status colour). Fills its box like CSS `slice`, anchored to the
/// bottom centre, so it can be any width.
class VolcanoArt extends StatelessWidget {
  const VolcanoArt({super.key, this.accent = OpnColors.glassCyan});

  final Color accent;

  @override
  Widget build(BuildContext context) => ExcludeSemantics(
        child: CustomPaint(painter: _VolcanoPainter(accent), size: Size.infinite),
      );
}

class _VolcanoPainter extends CustomPainter {
  _VolcanoPainter(this.accent);

  final Color accent;

  static const _w = 520.0;
  static const _h = 300.0;

  static const _leftFlow = [
    Offset(300, 116), Offset(300, 150), Offset(284, 150), Offset(284, 196),
    Offset(262, 196), Offset(262, 244), //
  ];
  static const _rightFlow = [
    Offset(314, 116), Offset(314, 140), Offset(330, 140), Offset(330, 182),
    Offset(352, 182), Offset(352, 230), Offset(372, 230), Offset(372, 270), //
  ];
  static const _nodes = [
    Offset(284, 150), Offset(262, 196), Offset(262, 244), Offset(330, 140),
    Offset(352, 182), Offset(372, 230), Offset(372, 270), //
  ];
  static const _tunnel = [Offset(307, 118), Offset(307, 170), Offset(316, 170), Offset(316, 214)];

  Path _poly(List<Offset> pts) {
    final p = Path()..moveTo(pts.first.dx, pts.first.dy);
    for (final o in pts.skip(1)) {
      p.lineTo(o.dx, o.dy);
    }
    return p;
  }

  @override
  void paint(Canvas canvas, Size size) {
    if (size.isEmpty) return;
    final k = size.width / _w > size.height / _h ? size.width / _w : size.height / _h;
    canvas.save();
    canvas.clipRect(Offset.zero & size);
    canvas.translate((size.width - _w * k) / 2, size.height - _h * k);
    canvas.scale(k);

    const full = Rect.fromLTWH(0, 0, _w, _h);

    // Warm sky glow behind the crater.
    canvas.drawRect(
      full,
      Paint()
        ..shader = RadialGradient(
          center: const Alignment(0.24, -0.3),
          radius: 0.6,
          colors: [OpnColors.ember.withValues(alpha: 0.18), OpnColors.ember.withValues(alpha: 0)],
        ).createShader(full),
    );

    // Stars.
    final star = Paint()..color = OpnColors.text;
    for (final (o, r, a) in const [
      (Offset(40, 30), 1.2, 0.7), (Offset(120, 60), 0.9, 0.5), (Offset(210, 22), 1.1, 0.6),
      (Offset(470, 40), 1.3, 0.7), (Offset(400, 18), 0.8, 0.5), (Offset(500, 95), 0.9, 0.4),
      (Offset(80, 110), 0.8, 0.4), //
    ]) {
      canvas.drawCircle(o, r, star..color = OpnColors.text.withValues(alpha: a));
    }

    // Faint perspective grid on the ground.
    final grid = Paint()
      ..color = OpnColors.glassCyan.withValues(alpha: 0.12)
      ..strokeWidth = 1;
    for (final y in const [262.0, 278.0, 292.0]) {
      canvas.drawLine(Offset(0, y), Offset(_w, y), grid);
    }
    for (final x in const [40.0, 120.0, 200.0, 320.0, 400.0, 480.0]) {
      canvas.drawLine(const Offset(260, 250), Offset(x, _h), grid);
    }

    // Back hill and the volcano.
    canvas.drawPath(
      Path()
        ..moveTo(0, 300)
        ..lineTo(70, 210)
        ..lineTo(120, 240)
        ..lineTo(170, 190)
        ..lineTo(230, 255)
        ..lineTo(230, 300)
        ..close(),
      Paint()
        ..shader = const LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [Color(0xFF1A1F36), Color(0xFF0D1222)],
        ).createShader(const Rect.fromLTWH(0, 190, 230, 110)),
    );
    canvas.drawPath(
      Path()
        ..moveTo(150, 300)
        ..lineTo(285, 112)
        ..lineTo(300, 104)
        ..lineTo(318, 106)
        ..lineTo(332, 114)
        ..lineTo(470, 300)
        ..close(),
      Paint()
        ..shader = const LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [Color(0xFF2A2440), Color(0xFF0D1222)],
        ).createShader(const Rect.fromLTWH(150, 104, 320, 196)),
    );

    // Crater glow.
    canvas.drawOval(
      Rect.fromCenter(center: const Offset(308, 108), width: 68, height: 44),
      Paint()
        ..shader = const RadialGradient(colors: [
          OpnColors.emberLight,
          OpnColors.ember,
          Color(0x00FF7A3D),
        ], stops: [0, 0.35, 1])
            .createShader(Rect.fromCenter(center: const Offset(308, 108), width: 68, height: 44))
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 3),
    );

    // Lava traces: glow, then a bright core.
    final glow = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 3
      ..strokeJoin = StrokeJoin.round
      ..strokeCap = StrokeCap.round
      ..color = OpnColors.ember.withValues(alpha: 0.9)
      ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 3);
    final core = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1.4
      ..strokeJoin = StrokeJoin.round
      ..strokeCap = StrokeCap.round
      ..color = const Color(0xFFFFB07A);
    for (final f in [_leftFlow, _rightFlow]) {
      canvas.drawPath(_poly(f), glow);
      canvas.drawPath(_poly(f), core);
    }
    canvas.drawPath(_poly(_tunnel), glow..color = accent.withValues(alpha: 0.7));
    canvas.drawPath(_poly(_tunnel), core..color = accent);

    // Nodes.
    final ember = Paint()..color = OpnColors.emberLight;
    for (final o in _nodes) {
      canvas.drawCircle(o, 3, ember);
    }
    canvas.drawCircle(_tunnel.last, 3.5, Paint()..color = accent);
    canvas.restore();
  }

  @override
  bool shouldRepaint(_VolcanoPainter old) => old.accent != accent;
}
