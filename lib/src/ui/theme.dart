import 'package:flutter/material.dart';

import '../core/house_state.dart';

class OpnColors {
  static const green = Color(0xFF2ECC71);
  static const amber = Color(0xFFF5A623);
  static const red = Color(0xFFE5484D);
  static const purple = Color(0xFF9B5DE5);
  static const grey = Color(0xFF8A8F98);
  static const glassCyan = Color(0xFF5CE1E6);
  static const glassBlue = Color(0xFF3A7BD5);
  static const ink = Color(0xFF0E1320);

  static Color forHealth(Health h) => switch (h) {
        Health.ok => green,
        Health.warning => amber,
        Health.problem => red,
        Health.bypass => purple,
        Health.notConfigured => grey,
      };
}

ThemeData buildTheme(Brightness brightness) {
  final scheme = ColorScheme.fromSeed(
    seedColor: OpnColors.glassBlue,
    brightness: brightness,
  );
  final dark = brightness == Brightness.dark;
  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    scaffoldBackgroundColor: dark ? OpnColors.ink : const Color(0xFFF4F7FB),
    cardTheme: CardThemeData(
      elevation: 0,
      color: dark ? const Color(0xFF161D2E) : Colors.white,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(18),
        side: BorderSide(color: scheme.outlineVariant.withValues(alpha: 0.5)),
      ),
      margin: EdgeInsets.zero,
    ),
    inputDecorationTheme: const InputDecorationTheme(border: OutlineInputBorder()),
    visualDensity: VisualDensity.standard,
  );
}
