import 'package:flutter/material.dart';

import '../core/house_state.dart';

/// Night palette. The app is always dark.
class OpnColors {
  // Status colours (also used by the tray icons).
  static const green = Color(0xFF2ECC71);
  static const amber = Color(0xFFF5A623);
  static const red = Color(0xFFFF6B6F);
  static const purple = Color(0xFFB794F4);
  static const grey = Color(0xFF8A8F98);

  // Brand.
  static const glassCyan = Color(0xFF5CE1E6);
  static const glassBlue = Color(0xFF3A7BD5);
  static const ember = Color(0xFFFF7A3D);
  static const emberLight = Color(0xFFFFD08A);
  static const emberDeep = Color(0xFFC2410C);

  // Surfaces and text.
  static const ink = Color(0xFF0B0E17);
  static const rail = Color(0xFF0F1320);
  static const surface = Color(0xFF121726);
  static const surfaceHigh = Color(0xFF182035);
  static const border = Color(0xFF232C44);
  static const text = Color(0xFFE8ECF5);
  static const textSoft = Color(0xFFB3BBCD);
  static const muted = Color(0xFF9AA3B8);

  static Color forHealth(Health h) => switch (h) {
        Health.ok => green,
        Health.warning => amber,
        Health.problem => red,
        Health.bypass => purple,
        Health.notConfigured => grey,
      };
}

ThemeData buildTheme() {
  final scheme = ColorScheme.fromSeed(
    seedColor: OpnColors.glassCyan,
    brightness: Brightness.dark,
  ).copyWith(
    primary: OpnColors.glassCyan,
    onPrimary: OpnColors.ink,
    secondary: OpnColors.ember,
    onSecondary: OpnColors.ink,
    error: OpnColors.red,
    surface: OpnColors.ink,
    onSurface: OpnColors.text,
    onSurfaceVariant: OpnColors.textSoft,
    surfaceContainerLowest: OpnColors.ink,
    surfaceContainerLow: OpnColors.rail,
    surfaceContainer: OpnColors.surface,
    surfaceContainerHigh: OpnColors.surfaceHigh,
    surfaceContainerHighest: OpnColors.surfaceHigh,
    outline: const Color(0xFF3A4566),
    outlineVariant: OpnColors.border,
  );
  final selected = WidgetStateProperty.resolveWith<Color>(
      (s) => s.contains(WidgetState.selected) ? OpnColors.glassCyan : OpnColors.muted);
  return ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    colorScheme: scheme,
    scaffoldBackgroundColor: OpnColors.ink,
    canvasColor: OpnColors.ink,
    dividerColor: OpnColors.border,
    appBarTheme: const AppBarTheme(
      backgroundColor: OpnColors.ink,
      surfaceTintColor: Colors.transparent,
      foregroundColor: OpnColors.text,
    ),
    cardTheme: CardThemeData(
      elevation: 0,
      color: OpnColors.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
        side: const BorderSide(color: OpnColors.border),
      ),
      margin: EdgeInsets.zero,
    ),
    navigationRailTheme: const NavigationRailThemeData(
      backgroundColor: OpnColors.rail,
      indicatorColor: Color(0xFF1A2238),
      selectedIconTheme: IconThemeData(color: OpnColors.glassCyan),
      unselectedIconTheme: IconThemeData(color: OpnColors.muted),
      selectedLabelTextStyle: TextStyle(color: OpnColors.glassCyan, fontWeight: FontWeight.w600),
      unselectedLabelTextStyle: TextStyle(color: OpnColors.muted),
    ),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: OpnColors.rail,
      indicatorColor: const Color(0xFF1A2238),
      iconTheme: WidgetStateProperty.resolveWith(
          (s) => IconThemeData(color: selected.resolve(s))),
      labelTextStyle: WidgetStateProperty.resolveWith((s) => TextStyle(
            color: selected.resolve(s),
            fontSize: 12,
            fontWeight: s.contains(WidgetState.selected) ? FontWeight.w600 : FontWeight.w400,
          )),
    ),
    chipTheme: const ChipThemeData(
      backgroundColor: Color(0xFF1A2238),
      side: BorderSide(color: Color(0xFF2A3452)),
      labelStyle: TextStyle(color: Color(0xFFD5DBE8)),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
        minimumSize: const Size(0, 48),
      ),
    ),
    switchTheme: SwitchThemeData(
      trackOutlineColor: WidgetStateProperty.all(OpnColors.border),
    ),
    inputDecorationTheme: const InputDecorationTheme(
      border: OutlineInputBorder(),
      enabledBorder: OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF3A4566))),
    ),
    visualDensity: VisualDensity.standard,
  );
}
