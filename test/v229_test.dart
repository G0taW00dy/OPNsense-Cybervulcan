import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

Set<String> _names(String path) =>
    RegExp(r'<color name="([a-z_]+)"').allMatches(File(path).readAsStringSync()).map((m) => m[1]!).toSet();

void main() {
  group('Widget follows the phone theme (v2.2.9)', () {
    const light = 'android/app/src/main/res/values/widget_colors.xml';
    const dark = 'android/app/src/main/res/values-night/widget_colors.xml';

    test('light and dark define the same colours', () {
      expect(_names(light), isNotEmpty);
      expect(_names(light), _names(dark));
    });

    test('the widget files use those colours, not fixed ones', () {
      for (final f in [
        'android/app/src/main/res/layout/exit_widget.xml',
        'android/app/src/main/res/drawable/widget_background.xml',
        'android/app/src/main/res/drawable/widget_button.xml',
        'android/app/src/main/res/drawable/ic_widget_refresh.xml',
      ]) {
        final s = File(f).readAsStringSync();
        expect(RegExp(r'(textColor|startColor|endColor|android:color|fillColor)="#').hasMatch(s), isFalse, reason: f);
        for (final m in RegExp(r'@color/([a-z_]+)').allMatches(s)) {
          expect(_names(light), contains(m[1]), reason: '$f uses ${m[1]}');
        }
      }
    });

    test('status colours come from the colour files', () {
      final k = File('android/app/src/main/kotlin/au/cybervulcan/opnsense/ExitWidgetProvider.kt').readAsStringSync();
      expect(k, contains('R.color.widget_ok'));
      expect(k, isNot(contains('Color.parseColor')));
    });
  });
}
