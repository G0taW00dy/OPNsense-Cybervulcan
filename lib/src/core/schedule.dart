import 'config.dart';

/// Scheduled whole-house bypass (v2.0) and other time-based helpers. Pure
/// functions so they are unit-tested without clocks or a router.

const weekdayShort = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

/// Parses "HH:MM" (24 h) into minutes after midnight; null when invalid.
int? parseClock(String hhmm) {
  final m = RegExp(r'^(\d{1,2}):(\d{2})$').firstMatch(hhmm.trim());
  if (m == null) return null;
  final h = int.parse(m.group(1)!);
  final min = int.parse(m.group(2)!);
  if (h > 23 || min > 59) return null;
  return h * 60 + min;
}

String formatClockMinutes(int minutes) =>
    '${(minutes ~/ 60).toString().padLeft(2, '0')}:${(minutes % 60).toString().padLeft(2, '0')}';

/// Bit for [weekday] (DateTime.monday = 1 ... sunday = 7) in [AppConfig.schedDays].
int weekdayBit(int weekday) => 1 << (weekday - 1);

String dayKey(DateTime local) =>
    '${local.year}-${local.month.toString().padLeft(2, '0')}-${local.day.toString().padLeft(2, '0')}';

/// "Mon, Wed, Fri 19:00 for 3 h" style summary.
String describeSchedule(AppConfig cfg) {
  if (!cfg.schedBypassEnabled || cfg.schedDays == 0) return 'Off';
  final days = [
    for (var d = 1; d <= 7; d++)
      if (cfg.schedDays & weekdayBit(d) != 0) weekdayShort[d - 1],
  ];
  final daysText = days.length == 7
      ? 'Every day'
      : cfg.schedDays == 0x1f
          ? 'Weekdays'
          : cfg.schedDays == 0x60
              ? 'Weekends'
              : days.join(', ');
  final h = cfg.schedMinutes ~/ 60;
  final m = cfg.schedMinutes % 60;
  final len = h > 0 ? '$h h${m > 0 ? ' $m min' : ''}' : '$m min';
  return '$daysText ${cfg.schedStart} for $len';
}

/// When the scheduled bypass should start now, returns how long it should
/// still run (the rest of today's window); null when nothing is due.
/// [lastFiredDay] is the [dayKey] it last fired on, so it fires once a day
/// and a manual "turn off" inside the window is respected.
Duration? scheduledBypassDue(AppConfig cfg, DateTime nowLocal, String? lastFiredDay) {
  if (!cfg.schedBypassEnabled || cfg.schedDays == 0 || cfg.schedMinutes < 5) return null;
  final start = parseClock(cfg.schedStart);
  if (start == null) return null;
  if (cfg.schedDays & weekdayBit(nowLocal.weekday) == 0) return null;
  if (lastFiredDay == dayKey(nowLocal)) return null;
  final nowMin = nowLocal.hour * 60 + nowLocal.minute;
  final end = start + cfg.schedMinutes;
  if (nowMin < start || nowMin >= end) return null;
  return Duration(minutes: end - nowMin);
}

/// True when a router backup reminder is due (every [AppConfig.backupReminderDays]).
bool backupReminderDue(AppConfig cfg, DateTime now, DateTime? lastBackup, DateTime? lastReminded) {
  if (cfg.backupReminderDays <= 0 || lastBackup == null) return false;
  if (now.difference(lastBackup) < Duration(days: cfg.backupReminderDays)) return false;
  return lastReminded == null || now.difference(lastReminded) >= const Duration(hours: 24);
}

/// `yyyy-mm-dd` -> a local date (midnight), or null.
DateTime? parseIsoDate(String s) {
  final m = RegExp(r'^(\d{4})-(\d{2})-(\d{2})$').firstMatch(s.trim());
  if (m == null) return null;
  final y = int.parse(m.group(1)!), mo = int.parse(m.group(2)!), d = int.parse(m.group(3)!);
  final dt = DateTime(y, mo, d);
  return dt.year == y && dt.month == mo && dt.day == d ? dt : null; // rejects 2026-02-31
}

/// Warning stages for a provider key's expiry: 30, 7 and 1 day(s) before,
/// and 0 = expired. Returns the stage to warn about now, or null when there
/// is nothing new (each stage warns once; [lastWarnedStage] is the last one sent).
int? keyExpiryStage(DateTime expiry, DateTime nowLocal, int? lastWarnedStage) {
  final today = DateTime(nowLocal.year, nowLocal.month, nowLocal.day);
  final days = expiry.difference(today).inDays;
  final stage = days <= 0
      ? 0
      : days <= 1
          ? 1
          : days <= 7
              ? 7
              : days <= 30
                  ? 30
                  : null;
  if (stage == null) return null;
  if (lastWarnedStage != null && lastWarnedStage <= stage) return null;
  return stage;
}

/// Days until [expiry] (negative when past).
int daysUntil(DateTime expiry, DateTime nowLocal) =>
    expiry.difference(DateTime(nowLocal.year, nowLocal.month, nowLocal.day)).inDays;

/// Nightly "find best server" window: 03:00-05:00 local, at most every 20 h.
bool nightlyBestDue(AppConfig cfg, DateTime nowLocal, DateTime? lastRun) {
  if (!cfg.autoBestNightly || !cfg.serverSwitcherEnabled) return false;
  if (nowLocal.hour < 3 || nowLocal.hour >= 5) return false;
  return lastRun == null || nowLocal.difference(lastRun) >= const Duration(hours: 20);
}

/// MAC addresses not in [known] (case-insensitive). Empty [known] = first
/// run: nothing is "new" (the caller just seeds the list).
List<String> newMacs(Iterable<String> current, Set<String> known) {
  if (known.isEmpty) return const [];
  return [
    for (final m in current.map((m) => m.toLowerCase()).toSet())
      if (m.isNotEmpty && !known.contains(m)) m,
  ];
}
