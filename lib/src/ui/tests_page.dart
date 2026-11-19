import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

import '../core/controller.dart';
import '../core/network_map.dart';
import '../core/pc_mode.dart';
import '../core/quick_tests.dart';
import '../core/security_tests.dart';
import 'theme.dart';

/// v2.0 security Tests page: score, grouped checks (router side + outside),
/// run one or all, history and a copyable report.
class TestsPage extends StatefulWidget {
  const TestsPage({super.key, required this.controller});
  final CybervulcanController controller;

  @override
  State<TestsPage> createState() => _TestsPageState();
}

class _TestsPageState extends State<TestsPage> {
  final _http = http.Client();
  final Map<String, SecurityTestResult> _results = {};
  final Set<String> _running = {};
  List<TestRun> _history = [];
  DateTime? _lastRun;
  String? _deviceIp;
  ExpectedPath _expected = ExpectedPath.unknown;

  CybervulcanController get c => widget.controller;

  @override
  void initState() {
    super.initState();
    _history = decodeHistory(c.prefs.getString(testHistoryKey));
    if (_history.isNotEmpty) {
      final last = _history.first;
      _lastRun = last.at;
      for (final r in last.results) {
        _results[r.id] = r;
      }
    }
  }

  @override
  void dispose() {
    _http.close();
    super.dispose();
  }

  Future<TestEnv> _env() async {
    _deviceIp = c.snapshot.pcIp ?? await detectPcIp(c.config);
    _expected = expectedPathFor(
      deviceIp: _deviceIp,
      cfg: c.config,
      bypassActive: c.snapshot.bypassActive,
      pcClear: c.supportsPcMode ? c.snapshot.pcClear : null,
    );
    return TestEnv(
      config: c.config,
      web: _http,
      client: c.routerClient,
      snapshot: c.snapshot,
      deviceIp: _deviceIp,
      expected: _expected,
      target: c.routerTarget,
      route: c.routerRoute,
      atHome: c.atHome,
    );
  }

  Future<void> _runAll() async {
    if (_running.isNotEmpty) return;
    await c.refresh();
    final env = await _env();
    setState(() {
      _running.addAll(allSecurityTests.map((t) => t.id));
      _results.clear();
    });
    // Router-side checks in parallel; outside checks one after another so
    // they don't skew each other (bufferbloat last: it loads the line).
    final router = allSecurityTests.where((t) => !t.external);
    final outside = allSecurityTests.where((t) => t.external && t.id != 'bufferbloat');
    await Future.wait([
      for (final t in router) _runOne(t, env),
      () async {
        for (final t in outside) {
          await _runOne(t, env);
        }
      }(),
    ]);
    await _runOne(allSecurityTests.firstWhere((t) => t.id == 'bufferbloat'), env);
    final run = TestRun(DateTime.now(), securityScore(_results.values.toList(), securityTestWeights),
        [for (final t in allSecurityTests) ?_results[t.id]]);
    _history = [run, ..._history].take(testHistoryMax).toList();
    await c.prefs.setString(testHistoryKey, encodeHistory(_history));
    if (mounted) setState(() => _lastRun = run.at);
  }

  Future<void> _runOne(SecurityTest t, [TestEnv? env]) async {
    final e = env ?? await _env();
    if (mounted) setState(() => _running.add(t.id));
    final r = await runSecurityTest(t, e);
    if (!mounted) return;
    setState(() {
      _results[t.id] = r;
      _running.remove(t.id);
    });
  }

  int? get _score => _results.isEmpty ? null : securityScore(_results.values.toList(), securityTestWeights);

  String get _deviceName => Platform.isAndroid ? 'Phone' : 'PC';

  void _copyReport(TestRun run) {
    Clipboard.setData(ClipboardData(text: testReport(run, device: '$_deviceName ${_deviceIp ?? ''}'.trim())));
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Report copied - no secrets in it')));
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final cfg = c.config;
    final busy = _running.isNotEmpty;
    final current = TestRun(_lastRun ?? DateTime.now(), _score, [for (final x in allSecurityTests) ?_results[x.id]]);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        _ScoreCard(
          score: _score,
          running: busy,
          lastRun: _lastRun,
          counts: {
            for (final s in TestStatus.values) s: _results.values.where((r) => r.status == s).length,
          },
          onRun: busy ? null : _runAll,
          onCopy: _results.isEmpty ? null : () => _copyReport(current),
          chips: [
            _chip(Icons.devices, '$_deviceName ${_deviceIp ?? '(not on a house network)'}'),
            _chip(Icons.alt_route, 'Expected: ${switch (_expected) {
              ExpectedPath.vpn => 'VPN',
              ExpectedPath.direct => 'direct',
              ExpectedPath.unknown => 'unknown',
            }}'),
            if (_deviceIp != null) _chip(Icons.lan, networkNameFor(_deviceIp!, cfg.networks) ?? 'other network'),
            _chip(cfg.externalTests ? Icons.public : Icons.public_off,
                cfg.externalTests ? 'Outside checks on' : 'Router-only mode'),
          ],
        ),
        for (final g in TestGroup.values) ...[
          const SizedBox(height: 20),
          Text(g.label, style: t.titleMedium),
          const SizedBox(height: 8),
          Card(
            child: Column(children: [
              for (final test in allSecurityTests.where((x) => x.group == g))
                _TestTile(
                  test: test,
                  result: _results[test.id],
                  running: _running.contains(test.id),
                  onRun: busy ? null : () => _runOne(test),
                ),
            ]),
          ),
        ],
        const SizedBox(height: 20),
        if (_history.length > 1) ...[
          Text('History', style: t.titleMedium),
          const SizedBox(height: 8),
          Card(
            child: Column(children: [
              for (final run in _history.take(8))
                ListTile(
                  dense: true,
                  leading: _ScoreBadge(score: run.score),
                  title: Text(run.at.toLocal().toString().substring(0, 16)),
                  subtitle: Text(_countsLine(run.results)),
                  trailing: IconButton(
                    tooltip: 'Copy report',
                    icon: const Icon(Icons.copy, size: 18),
                    onPressed: () => _copyReport(run),
                  ),
                ),
            ]),
          ),
          const SizedBox(height: 20),
        ],
        Text('How these tests work', style: t.titleSmall),
        const SizedBox(height: 4),
        Text(
          '- Router checks ask your router directly - nothing leaves the house.\n'
          '- Outside checks (HTTPS only) use api.ipify.org, ipwho.is, bash.ws, Akamai whoami and '
          'Cloudflare speed. On the VPN they only see the ${cfg.vpnName} exit, never your home IP. '
          'Turn them off in Settings > Tests & privacy.\n'
          '- Country matching is a heuristic: a ${cfg.vpnName} server in ${cfg.homeCountryCode} would look "direct".\n'
          '- ${Platform.isAndroid ? 'On mobile data the phone is not on a house network, so leak results are informational.' : 'Results reflect this PC only.'}',
          style: t.bodySmall,
        ),
      ],
    );
  }

  String _countsLine(List<SecurityTestResult> rs) {
    int n(TestStatus s) => rs.where((r) => r.status == s).length;
    return '${n(TestStatus.pass)} passed, ${n(TestStatus.warn)} warnings, ${n(TestStatus.fail)} failed';
  }

  Widget _chip(IconData icon, String label) => Chip(
        avatar: Icon(icon, size: 16, color: OpnColors.textSoft),
        label: Text(label, style: const TextStyle(fontSize: 12)),
        visualDensity: VisualDensity.compact,
      );
}

(Color, IconData, String) statusLook(TestStatus s) => switch (s) {
      TestStatus.pass => (OpnColors.green, Icons.check_circle, 'PASS'),
      TestStatus.warn => (OpnColors.amber, Icons.warning_amber_rounded, 'WARN'),
      TestStatus.fail => (OpnColors.red, Icons.cancel, 'FAIL'),
      TestStatus.skip => (OpnColors.grey, Icons.remove_circle_outline, 'SKIPPED'),
      TestStatus.info => (OpnColors.glassCyan, Icons.info_outline, 'INFO'),
    };

Color scoreColor(int? score) => score == null
    ? OpnColors.grey
    : score >= 85
        ? OpnColors.green
        : score >= 60
            ? OpnColors.amber
            : OpnColors.red;

class _ScoreCard extends StatelessWidget {
  const _ScoreCard({
    required this.score,
    required this.running,
    required this.lastRun,
    required this.counts,
    required this.onRun,
    required this.onCopy,
    required this.chips,
  });

  final int? score;
  final bool running;
  final DateTime? lastRun;
  final Map<TestStatus, int> counts;
  final VoidCallback? onRun;
  final VoidCallback? onCopy;
  final List<Widget> chips;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final color = scoreColor(score);
    final ring = SizedBox(
      width: 112,
      height: 112,
      child: Stack(alignment: Alignment.center, children: [
        SizedBox.expand(
          child: CircularProgressIndicator(
            value: running ? null : (score ?? 0) / 100,
            strokeWidth: 9,
            backgroundColor: OpnColors.border,
            color: color,
          ),
        ),
        Column(mainAxisSize: MainAxisSize.min, children: [
          Text(score == null ? '--' : scoreGrade(score!),
              style: t.headlineMedium?.copyWith(fontWeight: FontWeight.w800, color: color)),
          Text(score == null ? 'not run' : '$score / 100', style: t.bodySmall),
        ]),
      ]),
    );
    final info = Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text('Security check', style: t.titleLarge),
      const SizedBox(height: 4),
      Text(
        running
            ? 'Running... router checks first, then outside checks.'
            : lastRun == null
                ? 'Leaks, kill switch, tunnels, encrypted DNS, certificate and line quality.'
                : 'Last run ${lastRun!.toLocal().toString().substring(0, 16)} - '
                    '${counts[TestStatus.pass]} passed, ${counts[TestStatus.warn]} warnings, '
                    '${counts[TestStatus.fail]} failed',
        style: t.bodyMedium?.copyWith(color: OpnColors.textSoft),
      ),
      const SizedBox(height: 12),
      Wrap(spacing: 8, runSpacing: 8, children: [
        FilledButton.icon(
          onPressed: onRun,
          icon: running
              ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
              : const Icon(Icons.play_arrow),
          label: const Text('Run all'),
        ),
        OutlinedButton.icon(onPressed: onCopy, icon: const Icon(Icons.copy, size: 18), label: const Text('Copy report')),
      ]),
    ]);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          LayoutBuilder(builder: (context, box) {
            if (box.maxWidth < 420) {
              return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Center(child: ring),
                const SizedBox(height: 12),
                info,
              ]);
            }
            return Row(children: [ring, const SizedBox(width: 20), Expanded(child: info)]);
          }),
          const SizedBox(height: 12),
          Wrap(spacing: 6, runSpacing: 6, children: chips),
        ]),
      ),
    );
  }
}

class _ScoreBadge extends StatelessWidget {
  const _ScoreBadge({required this.score});
  final int? score;

  @override
  Widget build(BuildContext context) {
    final color = scoreColor(score);
    return CircleAvatar(
      radius: 18,
      backgroundColor: color.withValues(alpha: 0.18),
      child: Text(score == null ? '-' : scoreGrade(score!),
          style: TextStyle(color: color, fontWeight: FontWeight.w800, fontSize: 13)),
    );
  }
}

class _TestTile extends StatelessWidget {
  const _TestTile({required this.test, required this.result, required this.running, required this.onRun});

  final SecurityTest test;
  final SecurityTestResult? result;
  final bool running;
  final VoidCallback? onRun;

  @override
  Widget build(BuildContext context) {
    final r = result;
    final (color, icon, label) = r == null ? (OpnColors.grey, Icons.radio_button_unchecked, '') : statusLook(r.status);
    final leading = running
        ? const SizedBox(width: 24, height: 24, child: CircularProgressIndicator(strokeWidth: 2.5))
        : Icon(icon, color: color);
    final subtitle = running ? 'Running...' : (r?.summary ?? (test.external ? 'Outside check - not run yet' : 'Router check - not run yet'));
    final trailing = Row(mainAxisSize: MainAxisSize.min, children: [
      if (r != null && !running)
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
          decoration: BoxDecoration(color: color.withValues(alpha: 0.15), borderRadius: BorderRadius.circular(8)),
          child: Text(label, style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w700)),
        ),
      IconButton(tooltip: 'Run this test', icon: const Icon(Icons.replay, size: 20), onPressed: onRun),
    ]);
    final details = r?.details.where((d) => d.isNotEmpty).toList() ?? const <String>[];
    if (details.isEmpty) {
      return ListTile(leading: leading, title: Text(test.title), subtitle: Text(subtitle), trailing: trailing);
    }
    return ExpansionTile(
      leading: leading,
      title: Text(test.title),
      subtitle: Text(subtitle),
      trailing: trailing,
      shape: const Border(),
      collapsedShape: const Border(),
      childrenPadding: const EdgeInsets.fromLTRB(56, 0, 16, 12),
      expandedCrossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (final d in details)
          Padding(
            padding: const EdgeInsets.only(bottom: 4),
            child: SelectableText(d, style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: OpnColors.textSoft)),
          ),
      ],
    );
  }
}
