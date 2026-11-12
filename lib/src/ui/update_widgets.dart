import 'package:flutter/material.dart';

import '../core/updater.dart';
import 'format.dart';
import 'theme.dart';

/// Shown on the Status page when a newer release is out.
class UpdateBanner extends StatelessWidget {
  const UpdateBanner({super.key, required this.updates});

  final UpdateService updates;

  @override
  Widget build(BuildContext context) => ListenableBuilder(
        listenable: updates,
        builder: (context, _) {
          final r = updates.available;
          if (r == null) return const SizedBox.shrink();
          final t = Theme.of(context).textTheme;
          final progress = updates.downloadProgress;
          final windows = updates.target == UpdateTarget.windows;
          return Padding(
            padding: const EdgeInsets.only(top: 16),
            child: Card(
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(20),
                side: BorderSide(color: OpnColors.ember.withValues(alpha: 0.7)),
              ),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    const Icon(Icons.system_update_alt, color: OpnColors.ember),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text('Cybervulcan ${r.version} is available',
                          style: t.titleMedium?.copyWith(fontWeight: FontWeight.w600)),
                    ),
                  ]),
                  const SizedBox(height: 4),
                  Text('You have ${updates.currentVersion}.'
                      '${windows ? ' Installing closes the app and reopens it when done.' : ' The APK downloads in your browser; tap it to install.'}',
                      style: t.bodyMedium?.copyWith(color: OpnColors.textSoft)),
                  if (r.asset == null)
                    Padding(
                      padding: const EdgeInsets.only(top: 6),
                      child: Text('This release has no ${windows ? 'installer' : 'APK'} attached.',
                          style: t.bodySmall?.copyWith(color: OpnColors.amber)),
                    ),
                  if (updates.error != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 6),
                      child: Text(updates.error!, style: t.bodySmall?.copyWith(color: OpnColors.red)),
                    ),
                  const SizedBox(height: 12),
                  if (progress != null)
                    LinearProgressIndicator(value: progress > 0 ? progress : null, color: OpnColors.ember)
                  else
                    Wrap(spacing: 8, runSpacing: 8, children: [
                      FilledButton.icon(
                        style: FilledButton.styleFrom(
                            backgroundColor: OpnColors.ember, foregroundColor: OpnColors.ink),
                        onPressed: r.asset == null ? null : updates.install,
                        icon: Icon(windows ? Icons.download : Icons.open_in_browser),
                        label: Text(windows ? 'Install now' : 'Download APK'),
                      ),
                      TextButton(onPressed: updates.openReleasePage, child: const Text("What's new")),
                    ]),
                ]),
              ),
            ),
          );
        },
      );
}

/// "Updates" block for the Settings page.
class UpdateSettingsCard extends StatelessWidget {
  const UpdateSettingsCard({super.key, required this.updates});

  final UpdateService updates;

  @override
  Widget build(BuildContext context) => ListenableBuilder(
        listenable: updates,
        builder: (context, _) {
          final t = Theme.of(context).textTheme;
          final last = updates.lastChecked;
          final String status;
          if (updates.checking) {
            status = 'Checking...';
          } else if (updates.error != null) {
            status = updates.error!;
          } else if (updates.available != null) {
            status = 'Version ${updates.available!.version} is available - see the Status page.';
          } else if (last != null) {
            status = 'Up to date (checked ${formatClock(last)}).';
          } else {
            status = 'Not checked yet.';
          }
          return Card(
            child: ListTile(
              contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              leading: const Icon(Icons.system_update_alt, color: OpnColors.ember),
              title: Text('Version ${updates.currentVersion}', style: t.titleMedium),
              subtitle: Text('$status\nChecks GitHub Releases (${updates.repo}) at start-up and every 12 hours.'),
              isThreeLine: true,
              trailing: TextButton(
                onPressed: updates.checking ? null : updates.check,
                child: const Text('Check now'),
              ),
            ),
          );
        },
      );
}
