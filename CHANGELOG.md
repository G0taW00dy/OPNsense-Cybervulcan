# Changelog

## 1.0.1 (2026-11-12)

### Fixed

* DNS resolver test failed with "HTTP 404": the edns.ip-api.com label must be 32 characters.

### Added

* Whole-house bypass "Until I turn it off" option (and 0 = no time limit as the
  default in Settings), with a reminder notification every 4 hours.
* Setup guide (help button in the menu and on Settings): router aliases, kill
  switch, API user and privileges, connecting the app, troubleshooting.
* Settings: "Start Cybervulcan in the tray when I sign in" (Windows) and
  "Check for updates automatically".

### Changed

* Devices page shows a "Nothing connected yet" message when there are no leases.
* Settings: "VPN gateways" instead of "Proton gateways"; bypass length field explains 0.

## 1.0.0 (2026-11-12)

First release. Replaces the PowerShell "PC Mode" app.

### Added

* Windows tray app with an Inno Setup installer.
  * Tray icon colours: green, amber, red, purple and grey.
  * Toasts show "Cybervulcan" as the sender.
  * Single instance and optional autostart.
* Android app with a home-screen widget and a "VPN bypass" Quick Settings tile.
* Live Proton status: active exit (San Jose main / LA backup / none), plus ping, loss and jitter for each tunnel, and failover detection.
* Alerts for failover, failback, both tunnels down (kill switch tripped), and bypass start and end.
* PC mode on Windows: switch this PC between VPN and CLEAR through `PCMODE_CLEAR`. The switch is confirmed with the router, and the PC's IP is auto-detected (you can override it).
* Whole-house VPN bypass toggle through `BYPASS_ALL`.
  * Warns before turning on.
  * Auto-expires (2 h by default) with a countdown.
  * The deadline is shared across devices through a marker entry on the router and is enforced at every start and poll.
* Every mode change (PC VPN/CLEAR, bypass on/off, bypass auto-expiry) drops the affected IP's or subnet's pf states through `kill_states`, so connections move to the new path.
* Aliases are changed only through `/api/firewall/alias_util/*`. Firewall: Alias: Edit is not needed.
* Who's online: Dnsmasq DHCP leases grouped by network.
* Kill switch status: armed (from the rule search or the rule UUID's stats) and tripped (both tunnels down).
* Quick tests: exit IP and country check against the expected path, and a DNS resolver check.
* Self-signed router certificates can be trusted through SHA-256 pinning, with trust-on-first-use confirmed by you.
* API secrets are kept in OS secure storage only.
* GitHub Actions builds the Windows installer and Android APK, with a release on each tag.

### Changed (night theme)

* Always-dark night theme with ember and cyan accents.
* New "Vulcan V" logo replaces the OPn mark: app icon, tray icons in all five
  status colours, Android launcher, themed and notification icons.
* Status header shows the current exit large, over a volcano illustration
  whose tunnel line takes the house status colour.

### Added (updates)

* Update check against GitHub Releases at start-up and every 12 hours, with a
  Status banner, a notification and *Settings > Updates > Check now*.
* Windows: one-click install (SHA-256 checked when GitHub gives a digest,
  silent installer, app reopens). Android: opens the APK download.

### Removed

* STATIC mode from the old PowerShell app.
