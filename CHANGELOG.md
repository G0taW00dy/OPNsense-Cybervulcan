# Changelog

## 1.0.0 (unreleased)

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

### Removed

* STATIC mode from the old PowerShell app.
