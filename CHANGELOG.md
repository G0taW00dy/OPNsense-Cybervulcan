# Changelog

## 1.1.0 (unreleased)

### Added

* **Remote access, app-only.** A built-in WireGuard client (wireguard-go on a
  gVisor user-space network stack, `native/cvwg`, loaded through dart:ffi)
  that only Cybervulcan uses. It does not take Android's VPN slot, so Proton
  VPN can stay on. Each check tries the router directly (2 s) and only then
  the tunnel; the tunnel stops back home, in the background (Android) and
  after 3 minutes unused. A random per-tunnel access token protects the
  local forwarder from other apps.
* The app makes its own WireGuard key (private key in secure storage only,
  never shown or exported) and shows the public key with Copy and QR.
  Settings for endpoint (default `home.cybervulcan.com:51830`), router public
  key, tunnel address, allowed IPs (default `10.10.10.254/32`), keepalive
  (25 s) and an optional pre-shared key; import from a wg-quick `.conf`.
* **Certificate name check ("Option A").** The app connects to the router
  address (`10.10.10.254`) but checks the TLS certificate against a name
  (default `router.cybervulcan.com`, e.g. a Let's Encrypt wildcard) with the
  system CAs. The SHA-256 pin remains as an alternative for self-signed
  certificates. A failed check stops before any HTTP request, so the API
  key is never sent. Status shows Connected / Remote access / Not home /
  Wrong certificate.
* **First-run setup wizard** (both platforms): settings from the admin,
  router address and certificate name, API key, connection test, optional
  remote access.
* **Settings export / import without secrets** (text, QR, file) so an admin
  can hand a ready setup to another person.
* New settings for everything that was specific to this house: VPN provider
  name, label while bypassed, direct network name and the house networks.
* `docs/ADMIN-SETUP.md` (per-user API keys with minimum privileges,
  Let's Encrypt, road-warrior WireGuard, DDNS, router timer) and
  `docs/USER-SETUP.md`; in-app help updated.
* `router/install-ddns.sh`: GoDaddy dynamic DNS updater for OPNsense (one
  record only, changes only when the address changed, key in a root-only
  file).

### Changed

* Warning when the router address is plain `http://`.
* Warning when a whole-house bypass has no deadline on the router ("the
  router can't end this bypass by itself") with an **Add deadline** button;
  Settings warns when "Store bypass deadline on the router" is off; with it
  on, a missing deadline marker is restored automatically.
* Windows: the first time the window is closed, a one-time note explains that
  Cybervulcan keeps running in the tray (with a "Quit instead" choice).
* CI builds the Windows installer and the Android APK on every pull request,
  plus the native library and its Go tests.

### Upgrading from 1.0.x

Existing settings keep working unchanged: a 1.0 `http://10.10.10.254` or
pinned `https://` setup keeps checking the address (or pin) as before. Set
the certificate name in Settings once the router has its certificate.

## 1.0.1 (2026-11-12)

### Fixed

* DNS resolver test failed with "HTTP 404": the edns.ip-api.com label must be 32 characters.

### Added

* Router-side bypass timer (`router/install.sh`, one-line install from the
  OPNsense console): ends an expired bypass even when no app is running.
* Whole-house bypass "Until I turn it off" option (and 0 = no time limit as the
  default in Settings), with a reminder notification every 4 hours.
* Setup guide (help button in the menu and on Settings): router aliases, kill
  switch, API user and privileges, connecting the app, the router timer (with a
  copy button for the install line), troubleshooting.
* Settings: "Start Cybervulcan in the tray when I sign in" (Windows) and
  "Check for updates automatically".

### Changed

* Android updates install from inside the app: download, SHA-256 check, then
  Android's installer opens (one tap). Needs release-signed APKs.
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
