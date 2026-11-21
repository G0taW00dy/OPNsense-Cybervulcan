# Changelog

## 2.1.8 (pre-release)
- Away: the connection no longer drops right after unlocking. The fingerprint prompt briefly counts as "background" on Android and the app stopped Tailscale at once; it now waits 15 seconds in the background before stopping remote access.

## 2.1.7 (pre-release)
- Away, after the app was in the background: no more "router not visible" for a few seconds while Tailscale restarts. The app now waits for Tailscale's device list before deciding.

## 2.1.6 (pre-release)
- Settings > Test now works away from home: when the home address does not answer, it tests through the remote route the app is already connected on (Tailscale or the in-app tunnel) and says so.
- "Router's Tailscale address" rejects this device's own Tailscale name.

## 2.1.5 (pre-release, 21 Nov 2026)

* Built-in Tailscale: explicitly accept subnet routes after start (the phone
  was signed in and saw the router but never sent it a packet).
* "Router not visible" now says what the device sees on the tailnet (peers,
  their routes, whether routes are accepted) for diagnostics.

## 2.1.4 (pre-release, 21 Nov 2026)

* Fix the phone crash when the built-in Tailscale starts: Tailscale wanted a
  folder for its log state and Android has none of its usual places
  ("no safe place found to store log state"); it now uses the app's own
  folder (nothing is uploaded).

## 2.1.3 (pre-release, 21 Nov 2026)

* Phone closed ~2 s after start when away (built-in Tailscale starting):
  - a crash while the engine starts now pauses the engine on the next
    launch instead of crashing again ("Sign in to Tailscale" retries);
  - a fatal native crash is saved and shown in Copy diagnostics, so the
    cause can be found.

## 2.1.2 (pre-release, 21 Nov 2026)

Found testing 2.1.0 on the PC:

* "This PC" card said "on the VPN" for a device on another network (e.g.
  MGMT); it now names the network and disables VPN/CLEAR there.
* Bufferbloat advice knows when a shaper is already set up and names the
  limit that is above what the line delivers (with a suggested value).
* Shaper card reads and shows the current limits when Settings opens.
* Remote modes that can't run on this device/engine are disabled with the
  reason (Windows: no "Everything"; Tailscale: no "Everything").
* Key-expiry date error says "Use a real date".

## 2.1.1 (pre-release, 21 Nov 2026)

* Fix: after the app had been locked once, opening a dialog or page could
  fail ("Null check operator" in HeroController) - the lock screen's own
  navigator shared the app's hero controller.

## 2.1.0 (pre-release, 21 Nov 2026)

### Fixed (found testing 2.0.4)

* Server switch: the router's `set_client` clears the peer's instance link
  when it isn't sent, which took the tunnel down. The link is now read and
  sent back (and restored if already lost); routes and the gateway monitor
  are refreshed; the switch only counts once a real handshake with the new
  server is seen, otherwise the old server is put back.
* No more "status: null" after a WireGuard restart (`{"result":"ok"}` is OK).
* App lock: the lock now sits above every page, so pages and dialogs survive
  it and the PIN dialog shows on the lock screen; the fingerprint prompt
  waits until the app is really back in front; time in a file picker or
  browser opened by the app doesn't count as leaving it (fixes the crash
  opening a config file from a cloud drive).
* Imported servers: the city is asked, not guessed; "Set city" / "Remove".
* "This phone is now CLEAR" on the phone.
* Tests: Quad9 recognised under its Australian network names; "line
  congestion" verdict when both tunnels slow down alike; bufferbloat also
  reads the router's tunnel monitor under load.

### Added

* **Provider profiles**: Proton VPN, Mullvad (server list downloaded from
  Mullvad), Other WireGuard providers. Proton closed its public server list
  in 2025, so Proton servers are added from its config page.
* **Scan QR** (phone) or paste a config to add a server; only the server
  address and public key are kept. Decoding runs on the device (ZXing).
* **Tunnel key expiry** dates with warnings 30/7/1 days before and on expiry.
* **Shaper card and auto-tune**: shows the VPN limits; auto-tune lowers them
  when lag rises under load and raises them when clear (within min/max),
  starts again after a server switch; re-tune; restore original limits.
* **Router safety net**: journal of every router change the app makes,
  failed server switches undone, shaper limits restored if tuning keeps
  failing.
* **Setup checker** (Settings > Test): checks gateways, kill-switch rule,
  tunnel links and shaper pipes with the fix in each line, and lists what
  this API key can do.
* **Copy diagnostics**: redacted bug-report text (no keys or secrets; public
  IPs and domain names blanked) with recent router changes and app errors.
* docs/ROUTER-REMOTE-MODES.md: router steps for the remote access modes.

### Remote modes and VPN-app reminder (phone)

* **Remote access can carry more than the app** (Settings > Remote access >
  What it carries): *App only* (default, unchanged), *Home devices only*
  (a real Android VPN that routes just the listed home devices - e.g. the NAS -
  plus the router through the WireGuard tunnel) and *Everything via home*
  (all traffic exits through the house and its VPN tunnels; DNS = router,
  IPv6 blocked). On only while away with remote access connected; uses the
  phone's VPN slot. Persistent notification with Disconnect; supports
  Android's Always-on VPN. Status page shows "Home link: ... - connected".
* **VPN-app reminder** (Alerts & reminders, off by default): "You're home -
  you can turn your VPN app off" / "You've left home - turn your VPN app back
  on", only on changes and at most every 20 minutes.
* Native library: new platform-neutral `vpn` package (gVisor netstack on the
  VPN interface, every TCP/UDP flow re-dialled through the tunnel) and
  `cvvpn_*` exports; the tunnel's Allowed IPs follow the chosen mode.

### Added - built-in Tailscale

* **Tailscale built into the app**: remote access through Tailscale without
  the Tailscale app - works behind CGNAT (5G home internet), uses no VPN
  slot on Android and needs no admin rights on Windows. Sign in once with
  "Sign in to Tailscale" (browser login, no auth keys); the login is kept.
  Settings shows the Tailscale state, approval needed, relay vs direct path
  and the device key expiry date. "Sign out" forgets the login.
* **Remote access engine: WireGuard, Tailscale or Auto.** Auto tries
  WireGuard first and uses Tailscale when WireGuard can't connect in time;
  while Tailscale is working it is tried first. Remote access now has its
  own on/off switch. v2.0 settings carry over (Tailscale users keep using the
  Tailscale app until they turn on "Built-in Tailscale").
* Native library: tsnet (Tailscale 1.104) next to wireguard-go in the same
  library; Go 1.27. Log upload to Tailscale is off.

### Windows: home link (remote modes "Home devices" / "Everything")

* The remote modes now work on Windows too, through a new **Cybervulcan**
  network adapter (Wintun): *Home devices* routes the listed home devices
  (e.g. the NAS) through the house; *Everything* sends all of the PC's
  traffic via the house with DNS from the router and no IPv6 leak. *App
  only* (the default) is unchanged and needs no admin rights.
* Turning a mode on shows a Windows admin (UAC) prompt: a small helper (the
  app's own exe with `--vpn-helper`) creates the adapter and sets routes /
  DNS, and talks to the tray app over pipes only your Windows user can open
  (start / stop / status with checked settings, and the adapter's packets).
  The WireGuard tunnel and its keys stay in the tray app; packets run
  through the same VPN core as on Android. Turning the mode off, or closing
  the app, removes the adapter, routes and DNS.
* The WireGuard endpoint and the router's own address stay on the real
  network (host routes via the normal gateway, following Wi-Fi changes).
* The installer ships the official signed `wintun.dll` (0.14.1, checksum
  and signature checked in CI) and its licence (`wintun-LICENSE.txt`).

## 2.0.4 (pre-release)

### Fixed

* Bufferbloat test pushes the line like Speedtest: 8 parallel streams each
  way, 12 s per direction, sampling after a 2.5 s ramp-up, loaded latency as
  the interquartile mean. With 3 streams it graded A while Speedtest showed
  ~+1.4 s on the same line.

## 2.0.3 (pre-release)

### Fixed

* Bufferbloat test: the download didn't run (one 100 MB request was refused),
  so an idle line was graded A+. Now 3 parallel streams each way with 25 MB
  requests, and the result says "not valid" when the line couldn't be loaded.
* bash.ws now hands out hexadecimal test ids; accepted.

## 2.0.2 (pre-release)

### Changed

* **App lock works like a banking app**: unlock once when the app opens
  (fingerprint, face, device PIN / Windows Hello, or the new app PIN), then
  it stays unlocked until the app has been in the background (or the PC
  window hidden in the tray) for 1, 5 or 15 minutes. Turning the lock off,
  changing or removing the app PIN, and changing VPN servers always ask.
  Tray / widget / tile shortcuts that go off the VPN ask unless the app was
  unlocked a moment ago. Going back on the VPN never asks.
* **App PIN** (Settings > Security & privacy): a backup for prompts that only
  offer a fingerprint, or devices without a screen lock / Windows Hello.
  Stored as a salted hash; 5 wrong tries cancel.

### Fixed

* The app lock could be switched off without unlocking.
* The system prompt now explicitly allows the device PIN, not only biometrics.

## 2.0.1 (pre-release)

### Changed

* **Shareable**: no personal names, domains or cities built in any more.
  New installs start neutral (router `https://10.10.10.254`, no certificate
  name, tunnels "Main" / "Backup", no endpoint, no server cities); help
  texts and docs use example values (`router.example.com`). Existing
  settings are kept. Hand your setup to others with *Share settings*.
* "Use https://<certificate name>" button in Settings when the router URL is
  still an IP (also fills in the Router LAN IP).
* Long connection-test reports fold to one line ("6 OK - 2 skipped").
* "This phone" card shows a phone icon.

### Fixed

* **Bufferbloat test measured the wrong thing**: it timed the device-to-router
  hop, which never crosses the slow internet link, so it always looked fine.
  It now times 1.1.1.1 idle, while downloading and while uploading, and grades
  the added delay A+ to F (Waveform-style). Wi-Fi warm-up samples are skipped.
* bash.ws DNS leak id: accepts JSON/whitespace answers and reports what came
  back when it fails.

## 2.0.0 (pre-release)

### Added

* **Phone CLEAR.** "This phone" switches just the phone between VPN and
  direct internet (same `PCMODE_CLEAR` alias as the PC; at home on Wi-Fi).
* **Tailscale remote access** (works behind CGNAT). Settings > Remote access
  picks Off / WireGuard / Tailscale. Uses the device's Tailscale app: either
  a subnet route for the router (the normal URL just works) or the router's
  tailnet address. The certificate-name check still applies. Status shows
  "Away - via Tailscale".
* **Pro Tests page.** Security score (A+ to D) from weighted checks:
  * Router side: kill switch armed + blocked count, both tunnels up +
    WireGuard handshakes, DNS-over-TLS servers (and DNSSEC), router
    certificate validity and days to expiry, tunnel latency / jitter / loss.
  * Outside (HTTPS only, can be switched off): exit IP, exit consistency
    across two providers, extended DNS leak test (bash.ws unique lookups +
    Akamai whoami), IPv6 leak, bufferbloat and download speed.
  * Run all or one, details per check, last 20 runs kept, copyable report
    with no secrets.
* **Proton server switcher** (optional, needs *VPN: WireGuard* on your own
  key): download Proton's server list or add servers from Proton `.conf`
  files (only the public key and endpoint are kept), switch either tunnel's
  server, and **Find best**: candidates are measured on the backup tunnel
  (the house stays on main), the winner is promoted only if it is at least
  10 % better, the runner-up from another city becomes the backup. Optional
  nightly run (3-5 am).
* **Preferences**: app lock (fingerprint / face / PIN / Windows Hello before
  bypass, CLEAR, server changes and saving settings), new-device alerts from
  the DHCP leases, scheduled whole-house bypass, router backup reminder.
* **Router URL** setting default `https://router.cybervulcan.com`, plus a
  separate *Router LAN IP* (`10.10.10.254`) that remote access targets.

### Changed

* **Settings redesigned**: fold-out sections with one-line summaries, a "?"
  explanation on every field, Save / Test bar always visible with an
  "unsaved changes" hint. Settings export leaves out personal preferences.
* Connection test lists optional privileges as SKIP instead of failures.

### Fixed

* A "Bypass check failed" banner from an earlier poll (e.g. before the router
  URL was fixed) stayed until the next button press; a good poll now clears it.

### Not yet tested on real devices

Tailscale on the router, the server switcher against Proton, the app lock on
Windows Hello / Samsung, and the new Tests against the live network.


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
  Let's Encrypt via DNS-01, road-warrior WireGuard on UDP 51830, dynamic DNS
  with OPNsense's own os-ddclient, router timer; deSEC with per-record scoped
  tokens as the worked example) and `docs/USER-SETUP.md`; in-app help
  updated.

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
pinned `https://` setup keeps checking the address (or pin) as before. A
plain `http://` address shows a warning on the Status page with a **Switch to
HTTPS** button (`https://<same IP>` + certificate name
`router.cybervulcan.com`); or set it in Settings.

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
