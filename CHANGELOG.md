# Changelog

## 2.2.5 (pre-release)
Security, privacy and battery release (independent code audit, 24 Nov).
- Updates are signed: every release file has a minisign signature, and the app installs an update only if it verifies against the publisher key built into the app (checked again right before the installer runs). Unsigned releases are refused.
- Battery (Android): the router is checked every 5 minutes while the app is in the background (was every 15 seconds all day); on screen it stays at your setting. The widget no longer greys out after one missed check while the phone sleeps.
- Router address: a plain http:// address is no longer used for direct connections (the API key would travel unencrypted to whatever answers at that address). Use https://.
- Windows: the DNS lock of "Everything via home" no longer survives a reboot, and if a crash leaves it behind the Status page offers "Repair DNS". Home-link status no longer freezes the tray app when the helper is slow. The admin helper only runs from Program Files, and its log folder can't be redirected by other users. The built-in Tailscale login is now encrypted for your Windows account.
- App PIN: stored with PBKDF2; wrong PINs now lock it for a while (5 free tries, then 1 min, doubling up to an hour), even across restarts. Existing PINs keep working and are upgraded on the next unlock.
- Settings import never takes a certificate pin, and says so when it changes the router address or certificate name.
- WireGuard config import: size, port and host checks. Help: the router timer install line now uses this version's script and checks its SHA-256.
- Tests: in direct mode, Quad9's Australian resolvers (hosted by local ISPs) pass when the router's DNS-over-TLS to Quad9 is confirmed. The outside-services list now names every service used.
- Everything via home: hints for a full kill switch (Android: Always-on VPN + Block connections without VPN).
- Build: privacy check on every file, commit message and commit email; actions pinned to commit SHAs; release fails without the Android release key or the update signing key; Go vulnerability scan (fixed GO-2026-6865 in a compression library); pre-release branches are removed once published.

## 2.2.4 (pre-release)
- Tests: away on Windows with "Everything via home" connected, the PC's own traffic goes through the house VPN - the tests now expect the VPN path, so exit and DNS leak checks pass/fail properly instead of "not on a house network the app can judge".
- Verified on a laptop on another network: 2.2.3 switches Home devices <-> Everything with no DNS loss and no admin prompt; exit and DNS both via the house VPN.

## 2.2.3 (pre-release)
- Windows "Everything via home": switching to it restarted the app's tunnel, which looked up the home name again - but with the DNS lock already on, that lookup needed the very tunnel that was restarting, and the PC lost DNS (found in testing 23 Nov). The app now keeps the last good address of the home name and uses it when a lookup fails.
- Safety: if home can't be reached for 90 s while Windows "Everything via home" is on, the mode pauses (adapter and DNS lock removed, internet goes direct) and comes back by itself when home answers - the PC is never left without DNS.

## 2.2.2 (pre-release)
- Update channel: Settings > App & updates > "Test builds" also installs pre-releases (the newest test build), with the same checksum check. Off (default) = stable releases only - for family devices.

## 2.2.1 (pre-release)
- "Everything via home" now works on Windows. While it is on, a Windows name-resolution policy sends every lookup to the tunnel's resolver only (Windows otherwise also asks the Wi-Fi's own DNS servers at the same time); the policy is removed when the mode stops, when the helper ends, and by the next start after a crash. The route to the home endpoint is re-pinned when the PC changes networks.
- Everything via home: choose its DNS server (Settings > Remote access): empty = the router, or e.g. 10.2.0.1 for Proton's DNS inside the house tunnels - the same as devices on the house VPN network. The router needs a rule letting the remote tunnel reach it through the VPN gateway.
- Remote access: "Scan QR code" (Android) imports the config the router's Peer generator shows for a new device.
- Tests: a read-only API user (family app) now gets the house tunnels' country from the live tunnel names, so a Singapore exit is no longer judged against "US". Away from home, a changing mobile exit address is information, not a warning, and lag under load is blamed on the network in use, not the router's shaper. With Everything via home on, the exit test says the app's own checks go direct and to check ipleak.net in a browser.
- Remote access mode buttons use short labels ("Everything" wrapped mid-word on phones).

## 2.2.0
First stable v2 release: everything in 2.1.x (server switcher and Find best, shaper by exit path with presets and city limits, remote access with WireGuard / Tailscale and the "Home devices only" mode, speed-test fallback, Wake on LAN, router-network hints). Same code as 2.1.24, tested 22-23 Nov on the router, the PC, the phone and the laptop (away on IoT Wi-Fi). "Everything via home" stays Android-only for now.

## 2.1.24 (pre-release)
- Wake button fixed: the router's Wake on LAN API wants the interface and MAC (`wake: {interface, mac}` to /api/wol/wol/set) - posting to set/<id> answered `[]` and sent nothing, and the app showed "Expected a JSON object". Checked on the router: the right call answers `{"status":"OK"}`.
- Tested on the laptop away (IoT Wi-Fi, 23 Nov) with 2.1.23: home link connected, RustDesk to the PC through it, Network layout offered CAMS, city labels Singapore/Singapore.

## 2.1.23 (pre-release)
- Windows home link: the elevated helper could not accept the app's connection - its own pipe gave Administrators no right to add the next pipe instance, so every accept failed with "Access is denied" (found with 2.1.22's helper log, 23 Nov). Administrators now have full access to the helper's pipe (they own it and the PC anyway); the app's user still gets only read/write.

## 2.1.22 (pre-release)
- Windows home link fixed: the app asked for more rights on the admin helper's pipe than the pipe grants, so Windows refused every try and the app gave up with "the admin helper did not answer" (23 Nov, laptop away). It now asks for exactly what the pipe allows (vendored pipe dialer with an access setting). If the helper still stops early, the message says why (its exit code, plus the last line of its log in ProgramData\Cybervulcan\vpn-helper.log).
- Tunnel names follow their server's city on every device about once a minute, not only when the VPN servers card opens (the phone's Status said Tokyo and the laptop's Settings San Jose while both tunnels were in Singapore).
- Remote access "Auto": the home-device modes always try WireGuard first - Tailscale only reaches the router, so the NAS and PC were unreachable after one WireGuard hiccup made it switch. In "App only" it stays on Tailscale for at most 5 minutes before trying WireGuard again.
- Android: when another VPN app (the provider's) is set as Always-on VPN, Android refuses Cybervulcan's VPN without asking. The app now says so and has an "Open VPN settings" button. The "VPN permission was not given" warning goes once the VPN is connected.
- Windows installer: an all-users install removes an old "just me" copy (two copies were installed side by side). An upgrade keeps the earlier choice; the app's message now gives the exact /ALLUSERS command to switch.
- Devices: a "Wake" button on devices saved in the router's Wake on LAN page (plugin os-wol), and a "Wake on LAN" list for saved devices that are offline. The API user needs "Services: Wake on LAN".
- Devices: the first load through a freshly started remote tunnel no longer times out (longer wait, one quiet retry).
- Settings > Network layout: lists networks the router has that are missing from "House networks" (CAMS was), with an Add button.
- A tunnel key replaced on the router moves that tunnel's expiry date to a year from today, noted under Router changes.

## 2.1.21 (pre-release)
- Speed test fallback fixed: DigitalOcean's test hostnames no longer exist and OVH/Linode did not answer from the Proton exit, so the 2.1.20 fallback still read "download 0.0". It now uses Vultr's public test files (Singapore, Tokyo, Sydney, Los Angeles, Frankfurt - checked from the Singapore exit), and the result says when the fallback was used.

## 2.1.20 (pre-release)
- Speed tests (Tests page and shaper Measure): when Cloudflare refuses with HTTP 429 - it did for 15+ minutes on a busy Proton Singapore exit - downloads switch to the fastest of several public test files (see 2.1.21) instead of failing with "download 0.0". Measure uses 8 streams again.
- Shaper rows show the limit only; the dialog explains real speed is 80-95 % of a tunnel limit depending on the server (Tokyo 410 -> 336, Singapore 415 -> 389), not a fixed guess.
- Server scores say "just now" instead of "0 min ago".

## 2.1.19 (pre-release)
- Find best: fixed moving the winner to main when it was the last server tested - it was still on the backup tunnel, the router refused the same key twice ("Public keys should be unique") and the run rolled back (23 Nov, SG#210 at 78 ms vs Tokyo 147). The backup now moves off first; every step re-reads the tunnels.
- Find best keeps the real server names when it restores or reports a tunnel (a rollback renamed the tunnel peers "Tokyo (37.19.205.155)").
- Real progress: "Server 3 of 15 - about 20 min left" with a filling bar, instead of a moving loading bar.
- Each server shows its last Find best result ("78 ms, jitter 0.5, loss 0 % - 2 h ago") and the list is sorted best first.

## 2.1.18 (pre-release)
- Scanning a server that is the same machine as one already listed (same address and key - Proton runs several names on one server, e.g. JP#153 and JP#157) keeps both names on one entry ("JP#153 JP#157") and says so, instead of replacing the name. A tunnel using that machine gets the joined name on the router too.

## 2.1.17 (pre-release)
- Find best rotates through the list: it remembers when each server was last tested and tries never-tested ones first, then the longest ago - so repeated runs and the nightly run cover every server, not the same few. Candidates: 3, 5, 10 or All (with the time it takes, ~100 s each). It follows the Cities dropdown; ticked cities with no servers are ignored (an old "San Jose, Los Angeles" setting found no candidates).
- Old "Former <city> server" entries get their city from the name.

## 2.1.16 (pre-release)
- From the 23 Nov phone test of 2.1.15 (server names from the router, switch backup to JP#302 and back to JP#219 with names and cities kept - all OK):
  - VPN servers: the "Only <cities>" on/off chip is replaced by a Cities dropdown with a tick per city and "All cities". A ticked city with no servers no longer hides the whole list.
  - Tunnel names follow their server's city on every device (with "Name tunnels after their server's city" on), not only on the device that switched - the phone still said San Jose / Los Angeles.
  - New Swap button on the VPN servers card: main and backup trade servers. The router allows each server on one tunnel at a time, so the backup waits on a spare server from the list for a moment; every step waits for a real handshake. Tunnel limits saved for the new main city are applied.

## 2.1.15 (pre-release)
- From the 23 Nov PC test of 2.1.14 (Tests A+ 100, Devices lists all 11 leases, presets, per-city limits, path on/off, rename to the router's tunnel peer all worked):
  - Shaper Measure: the app's test read 258/32 on a tunnel speedtest.net measured at 413/47, so "Use recommended" no longer lowers working limits by itself - it explains and asks you to press it again. The test now uses 16 streams for 12 s each way.
  - Shaper actions show their result in Settings too (it only appeared on Status).
  - The "Saved for <city>" line follows the main tunnel without pressing refresh.
  - Rename: Enter saves. A server's menu no longer offers the tunnel it is already on.

## 2.1.14 (pre-release)
- Shaper presets: save named limits for both paths ("NBN 500", "Boost 1000/100" for a speed-boost day, "Away mode") and put them on the router with one tap. New presets start from the limits on the router now; a preset can hold just one path. Kept on this device.
- Tunnel limits per city: limits you set for the tunnel are remembered for the main tunnel's city (shown under the tunnel row, with Remember / Update / forget) and go back on the router by themselves when the main tunnel moves to that city - by a switch, Find best or the nightly run.

## 2.1.13 (pre-release)
- Shaper redesigned (22 Nov tuning on the house NBN line):
  - Continuous auto-tune and "Restore original limits" are gone: on a quiet line it saw no lag and kept raising the limits (VPN went to 594/52, above the tunnel's real speed, so the shaper did nothing).
  - Two paths, each with an on/off switch and limits you can type in: Tunnel (everything through the VPN) and Direct line (CLEAR network, devices switched to CLEAR, whole-house bypass).
  - "Recommend from a speed test": press Measure (the shaper for that path is switched off for ~25 s while this device tests) or type your speedtest.net figures; the recommended limits fill in and can still be changed before saving.
  - The card shows the real speed to expect (the tunnel delivers ~82 % of its limit, the direct line ~97 %) and re-reads the router about every minute (it showed old limits before).
  - Checks the router's shaper rules: rules by network (VPN / CLEAR) held a device on CLEAR to the VPN limit. "Set up rules by exit path" replaces them with rules on the tunnel interfaces and WAN.
- VPN servers: the server a tunnel uses is stored in the tunnel peer's name on the router (CVT_...) when you switch, rename or set its city, so every device shows its name instead of "Main tunnel server" or a bare IP. New "Rename" in each server's menu.
- A new device turns "Keep the server list on the router" on by itself when the router already has the shared list (the new desktop install showed only two servers).
- Names saved with dashes before 2.1.12 read with spaces ("Former Los Angeles server").
- Tests: when this device doesn't know a tunnel's server, the expected exit country comes from the tunnel endpoint (the PC judged a Tokyo exit against "US" and warned about its own VPN app). The device chips fill in when the page opens, not only after Run all.
- Devices: all leases are listed (the router returned one page only, so the phone's new lease was missing).
- Status: "This PC" says it is going direct while whole-house bypass is on (it said "on the VPN").

## 2.1.12 (pre-release)
- Review fixes (independent review of the router-writing code - nothing critical found):
  - Router server list: background saves (after a switch, Find best, the nightly run) only ADD - an older copy on one device can no longer delete servers another device added. Removing is an explicit action on the VPN servers page.
  - A failed switch puts the target server back in the router list; one bad entry no longer stops the rest.
  - Leak tests: an exit or DNS resolver on a home-country ISP is always a leak, even when a tunnel server is in the same country; VPN network names match whole words only.
  - CLEAR auto-tune waits for a monitor IP on the WAN gateway instead of tuning on no data.
- Both tunnels down: says "Internet line down - check the modem and WAN cable" when the router's WAN gateway is down (needs a monitor IP on the WAN gateway); otherwise suggests checking the line first when both drop together (22 Nov modem dropout).
- Tests: the bypass timer on the router was verified end to end (expired on time, logged).
- Tunnel names follow the new server's city after a switch on every device (new setting "Name tunnels after their server's city", on by default) - the old guess failed on a device that didn't know the old name was a city.
- VPN servers: the "(main/backup) now" tags move right after a switch or Find best (no need to reopen the page).
- The server a tunnel leaves keeps the tunnel's city; names with spaces survive the router list.

## 2.1.11 (pre-release) - includes everything below from 2.1.10 onwards

## 2.1.10 (pre-release)
- Tests: the expected exit country comes from the servers the tunnels use now (JP#153 -> Japan), so a Tokyo exit and Proton's Japanese DNS pass instead of "neither AU nor US".
- Tests: an exit or DNS on a VPN provider's network that is not one of the router's tunnels (e.g. the device's own Proton app) is a warning - "this device's own VPN app is probably on" - not a leak.
- Tests on PC: lists other network connections (e.g. a second Wi-Fi) that may carry the internet instead of the router; networks other than VPN/CLEAR are described ("goes straight to the internet") instead of "can't reason about".
- Bufferbloat: smaller upload pieces (slow far-away uploads were under-measured); advice no longer blames a limit that is below the measured speed, and on an unshaped network (e.g. MGMT) says so.
- VPN servers: no "Only my cities" chip when no cities are chosen.
- After a server switch the tunnel's name follows the new server's city (Status title, widget, tray, alerts) - unless you gave it your own name.
- VPN servers: the server each tunnel uses is always listed (on every device), tagged "(main) now" / "(backup) now" - name it with Set city. After a switch, the server the tunnel left goes into the list (and the router list), even on a device that never had it.

## 2.1.9 (pre-release)
- Settings > Diagnostics: the buttons wrap instead of squeezing "Copy diagnostics" onto three lines.
- Widget: shorter "Out of reach · last seen" line so it no longer runs over the artwork.
- Tests: "Clear history" (keeps the latest run); a quick double tap on Run all no longer starts two runs.
- The Quick Settings tile is now called "Cybervulcan bypass" so it is easy to find, and shows the Cybervulcan V instead of a "P".
- VPN servers: the heading says when the city filter hides servers ("1 of 4 - filter on"), and adding a server the filter hides says so.
- Router server list fixes from the first real try: the router allows each public key on one peer only, so a server a tunnel is using is not added again (it was rejected and stopped the rest); one rejected entry no longer stops the others; switching a tunnel to a listed server removes its list entry first, and the server the tunnel left goes back into the list.
- Turning on "Keep the server list on the router" copies the list to the router as soon as you save (before, only when the VPN servers page opened).
- Cities: when adding a server, pick a city you already have from chips (or type a new one); Settings > "Cities to choose from" gets tap-to-choose chips for every city in your list.
- Bypass time choices read 30 min · 1 h · 2 h · 4 h.

## 2.1.8 (pre-release)
- Away: the connection no longer drops right after unlocking. The fingerprint prompt briefly counts as "background" on Android and the app stopped Tailscale at once; it now waits 15 seconds in the background before stopping remote access.
- Settings > Shaper: if the limits could not be read (router not reachable yet), the app tries again after the next good router check instead of showing the error until Settings is reopened.
- Settings > Shaper lists every limit on the router (VPN and CLEAR, download and upload) with whether auto-tune moves it. The min/max boxes now say which network they are for.
- New: "Auto-tune CLEAR too" tunes the direct internet line's limits against the WAN gateway's ping (off by default). Restore puts both VPN and CLEAR limits back.
- VPN servers page: marks the server each tunnel uses now, says when a tunnel's server is not in the list, and no longer shows a grey "offline-looking" dot for servers without a load figure.
- New: "Keep the server list on the router" (Settings > VPN tunnels, off by default). Servers you add are saved on the router as switched-off, unlinked WireGuard peers (CVL_...), so every device with your key shares one list. The live tunnels are never touched by it.
- Home-screen widget redesigned in the Cybervulcan style (status word, exit city, ping and backup state, where you are, the peak-and-circuit art). Away or with the app paused it keeps the last known status, greyed, with "last seen", instead of a red "Router unreachable".
- Built-in Tailscale is no longer paused after a single unexplained close (Android closing the app in the background looked like a crash). It is paused only on a real native crash, or two failed starts in a row.
- Settings > Diagnostics: "Clear errors" removes old, already-fixed errors from the diagnostics.

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
* **Router URL** setting default `https://router.example.com`, plus a
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
  Settings for endpoint (default `home.example.com:51830`), router public
  key, tunnel address, allowed IPs (default `10.10.10.254/32`), keepalive
  (25 s) and an optional pre-shared key; import from a wg-quick `.conf`.
* **Certificate name check ("Option A").** The app connects to the router
  address (`10.10.10.254`) but checks the TLS certificate against a name
  (default `router.example.com`, e.g. a Let's Encrypt wildcard) with the
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
`router.example.com`); or set it in Settings.

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
