# OPNsense Cybervulcan ("OPn")

A companion app for a home OPNsense router running Proton VPN over WireGuard
with gateway failover. It's one Flutter codebase with two targets:

* **Windows**: a tray app with an `.exe` installer. The tray icon changes colour with the house status, and the app switches the PC between VPN and CLEAR.
* **Android**: an `.apk` with a home-screen widget (current exit plus a bypass button) and a Quick Settings tile for the whole-house bypass.

It replaces the old PowerShell "PC Mode" app. Notifications now come from
**Cybervulcan**, not "Windows PowerShell". STATIC mode has been removed.

## Features (v1)

| | Windows | Android |
|---|---|---|
| Live status: active Proton exit (San Jose main / LA backup / none), ping, loss and jitter per tunnel, "failover active" | yes | yes |
| Alerts on failover, failback, both tunnels down (kill switch tripped), and bypass start/end | yes (toast, sender "Cybervulcan") | yes, while the app is running |
| PC mode: this PC on VPN or CLEAR via `PCMODE_CLEAR` | yes | n/a |
| Whole-house VPN bypass toggle via `BYPASS_ALL`, with auto-expiry and a countdown | yes | yes (app, widget, QS tile) |
| Who's online: DHCP leases grouped by network | yes | yes |
| Kill switch: armed / tripped | yes | yes |
| Quick tests: exit IP and country, DNS resolver check | yes | yes |

Tray / status colours:

| Colour | Meaning |
|---|---|
| green | Main tunnel (San Jose) up, kill switch armed |
| amber | Failover active (LA backup in use), latency or loss on the active tunnel, or a change is in progress |
| red | Router unreachable, API error, kill switch rule missing, or both tunnels down (kill switch tripped) |
| purple | Whole-house VPN bypass is active |
| grey | Not set up yet |

## Router assumptions

The defaults match this house. Everything can be changed in Settings.

| Thing | Default |
|---|---|
| Router API | `https://10.10.10.254` (or `http://` during the VM phase) |
| Networks | MGMT 10.10.10.0/24, CLEAR (VLAN20) 10.10.20.0/24, VPN (VLAN40) 10.10.40.0/24, IOT (VLAN50) 10.10.50.0/24 |
| Gateways | `WG_MAIN_GW` (US-CA#446 San Jose, monitor 1.0.0.1) and `WG_BACKUP_GW` (US-CA#1077 Los Angeles, monitor 8.8.4.4) in group `PROTON_FAILOVER` |
| Runtime aliases (type *External (advanced)*, empty after reboot) | `PCMODE_CLEAR` (PC goes direct), `BYPASS_ALL` (whole VPN network goes direct; NAT rules send its DNS to the router's Quad9 DoT resolver) |
| Kill switch | WAN outbound block rule matching tag `NO_WAN_EGRESS` |

Because both aliases are runtime-only (pf tables), a router reboot always drops
back to VPN-only. That is the safe failure mode.

## OPNsense API privileges for the `pcmode` user

These privilege names were checked against the `ACL.xml` files in
[opnsense/core](https://github.com/opnsense/core) (master, 26.x). Set them in
**System > Access > Users > pcmode > Effective Privileges**.

| Feature | Endpoint(s) used | Privilege (GUI name) | ACL id | Status for `pcmode` today |
|---|---|---|---|---|
| Bypass toggle + expiry, PC mode | `GET /api/firewall/alias_util/list/{alias}`, `POST .../add/{alias}`, `POST .../delete/{alias}`, `POST .../flush/{alias}` | **Diagnostics: PF Table IP addresses** | `page-diagnostics-tables` | Has it (shown to you as "Diagnostics: pf Tables") |
| Reset existing connections on every mode change (PC VPN/CLEAR, bypass on/off, bypass auto-expiry) | `POST /api/diagnostics/firewall/kill_states` `{"filter": ...}` | **Diagnostics: Show States** | `page-diagnostics-showstates` | Has it |
| Live status, failover, kill switch *tripped*, alerts | `GET /api/routes/gateway/status` | **System: Gateways** | `page-system-gateways` | **Must add (required)** |
| Who's online | `GET /api/dnsmasq/leases/search` | **Services: Dnsmasq DNS/DHCP: Settings** | `page-services-dnsforwarder` | Add (optional) |
| Kill switch *armed* (preferred) | `POST /api/firewall/filter/search_rule?show_all=1` | **Firewall: Rules [new]** | `page-filter-api` | Add (optional) |
| Kill switch *armed* (alternative) | `GET /api/firewall/filter_util/rule_stats` plus the rule UUID set in Settings | **Firewall: Rules** | `page-firewall-rules` | Add (optional, instead of the row above) |

**Firewall: Alias: Edit is not needed and can be removed.** Cybervulcan never
calls `/api/firewall/alias/*`. It changes `PCMODE_CLEAR` and `BYPASS_ALL`
**only** through the runtime `/api/firewall/alias_util/*` endpoints, so no
saved configuration is ever written. A unit test checks that no
`/api/firewall/alias/` request is made.

**Trade-offs, honestly stated.** OPNsense has no read-only variants of these
pages. Each privilege covers its whole API namespace:

* *System: Gateways* also covers `api/routing/settings/*`, which can edit gateways.
* *Services: Dnsmasq DNS/DHCP: Settings* covers all of `api/dnsmasq/*`, which can change DHCP/DNS settings.
* *Firewall: Rules [new]* covers `api/firewall/filter/*`, which can edit rules.

Apart from `alias_util` and `kill_states`, the app only calls the read endpoints listed above. If you'd rather not
grant the optional privileges, the matching feature shows "unknown" and
nothing else breaks. The minimum for a useful app is **PF Table IP
addresses** plus **System: Gateways**.

Version notes:

* The `alias_util` endpoints are the same in 25.x and 26.x. `list` returns `{rows:[{ip}]}` (the client also accepts the older `items` shape).
* `dnsmasq/leases/search` exists since Dnsmasq DHCP arrived in 25.1.
* In 26.x, `search_rule` returns legacy rules as well as MVC rules. On 25.x a kill switch rule created in the legacy GUI may not be found. In that case use the *rule UUID + Firewall: Rules* option.

## First run

1. Install the app (see Releases, or build it yourself below).
2. Enter the router base URL plus the `pcmode` API key and secret. The key is the "key" field of the downloaded `apikey.txt` and the secret is the "secret" field. They go straight into OS secure storage:
   * Windows Credential Manager (DPAPI) through `flutter_secure_storage`
   * Android Keystore-backed storage

   They are never written to settings files or logs, and never sent anywhere except the configured router URL.
3. **HTTPS with a self-signed certificate:** press **Trust certificate...**.
   * The app connects without sending anything, shows the certificate's SHA-256 fingerprint, and asks you to confirm.
   * Check the fingerprint against *System > Trust > Certificates* on the router (or your browser's certificate viewer).
   * After you confirm, only that exact certificate (or a normal CA-valid one) is accepted. If the router certificate changes, the app shows "certificate not trusted" until you trust the new one.
4. Press **Test connection & privileges**. It calls every endpoint and reports `OK` or `NO PRIVILEGE` for each one.
5. **Save.** On Windows, the window then closes to the tray. Right-click the tray icon for quick actions.

## Whole-house bypass: how expiry is enforced

* **On** adds the VPN network (`10.10.40.0/24`) to `BYPASS_ALL`. **Off** flushes the table. If flush isn't permitted, the app deletes the entries one by one.
* Turning it on always shows a warning first, because it affects **everyone on the VPN network**. The widget and the Quick Settings tile open this dialog instead of switching on silently. Turning bypass *off* from the widget or tile is instant.
* The deadline (default 2 h, adjustable per use and in Settings) is stored in two places:
  * locally on the device, and
  * by default, **on the router** as an extra entry in `BYPASS_ALL`: `240.0.0.0/4` plus the expiry in epoch minutes (for example `241.195.x.y`). This range is reserved and never appears on the LAN, so the entry matches nothing. It means the PC and the phone both see and enforce the same deadline. It disappears with the table on reboot. You can turn this off in Settings.
* Every poll (default every 15 s) and every app start checks the deadline. If it passed while the app was closed, bypass is switched off straight away.
* If bypass was switched on elsewhere (for example in the GUI) without a deadline, the app gives it one (now + the default duration).

Limitation: if *no* Cybervulcan instance is running, nothing switches bypass off
at the deadline. The router has no timer for runtime tables. A router reboot
also clears it.

## Connection reset on mode changes

pf keeps existing connections on the path they started on. After every mode
change the app calls `kill_states` so open connections re-establish on the
new path:

| Change | States dropped (filter sent) |
|---|---|
| PC VPN <-> CLEAR | the PC's IP, e.g. `10.10.40.50` (exact address match) |
| Bypass on / off / auto-expiry (any device, including the widget and tile) | the VPN network, e.g. `10.10.40.` |

Things to know (checked against opnsense/core):

* The router sanitises `filter` to `[0-9A-Za-z ,*._#-]`, so a CIDR like `10.10.40.0/24` can't be sent. For a subnet the app sends the octet prefix (`10.10.40.`). That is a text match, so it can also drop states for, say, `110.10.40.x`. Those connections simply reconnect.
* A bypass change resets connections for everyone on the VPN network, including a PC that's in CLEAR mode.
* The device making the change is usually inside the affected range, so the state for its own API request is dropped too and the reply can be lost. The app treats a lost reply as success. It opens a fresh connection for every API call (no keep-alive), so later calls aren't affected.
* If the privilege is missing, the mode change still happens and the app shows a warning that existing connections weren't reset.

## Quick tests: what they can and can't tell you

* **Exit IP** comes from `api.ipify.org`. The country and organisation come from `ipwho.is`, with `ipapi.co` as a fallback.
  * The country is compared with what the router state says this device *should* do. VPN means the exit is in the VPN exit country (default US). Direct means the exit is in your home country (default AU).
  * The verdict is OK, MISMATCH (a possible leak, or still on VPN) or inconclusive.
* **DNS resolver**: the app looks up a random, never-cached subdomain of `edns.ip-api.com` (plain HTTP only), which reports the recursive resolver that queried it.
  * On the VPN you'd expect a Proton resolver.
  * During bypass you'd expect Quad9 (the router's DoT forwarder).
  * An ISP resolver while on the VPN suggests a DNS leak.
* Limitations:
  * It's a single lookup, not a full multi-query leak test.
  * The country check is a heuristic. A Proton server in your home country would look "direct".
  * On a phone using mobile data, the result is inconclusive.
  * The tests rely on those third-party services being reachable.

## Building

GitHub Actions (`.github/workflows/build.yml`) does everything:

* **Push or PR to `main`:** `flutter analyze` and `flutter test`.
* **Tag `vX.Y.Z` or *Run workflow*:**
  * Windows: `flutter build windows`, then bundle the VC++ runtime DLLs, then Inno Setup produces `Cybervulcan-Setup-X.Y.Z.exe`.
  * Android: `flutter build apk --release` produces `Cybervulcan-X.Y.Z.apk`.
  * Both are uploaded as workflow artifacts. A tag also creates a GitHub Release with both files attached.

```sh
git tag v1.0.0 && git push origin v1.0.0
```

Flutter is pinned to **3.47.9** (stable). The `android/` and `windows/` folders
were rendered from that release's `flutter create` templates.

Locally (Flutter 3.47+):

```sh
flutter pub get
flutter analyze && flutter test
flutter build windows --release          # on Windows
flutter build apk --release              # anywhere with the Android SDK + JDK 17
iscc /DAppVersion=1.0.0 installer\cybervulcan.iss   # Inno Setup 6
python3 tool/make_icons.py               # regenerate icons (needs rsvg-convert + Pillow)
```

### Android signing

By default the release APK is signed with the **debug key**. It installs fine
by sideloading, but every CI run uses a different debug key, so you can't
update over the top: uninstall first. For stable updates, add these repository
secrets and CI signs with your key:

| Secret | Value |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | `base64 -w0 upload-keystore.jks` |
| `ANDROID_KEYSTORE_PASSWORD` | keystore password |
| `ANDROID_KEY_ALIAS` | key alias (e.g. `upload`) |
| `ANDROID_KEY_PASSWORD` | key password (optional, defaults to the keystore password) |

Create a keystore with:

```sh
keytool -genkey -v -keystore upload-keystore.jks -keyalg RSA -keysize 4096 -validity 10000 -alias upload
```

Never commit it. `*.jks` and `key.properties` are git-ignored.

## Windows details

* Installs per user (no admin) to `%LOCALAPPDATA%\Programs\Cybervulcan`.
* Optional autostart: `HKCU\...\Run`, starts hidden in the tray with `--minimized`.
* Single instance: launching it again brings the existing window to the front.
* Toast sender: the Start-menu shortcut carries AppUserModelID `Cybervulcan.OPNsenseCybervulcan`, and `HKCU\Software\Classes\AppUserModelId\...` has `DisplayName=Cybervulcan`.
* Closing the window hides it to the tray. Use **Quit** in the tray menu to exit.
* Uninstalling leaves the API key in Credential Manager. Use *Settings > Forget stored API key* first if you want it gone.

## Android details

* **Widget:** shows the current exit and status dot, a bypass button (ON opens the confirmation dialog; OFF happens in the background), and refresh.
* **Quick Settings tile "VPN bypass":** active while bypass is on. Tapping it turns bypass off, or opens the confirmation dialog to turn it on.
* Alerts are raised while the app process is running. True background monitoring (a foreground service) is not in v1. The widget refreshes when the app runs, when you tap refresh, and every 30 minutes.
* `usesCleartextTraffic` is enabled for the `http://` router (VM phase) and for the HTTP-only DNS test. Use `https://` with a pinned certificate for the router as soon as it has one.

## Project layout

```
lib/
  main.dart                      platform bootstrap (tray / widget bridge / notifications)
  src/api/                       OPNsense client, models, TLS pinning helpers
  src/core/                      config, house state, alerts diff, bypass/expiry, PC mode, quick tests, controller
  src/platform/                  tray (Windows), notifications, Android widget/tile bridge
  src/ui/                        Material 3 UI (dark/light), OPn logo painter
android/app/src/main/kotlin/...  ExitWidgetProvider (home_widget), BypassTileService (TileService)
windows/runner/                  Flutter runner (hidden start, single instance)
installer/cybervulcan.iss        Inno Setup script
tool/make_icons.py               icon generator (tray .ico in 5 colours, app .ico, Android PNGs)
test/                            unit tests (client against a fake router, state, alerts, bypass expiry)
```
