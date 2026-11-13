# Cybervulcan - router admin setup

This is for whoever runs the OPNsense router. It covers everything the router
needs so that one or more people can use the Cybervulcan app (Windows tray
app / Android app), at home and away. The values in `code` are this
project's defaults; use your own names if they differ and change them in the
app's Settings (or in the settings you hand out, see step 7).

Contents

1. [API user per person (minimum privileges)](#1-api-user-per-person)
2. [HTTPS certificate (Let's Encrypt) and the certificate name](#2-https-certificate-lets-encrypt)
3. [Road-warrior WireGuard for remote access](#3-road-warrior-wireguard-remote-access)
4. [Dynamic DNS for the home address (GoDaddy)](#4-dynamic-dns-godaddy)
5. [Router-side bypass timer](#5-router-side-bypass-timer)
6. [Aliases, rules and kill switch (once)](#6-aliases-rules-and-kill-switch)
7. [Hand the settings to a new user](#7-hand-the-settings-to-a-new-user)
8. [Removing a user or a lost phone](#8-removing-a-user-or-a-lost-phone)

---

## 1. API user per person

Give **every person (or device) their own API user and key**. A lost phone
can then be cut off without touching anyone else, and the log shows who did
what.

**System > Access > Users > +**

* Username: e.g. `pcmode` (Tim's PC), `tim-phone`, `kate`.
* Password: a long random one (nobody logs in to the GUI with it).
* Login shell: none. Do not add the user to the `admins` group.
* Save, then edit the user again and set **Effective Privileges**:

| Privilege (GUI name) | Needed for | Give it to |
|---|---|---|
| **Diagnostics: PF Table IP addresses** | Whole-house bypass on/off + expiry, PC mode | everyone (required) |
| **System: Gateways** | Live status, failover, alerts | everyone (required) |
| **Diagnostics: Show States** | Moves open connections after a switch | everyone (recommended) |
| Services: Dnsmasq DNS/DHCP: Settings | "Devices" page (who's online) | optional |
| Firewall: Rules [new] | Kill switch "armed" check | **admin only** - see below |
| Firewall: Rules (+ rule UUID in Settings) | Alternative kill switch check | optional |

**Firewall: Rules [new] is admin-level.** OPNsense has no read-only version:
the same privilege lets the key create, change and delete firewall rules
through the API. Only give it to your own key. Without it the app shows the
kill switch as "armed state unknown"; everything else works (the "tripped"
state still comes from the gateways).

The same applies, less dramatically, to *System: Gateways* (also covers
editing gateways) and *Services: Dnsmasq DNS/DHCP: Settings* (also covers
changing DHCP/DNS). Cybervulcan itself only reads those endpoints; the
privileges are simply that coarse.

**Restricted key for a partner / family member (e.g. Kate):**
PF Table IP addresses + System: Gateways + Diagnostics: Show States
(+ Dnsmasq if she wants the Devices page). **No** Firewall: Rules [new].

Create the key: edit the user > **API keys > +**. The browser downloads
`apikey.txt` with a `key=` and a `secret=` line. Send it to the person over a
private channel (or type it in on their device yourself) and delete the file.
The app stores it in Windows Credential Manager / the Android Keystore and
sends it only to the router, and only after the certificate check passed.

Cybervulcan never needs *Firewall: Alias: Edit*: it only touches the runtime
alias tables through `/api/firewall/alias_util/*`.

## 2. HTTPS certificate (Let's Encrypt)

The app connects to the router **by IP** (`10.10.10.254`) but checks the
certificate against a **name** (default `router.cybervulcan.com`). If the
certificate is not valid for that name - e.g. on a café network where some
other box uses `10.10.10.254` - the app says "Wrong certificate - not your
router" and stops before sending the API key. This needs a certificate from
a public CA; Let's Encrypt via DNS-01 works without opening any port.

1. **System > Firmware > Plugins**: install `os-acme-client`.
2. **Services > ACME Client > Settings**: enable.
3. **Accounts**: add a Let's Encrypt (production) account with your e-mail.
4. **Challenge Types**: add a **DNS-01** challenge with your DNS provider's
   API (for GoDaddy: DNS Service "GoDaddy", API key + secret). DNS-01 never
   needs the GUI to be reachable from the internet.
5. **Certificates > +**: Common name `*.cybervulcan.com` (or just
   `router.cybervulcan.com`), alt names as needed, account + challenge from
   above, auto-renew on. Issue it.
6. **System > Settings > Administration**:
   * Protocol: HTTPS, SSL certificate: the ACME certificate.
   * **Alternate Hostnames**: add `router.cybervulcan.com` (the app sends
     that name as the HTTP Host header; without it the GUI's DNS-rebind
     check can refuse requests).
   * Optional: restrict "Listen interfaces" to LAN/MGMT (and the WireGuard
     road-warrior interface for remote access).
7. You do not need a public DNS record for `router.cybervulcan.com`: the
   app never looks it up, it connects to the IP.

Renewals are automatic and need no change in the app (it checks the name and
the CA chain, not the exact certificate). Do **not** pin (SHA-256) a
Let's Encrypt certificate in the app: it changes every renewal. Pinning is
only for self-signed certificates.

Existing v1.0 users on `http://10.10.10.254` keep working (with a warning)
until you switch them to `https://` with the certificate name.

## 3. Road-warrior WireGuard (remote access)

Remote access lets the app reach the router API from anywhere. The app runs
its own WireGuard client **inside the app** (user space): it does not use
Android's VPN slot, so the Proton VPN app can stay on, and nothing else on
the device goes through it.

Values for this house:

| | |
|---|---|
| Instance name | `RW` (road warrior) |
| Listen port | **UDP 51830** (51820/51821 are the Proton client tunnels) |
| Tunnel network | `10.10.99.0/24`, router = `10.10.99.1/24` |
| App peers | `10.10.99.x/32`, one per device |
| Router public key (this house) | `rspBoRaiXUvobDZA8aQ6EmnafqEBJ9WHETHpZMa3iSk=` |
| Endpoint name | `home.cybervulcan.com` (see step 4) |

### Instance (once)

**VPN > WireGuard > Instances > +**: name `RW`, generate a keypair, listen
port `51830`, tunnel address `10.10.99.1/24`. Leave "Disable routes" off.
Save, enable WireGuard, Apply. Copy the instance's **public key** (the users
need it; it is not secret).

**Interfaces > Assignments**: assign the `wg` device of `RW` (e.g. `RW`),
enable it, no IP configuration (WireGuard sets it).

### Firewall (once)

* **Firewall > Rules > WAN**: pass, protocol UDP, destination "This
  Firewall", port `51830`. Nothing else is opened.
* **Firewall > Rules > RW** (the new interface), in this order:
  1. pass TCP from `RW net` to `10.10.10.254` port `443` - the router API/GUI.
  2. optional: pass TCP/UDP from `RW net` to `10.10.99.1` port `53` (router
     DNS; the app does not need it, other WireGuard clients might).
  3. nothing else (the default deny blocks the rest). In particular no
     access to the house networks and no internet through the tunnel.

### Per user / device

1. The user installs the app and, in **Settings > Remote access** (or the
   setup wizard), presses **Generate key** and sends you the **public key**
   (Copy or QR). The private key never leaves their device.
2. **VPN > WireGuard > Peers > +**: name e.g. `kate-phone`, public key = the
   one they sent, **Allowed IPs = their own `/32`** (e.g. `10.10.99.3/32`),
   optional pre-shared key (generate one; give it to them privately), no
   endpoint, instance `RW`. Save, Apply.
3. Tell them: tunnel address `10.10.99.3/32`, router public key, endpoint
   `home.cybervulcan.com`, port `51830` - or just send them the settings
   export (step 7), which carries all of that.

Alternative: create the peer with "generate keypair" on the router and hand
the user the resulting wg-quick `.conf` (text or QR) - the app's **Import a
WireGuard .conf** reads it and moves the private key straight into secure
storage. This means the private key existed on the router and in transit, so
the app-generated key above is preferred.

The app only uses the tunnel when the router does not answer directly within
~2 s, and stops it when back home, in the background (Android) or after
3 minutes unused. If home is behind CGNAT (no public IPv4 on WAN), inbound
WireGuard cannot work; see the CGNAT notes in the project docs.

## 4. Dynamic DNS (GoDaddy)

`home.cybervulcan.com` must point at the house's current WAN address.
OPNsense's `os-ddclient` has no GoDaddy service, so this repo ships a small
updater: `router/install-ddns.sh`.

What it does: every 5 minutes it works out the WAN IPv4 (from the WAN
interface; if that is a private/CGNAT address, from `api.ipify.org`) and
optionally the WAN IPv6, reads the current GoDaddy `A`/`AAAA` record of that
**one name** (`GET /v1/domains/cybervulcan.com/records/A/home`) and only when
it differs replaces it (`PUT` of that same type + name). **It never touches
any other record** - the Proton Mail MX, SPF, DKIM and DMARC records of
`cybervulcan.com` are left exactly as they are. Everything is logged with
tag `cybervulcan-ddns`.

1. GoDaddy: create a **production** API key at
   https://developer.godaddy.com/keys. (GoDaddy limits API access for small
   accounts; if every update fails with HTTP 403 "ACCESS_DENIED", the
   account does not qualify and you need another DNS host, e.g. moving DNS
   to Cloudflare, which os-ddclient supports.)
2. Router shell (console option 8, or SSH) as root:
   ```sh
   fetch -qo /tmp/install-ddns.sh https://raw.githubusercontent.com/G0taW00dy/OPNsense-Cybervulcan/main/router/install-ddns.sh
   sh /tmp/install-ddns.sh
   ```
   It asks for the key and secret (typing is not shown), the WAN interface
   (default: the one with the default route) and whether to publish IPv6.
   They are stored in `/usr/local/etc/cybervulcan-ddns.conf`, owned by root,
   mode 0600; the updater refuses to run if that file is readable by anyone
   else. The key is never put on a command line or in a log.
   (Download first, then run: piping into `sh` would not let it ask.)
3. Test: `configctl cybervulcan_ddns update home.cybervulcan.com`, then
   `grep cybervulcan-ddns /var/log/system/latest.log`.
4. **System > Settings > Cron > +**: Minutes `*/5`, the rest `*`, Command
   **"Cybervulcan - update GoDaddy DNS"**, Parameters `home.cybervulcan.com`.
   Save, Apply.

Remove: `sh /tmp/install-ddns.sh uninstall` (also deletes the stored key),
then delete the cron job. Re-run the installer after restoring a backup onto
new hardware (the files are not part of the config backup).

Note: the router's own traffic must leave via WAN (not a VPN gateway) for
the check-IP fallback to see the house's address; with the interface address
(the normal case) this does not matter.

## 5. Router-side bypass timer

Ends an expired whole-house bypass even when no app is running (PC off,
phones away). Without it, only a running app ends the bypass.

```sh
fetch -qo - https://raw.githubusercontent.com/G0taW00dy/OPNsense-Cybervulcan/main/router/install.sh | sh
```

Then **System > Settings > Cron > +**: every field `*`, Command
**"Cybervulcan - end expired whole-house VPN bypass"**, Parameters
`BYPASS_ALL`. Save, Apply.

The timer reads the deadline the app stores **on the router** (a `240.x.x.x`
marker entry in `BYPASS_ALL`). Keep **Settings > "Store bypass deadline on
the router"** switched **on** in every app: on 12 Nov a test bypass did not
end on time because that setting had been switched off. v1.1 warns about it
in Settings, warns on the Status page when a running bypass has no router
deadline ("the router can't end this bypass by itself") and offers
**Add deadline**.

## 6. Aliases, rules and kill switch

Unchanged from v1.0 - see the in-app Setup guide (sections 1-3) or the
README: `BYPASS_ALL` and `PCMODE_CLEAR` as *External (advanced)* aliases,
pass rules with those sources via the WAN gateway above the VPN rule, local
tag `NO_WAN_EGRESS` on the VPN pass rule and a WAN block rule on that tag.

## 7. Hand the settings to a new user

On your own (working) app: **Settings > Share settings > Export...** -
Copy, QR, or Save file (Windows). Before exporting, fill in the new user's
**tunnel address** (e.g. `10.10.99.3/32`) in Remote access if you want it
included, then set your own back (or export from a scratch install).

The export contains router address, certificate name, gateway/alias names,
labels, networks, country codes, poll interval, remote-access endpoint/port/
router public key/allowed IPs/keepalive. It **never** contains the API key or
secret, any WireGuard private or pre-shared key, or device-only settings
(this PC's IP, notification choices). An import also ignores anything that
looks like a secret.

The new user: install the app > first-run setup > **Load settings from
admin** > enter their own API key + secret > test > Remote access:
**Generate key** and send you the public key > Save. See
[USER-SETUP.md](USER-SETUP.md).

## 8. Removing a user or a lost phone

* **System > Access > Users > (user) > API keys**: delete the key (or the
  whole user).
* **VPN > WireGuard > Peers**: delete (or disable) their peer, Apply.

Nobody else is affected.
