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
4. [Dynamic DNS for the home address (os-ddclient)](#4-dynamic-dns-os-ddclient)
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

* Username: one per person, e.g. `alex-app`, `sam-app`.
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
| Services: Unbound DNS: Settings | Tests page: router DNS-over-TLS / DNSSEC check | optional (v2.0) |
| VPN: WireGuard | Server switcher, tunnel handshakes on the Tests page | **admin only** (v2.0) - see below |

**VPN: WireGuard is admin-level too.** It lets the key change the tunnels
and, through the API, read the WireGuard private keys of the Proton tunnels.
Cybervulcan only ever sends a peer's server address, port and the server's
*public* key, and ignores the key fields it receives - but the privilege is
that coarse. Give it to your own key only and turn on the app lock
(Settings > Security & privacy).

**Firewall: Rules [new] is admin-level.** OPNsense has no read-only version:
the same privilege lets the key create, change and delete firewall rules
through the API. Only give it to your own key. Without it the app shows the
kill switch as "armed state unknown"; everything else works (the "tripped"
state still comes from the gateways).

The same applies, less dramatically, to *System: Gateways* (also covers
editing gateways) and *Services: Dnsmasq DNS/DHCP: Settings* (also covers
changing DHCP/DNS). Cybervulcan itself only reads those endpoints; the
privileges are simply that coarse.

**Restricted key for a partner / family member:**
PF Table IP addresses + System: Gateways + Diagnostics: Show States
(+ Dnsmasq if she wants the Devices page). **No** Firewall: Rules [new],
**no** VPN: WireGuard.

Create the key: edit the user > **API keys > +**. The browser downloads
`apikey.txt` with a `key=` and a `secret=` line. Send it to the person over a
private channel (or type it in on their device yourself) and delete the file.
The app stores it in Windows Credential Manager / the Android Keystore and
sends it only to the router, and only after the certificate check passed.

Cybervulcan never needs *Firewall: Alias: Edit*: it only touches the runtime
alias tables through `/api/firewall/alias_util/*`.

## 2. HTTPS certificate (Let's Encrypt)

The app connects to the router **by IP** (`10.10.10.254`) but checks the
certificate against a **name** (default `router.example.com`). If the
certificate is not valid for that name - e.g. on a café network where some
other box uses `10.10.10.254` - the app says "Wrong certificate - not your
router" and stops before sending the API key. This needs a certificate from
a public CA; Let's Encrypt via DNS-01 works without opening any port.

1. **System > Firmware > Plugins**: install `os-acme-client`.
2. **Services > ACME Client > Settings**: enable.
3. **Accounts**: add a Let's Encrypt (production) account with your e-mail.
4. **Challenge Types**: add a **DNS-01** challenge with your DNS provider's
   API. DNS-01 never needs the GUI to be reachable from the internet. Any
   provider that acme.sh supports works; the example here is
   [deSEC](https://desec.io) (free, has a proper API and per-record tokens):
   * deSEC web UI > **Token management > +**: a new token just for
     certificates. Under the token's **policies** (RRset policies) add a
     default policy with no write permission, then one policy that allows
     writing only type `TXT`, subname `_acme-challenge` (and
     `_acme-challenge.router` if you issue `router.example.com` instead
     of the wildcard), domain `example.com`. The token can then create
     the validation records and nothing else - it cannot change your MX,
     SPF/DKIM/DMARC or the `home` address record.
   * OPNsense: DNS Service **deSEC.io (dns_desec)**, paste the token.
5. **Certificates > +**: Common name `*.example.com` (or just
   `router.example.com`), alt names as needed, account + challenge from
   above, auto-renew on. Issue it.
6. **System > Settings > Administration**:
   * Protocol: HTTPS, SSL certificate: the ACME certificate.
   * **Alternate Hostnames**: add `router.example.com` (the app sends
     that name as the HTTP Host header; without it the GUI's DNS-rebind
     check can refuse requests).
   * Optional: restrict "Listen interfaces" to LAN/MGMT (and the WireGuard
     road-warrior interface for remote access).
7. You do not need a public DNS record for `router.example.com`: the
   app never looks it up, it connects to the IP.

Renewals are automatic and need no change in the app (it checks the name and
the CA chain, not the exact certificate). Do **not** pin (SHA-256) a
Let's Encrypt certificate in the app: it changes every renewal. Pinning is
only for self-signed certificates.

Existing v1.0 users on `http://10.10.10.254` keep working (with a warning)
until you switch them to `https://` with the certificate name.

Upgrading users from v1.0.x: their app shows "The router address is plain
http://" with a **Switch to HTTPS** button. It changes the address to
`https://<same IP>` and sets the certificate name to `router.example.com`
(when none is set). Nothing else in their settings changes.

## 3. Road-warrior WireGuard (remote access)

Remote access lets the app reach the router API from anywhere. The app runs
its own WireGuard client **inside the app** (user space): it does not use
Android's VPN slot, so the Proton VPN app can stay on, and nothing else on
the device goes through it.

Values used in this guide (change them to suit; the app's defaults are the
endpoint, port, allowed IPs and keepalive below):

| | |
|---|---|
| Instance name | `RW` (road warrior) |
| Listen port | **UDP 51830** (51820/51821 are the Proton client tunnels) |
| Tunnel network | `10.10.99.0/24`, router = `10.10.99.1/24` |
| App peers | `10.10.99.x/32`, one per device |
| Router address reached through the tunnel | `10.10.10.254` TCP 443 only (app setting "Allowed IPs" = `10.10.10.254/32`) |
| Keepalive | 25 s |
| Router public key | yours - generated in the next step. Example of the format: `8VtOYZP9yUPtMsYK5pYRBl2b5AwkS1oM7G6tuYNXhvM=` (it is not secret, but it is different on every router; the app has no default for it) |
| Endpoint name | `home.example.com`, port `51830` (see step 4) |

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
  2. pass TCP/UDP from `RW net` to `10.10.99.1` port `53` - router DNS (the
     app itself does not use it; it keeps other WireGuard clients on the same
     instance working and costs nothing).
  3. nothing else (the default deny blocks the rest). In particular no
     access to the house networks, no other router ports and no internet
     through the tunnel.
* 51820 and 51821 belong to the Proton client tunnels (outbound); do not
  reuse them for the road-warrior instance.

### Per user / device

1. The user installs the app and, in **Settings > Remote access** (or the
   setup wizard), presses **Generate key** and sends you the **public key**
   (Copy or QR). The private key never leaves their device.
2. **VPN > WireGuard > Peers > +**: name e.g. `sam-phone`, public key = the
   one they sent, **Allowed IPs = their own `/32`** (e.g. `10.10.99.3/32`),
   optional pre-shared key (generate one; give it to them privately), no
   endpoint, instance `RW`. Save, Apply.
3. Tell them: tunnel address `10.10.99.3/32`, router public key, endpoint
   `home.example.com`, port `51830` - or just send them the settings
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

## 3b. Tailscale (remote access behind CGNAT) - v2.0, built-in from v2.1

WireGuard (section 3) needs the router to be reachable from the internet.
Behind CGNAT - for example a 5G hotspot - nothing can connect in. Tailscale
connects outwards from both ends and works anyway.

**Router (once)**

1. System > Firmware > Plugins: install **os-tailscale**.
2. VPN > Tailscale > Settings: enable, set **Advertise routes** to
   `10.10.10.254/32` (just the router), Apply, then log in with the link it
   shows (your Tailscale account).
3. In the Tailscale admin console: approve the subnet route; disable key
   expiry for the router.
4. Interfaces > Assignments: assign the `tailscale0` interface (e.g. `TS`)
   and allow on it only TCP to `10.10.10.254:443` (and DNS to the router if
   wanted) - the same "router only" rule as the road-warrior interface.
5. If System > Settings > Administration has restricted *Listen
   interfaces*, add the Tailscale interface.

**Each device - built-in Tailscale (v2.1, recommended)**: no Tailscale app
needed. The app runs its own Tailscale node in user space (no VPN slot on
Android, no admin rights on Windows), only for the app's own connection to
the router - the Proton app on the phone can stay on.

1. Cybervulcan: Settings > Remote access: switch it on, engine **Tailscale**
   (or **Auto**: WireGuard first, Tailscale when WireGuard can't get in within
   a few seconds), keep **Built-in Tailscale** on, Save.
2. Tap **Sign in to Tailscale**. A browser opens: log in with the account
   of the tailnet the router is in. No auth key is typed into the app. This
   works at home too - sign in before you leave.
3. Admin console > Machines: the device shows up as `cybervulcan-<pc name>`
   or `cybervulcan-android` (Tailscale adds `-1`, `-2` for more phones). If
   the tailnet uses *device approval*, approve it (Settings shows "waiting
   for approval" until then). The app saves the login in its private folder;
   later starts are silent.
4. **Key expiry**: Tailscale device keys expire (180 days by default).
   Settings shows the date and warns 14 days ahead. Either sign in again
   then, or in the admin console use *Disable key expiry* on the device
   (fine for a device you control; then remove it promptly if it is lost).
5. **Sign out** in Settings forgets the login on the device (and expires
   its key when the engine is running). Also remove the machine in the admin
   console - always do that for a lost phone (section 8).

The app reaches the router at its LAN IP through the subnet route from
step 2 above (or at the address in "Router's Tailscale address" if set). The
route must be approved, otherwise Settings says "router not visible". The
built-in node does not upload logs to Tailscale, offers no services to the
tailnet and is not an exit node. The certificate is still checked
against `router.example.com`, so a wrong path can't see the API key.

**Each device - Tailscale app (as in v2.0)**: turn **Built-in Tailscale**
off, install Tailscale, sign in to the same tailnet. With the subnet route
the normal router URL works unchanged; otherwise enter the router's
`100.x.y.z` (or MagicDNS name) as "Router's Tailscale address". The
certificate is still checked against `router.example.com`.

Android runs one VPN app at a time: with the Tailscale *app* on, the Proton
app on the phone is off. To keep the house VPN while away, set the router as
the phone's Tailscale *exit node*. (Built-in Tailscale doesn't have this
limit.)

## 4. Dynamic DNS (os-ddclient)

`home.example.com` (the WireGuard endpoint) must point at the house's
current WAN address. OPNsense's own **os-ddclient** plugin does this; no
extra scripts. Any provider os-ddclient supports works; the example is
deSEC, with a token that may change **only that one name**.

1. deSEC web UI: create the record once (**Domains > example.com > +**:
   subname `home`, type `A`, any address; add `AAAA` too if the WAN has
   public IPv6).
2. **Token management > +**: a new token just for DDNS. Policies: a default
   policy with no write permission, then policies that allow writing
   subname `home`, type `A` and subname `home`, type `AAAA`, domain
   `example.com`. Nothing else - this token cannot touch MX, SPF/DKIM/
   DMARC, `_acme-challenge` or any other record. (Use a separate token from
   the certificate one in step 2.)
3. OPNsense: **System > Firmware > Plugins**: install `os-ddclient`.
4. **Services > Dynamic DNS > Settings**: enable. **Accounts > +**:
   * Service: **desec-v4** (and a second account with **desec-v6** for
     IPv6, if you publish `AAAA`).
   * Username: the hostname, `home.example.com`.
   * Password: the DDNS token from step 2.
   * Hostname(s): `home.example.com`.
   * Check ip method: **Interface** with interface **WAN** (the router's own
     traffic may leave through a VPN gateway, so a web check-IP service
     could report the Proton address).
   * Save, Apply.
5. Check: **Services > Dynamic DNS > Log File**, and from outside:
   `nslookup home.example.com` shows the WAN address.

If home ever goes behind CGNAT again (WAN address in `100.64.0.0/10` or
another private range), inbound WireGuard cannot work whatever DNS says.

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
* **Tailscale admin console > Machines**: remove the device
  (`cybervulcan-...` for built-in Tailscale, or its Tailscale app).

Nobody else is affected.
