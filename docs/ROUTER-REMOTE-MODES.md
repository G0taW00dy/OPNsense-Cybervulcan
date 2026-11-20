# Router setup for the remote access modes (v2.1)

The app's remote access has three modes (Settings > Remote access > "What it carries"):

| Mode | What goes through the link | Device VPN slot | Router work needed |
|---|---|---|---|
| **App only** (default) | Only the app's own connection to the router | Not used | Section 1 (already done if remote access works today) |
| **Home devices only** | The app + the home devices you list (e.g. the NAS) | Used | Sections 1 + 2 |
| **Everything via home** | All of the device's traffic, out through the house's VPN tunnels | Used | Sections 1 + 2 + 3 |

Engines: **WireGuard** (needs a public address - not behind CGNAT), **Tailscale** (works behind CGNAT, e.g. a
5G hotspot) or **Auto** (WireGuard first, then Tailscale). The rules below are written for the Tailscale
interface; for WireGuard use the road-warrior WireGuard interface instead - the rules are the same.

Placeholders: `<ROUTER_LAN_IP>` (e.g. 10.10.10.254), `<NAS_IP>`, `<VPN_GW_GROUP>` (the gateway group with the
main and backup tunnels), `<KILL_TAG>` (the kill switch tag, e.g. NO_WAN_EGRESS).

## 0. Privileges for the app user (optional features)

On **your** app user only (System > Access > Users > edit > Effective privileges), never on keys for others:

| Privilege | Used for |
|---|---|
| VPN: WireGuard: Configuration + Status | Server switcher (can also read WireGuard keys - keep the app lock on) |
| System: Static Routes | Re-apply the gateway monitor's route after a server switch |
| Status: Services | Restart the gateway monitor after a server switch |
| Firewall: Shaper | Shaper card and auto-tune |

Without the middle two the switch still works; the app says the tunnel's ping may be stale until the router
refreshes it. Settings > Test lists what the key can do.

## 1. App only

Already covered by docs/ADMIN-SETUP.md section 3 / 3b: a route to `<ROUTER_LAN_IP>/32` and a rule on the remote
interface that allows only TCP 443 to the router (plus DNS to the router), then block everything else.

## 2. Home devices only

1. **Tailscale:** VPN > Tailscale > Settings > Subnets: add `<NAS_IP>/32` next to `<ROUTER_LAN_IP>/32`, apply,
   then approve the new route in the Tailscale admin console (Machines > the router > Edit route settings).
2. **Alias:** Firewall > Aliases: `REMOTE_DEVICES` (Host(s)) = the tailnet IPs of YOUR devices (Tailscale admin
   console > Machines). Only these get past the router.
3. **Rule** on the TAILSCALE interface, ABOVE the final "block all":
   pass TCP, source `REMOTE_DEVICES`, destination `<NAS_IP>`, ports 5001 (DSM), 6690 (Synology Drive),
   445 (SMB, optional), description "Remote: home devices".
4. In the app: Remote access > "Home devices only", Home devices = `<NAS_IP>`.

## 3. Everything via home

1. **Exit node:** VPN > Tailscale > Settings: tick "Advertise exit node", apply, then approve it in the
   Tailscale admin console (Machines > the router > Edit route settings > Use as exit node).
2. **Rule** on the TAILSCALE interface, ABOVE the final "block all": pass any, source `REMOTE_DEVICES`,
   destination NOT the private ranges (alias of 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), **Gateway =
   `<VPN_GW_GROUP>`** (Advanced: policy-based routing), **Set local tag = `<KILL_TAG>`**, description
   "Remote: everything via VPN". The tag puts this traffic under the kill switch: if both tunnels drop it is
   blocked instead of leaving through the plain internet.
3. **Outbound NAT:** Firewall > NAT > Outbound. In Automatic mode nothing to do. In Hybrid/Manual add, on each VPN
   interface (main and backup tunnel): source = the Tailscale range 100.64.0.0/10, translation = interface
   address.
4. **DNS:** remote devices use the router's resolver (already allowed by the DNS rule from section 1), so DNS
   also goes out through the tunnels.
5. **Test** from mobile data: the app's Tests page should show the VPN exit city, "no DNS leak" and the kill
   switch armed.

## Undo

Delete the rules/alias above, untick "Advertise exit node" and remove the extra subnet; the app falls back to
"App only". OPNsense keeps every change under System > Configuration > History.
