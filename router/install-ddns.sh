#!/bin/sh
# Cybervulcan GoDaddy DDNS updater - installer for OPNsense.
#
# os-ddclient has no GoDaddy service. This installs a small script that keeps
# ONE GoDaddy DNS record (e.g. home.cybervulcan.com, A and optionally AAAA)
# pointing at the router's WAN address, so the Cybervulcan app's remote
# access (WireGuard) can find home.
#
# It only ever reads and replaces the A/AAAA record of the exact name you give
# it (GET/PUT /v1/domains/{domain}/records/{A|AAAA}/{name}); it never touches
# any other record - MX, SPF, DKIM, DMARC etc. stay exactly as they are - and
# it only writes when the address actually changed.
#
# Install (OPNsense console option 8 "Shell", or SSH), as root:
#   fetch -qo /tmp/install-ddns.sh https://raw.githubusercontent.com/G0taW00dy/OPNsense-Cybervulcan/main/router/install-ddns.sh && sh /tmp/install-ddns.sh
# (Download first, then run: the installer asks for the GoDaddy key and
#  secret on the console, which does not work when piped into sh.)
# Remove:
#   sh /tmp/install-ddns.sh uninstall
#
# Then in the web GUI: System > Settings > Cron > "+":
#   Minutes: */5   Hours/Day/Month/Weekdays: *
#   Command: "Cybervulcan - update GoDaddy DNS"
#   Parameters: home.cybervulcan.com      (the record to keep up to date)
#
# The key and secret are stored in /usr/local/etc/cybervulcan-ddns.conf
# (root only, mode 0600). They are never echoed, logged or put on a command
# line. Log: System > Log Files > General, search "cybervulcan-ddns".

set -eu

SCRIPT=/usr/local/sbin/cybervulcan-ddns-godaddy
CONF=/usr/local/etc/cybervulcan-ddns.conf
ACTIONS=/usr/local/opnsense/service/conf/actions.d/actions_cybervulcan_ddns.conf
GUI_CACHE=/var/lib/php/tmp/configdmodelfield.data

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root (console option 8, or 'sudo su -' over SSH)." >&2
    exit 1
fi

if [ "${1:-}" = "uninstall" ]; then
    rm -f "$SCRIPT" "$ACTIONS" "$GUI_CACHE" "$CONF"
    rm -rf /var/db/cybervulcan-ddns
    service configd restart >/dev/null 2>&1 || true
    echo "Cybervulcan GoDaddy DDNS removed (including the stored key). Delete its job under System > Settings > Cron too."
    exit 0
fi

cat > "$SCRIPT" <<'EOF'
#!/bin/sh
# Cybervulcan: keep one GoDaddy A/AAAA record pointing at this router's WAN.
# Usage: cybervulcan-ddns-godaddy HOSTNAME     e.g. home.cybervulcan.com
# Settings + credentials: /usr/local/etc/cybervulcan-ddns.conf (root, 0600)
# Installed by https://github.com/G0taW00dy/OPNsense-Cybervulcan (router/install-ddns.sh)

umask 077
TAG=cybervulcan-ddns
CONF=/usr/local/etc/cybervulcan-ddns.conf
API=https://api.godaddy.com/v1/domains
log() { logger -t "$TAG" "$*"; }

HOST=$(printf '%s' "${1:-}" | tr 'A-Z' 'a-z')
case "$HOST" in
    ""|*[!a-z0-9.-]*|.*|*.|*..*) log "bad hostname parameter"; exit 2 ;;
esac

[ -f "$CONF" ] || { log "missing $CONF - run install-ddns.sh"; exit 2; }
# Only trust a root-owned file nobody else can read or write.
case "$(stat -f '%Su %Lp' "$CONF")" in
    "root 600") ;;
    *) log "$CONF must be owned by root with mode 0600"; exit 2 ;;
esac
GODADDY_KEY=""; GODADDY_SECRET=""; DOMAIN=""; WAN_IF=""; IPV6="no"; TTL=600
. "$CONF"
[ -n "$GODADDY_KEY" ] && [ -n "$GODADDY_SECRET" ] || { log "key/secret not set in $CONF"; exit 2; }

# Zone: from the config, else the last two labels of the host name.
[ -n "$DOMAIN" ] || DOMAIN=$(printf '%s' "$HOST" | awk -F. 'NF>=2 {print $(NF-1)"."$NF}')
case "$HOST" in
    "$DOMAIN") NAME="@" ;;
    *."$DOMAIN") NAME=${HOST%."$DOMAIN"} ;;
    *) log "$HOST is not inside the zone $DOMAIN"; exit 2 ;;
esac

[ -n "$WAN_IF" ] || WAN_IF=$(route -n get -inet default 2>/dev/null | awk '/interface:/ {print $2}')

is_public_v4() {
    case "$1" in
        ""|10.*|127.*|0.*|169.254.*|192.168.*) return 1 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 1 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 1 ;; # CGNAT
        22[4-9].*|2[3-5][0-9].*) return 1 ;; # multicast / reserved
    esac
    printf '%s' "$1" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
}

# --- WAN IPv4: the interface address when it is public, else ask a check-IP
# service (behind CGNAT/another router the interface has a private address).
V4=""
[ -n "$WAN_IF" ] && V4=$(ifconfig "$WAN_IF" inet 2>/dev/null | awk '/inet / {print $2; exit}')
if ! is_public_v4 "$V4"; then
    V4=$(curl -4 -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)
    is_public_v4 "$V4" || V4=""
    [ -n "$V4" ] && log "WAN interface ${WAN_IF:-?} has no public IPv4; using check-IP result $V4 (if this is behind CGNAT, inbound WireGuard will not work)"
fi

V6=""
if [ "$IPV6" = "yes" ] && [ -n "$WAN_IF" ]; then
    V6=$(ifconfig "$WAN_IF" inet6 2>/dev/null \
        | awk '/inet6 / && !/deprecated/ && !/temporary/ && !/detached/ && !/tentative/ {print $2}' \
        | grep -E '^[23][0-9a-f]{0,3}:' | head -n 1)
fi

[ -n "$V4" ] || [ -n "$V6" ] || { log "no public WAN address found; nothing updated"; exit 1; }

WORK=$(mktemp -d /tmp/cvddns.XXXXXX) || exit 1
trap 'rm -rf "$WORK"' EXIT INT TERM
# The Authorization header goes through a 0600 file, never the command line.
printf 'Authorization: sso-key %s:%s\n' "$GODADDY_KEY" "$GODADDY_SECRET" > "$WORK/auth"
printf 'Accept: application/json\n' >> "$WORK/auth"

update() { # TYPE ADDRESS
    TYPE=$1; ADDR=$2
    URL="$API/$DOMAIN/records/$TYPE/$NAME"
    CODE=$(curl -sS --max-time 20 -H @"$WORK/auth" -o "$WORK/get" -w '%{http_code}' "$URL" 2>/dev/null) || CODE=000
    if [ "$CODE" != "200" ]; then
        log "GET $TYPE $HOST failed (HTTP $CODE)"; return 1
    fi
    CURRENT=$(sed -n 's/.*"data"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$WORK/get" | head -n 1)
    # Exactly one record that already matches: nothing to do.
    COUNT=$(grep -o '"data"' "$WORK/get" | wc -l | tr -d ' ')
    if [ "$CURRENT" = "$ADDR" ] && [ "$COUNT" = "1" ]; then
        return 0
    fi
    printf '[{"data":"%s","ttl":%d}]' "$ADDR" "$TTL" > "$WORK/body"
    CODE=$(curl -sS --max-time 20 -X PUT -H @"$WORK/auth" -H 'Content-Type: application/json' \
        --data-binary @"$WORK/body" -o "$WORK/put" -w '%{http_code}' "$URL" 2>/dev/null) || CODE=000
    if [ "$CODE" = "200" ]; then
        log "$TYPE $HOST updated: ${CURRENT:-none} -> $ADDR"
    else
        log "PUT $TYPE $HOST failed (HTTP $CODE): $(head -c 200 "$WORK/put" | tr -d '\n')"
        return 1
    fi
}

RC=0
[ -z "$V4" ] || update A "$V4" || RC=1
[ -z "$V6" ] || update AAAA "$V6" || RC=1
exit $RC
EOF
chmod 0755 "$SCRIPT"

cat > "$ACTIONS" <<'EOF'
[update]
command:/usr/local/sbin/cybervulcan-ddns-godaddy
parameters:%s
type:script
message:Cybervulcan GoDaddy DDNS update (%s)
description:Cybervulcan - update GoDaddy DNS
EOF

# ---- credentials (asked on the console, never echoed)
if [ -f "$CONF" ]; then
    printf 'Keep the stored GoDaddy key and settings? [Y/n] ' > /dev/tty
    read -r KEEP < /dev/tty || KEEP=y
else
    KEEP=n
fi
case "$KEEP" in
    n*|N*)
        printf 'GoDaddy API key: ' > /dev/tty
        stty -echo < /dev/tty; read -r K < /dev/tty; stty echo < /dev/tty; echo > /dev/tty
        printf 'GoDaddy API secret: ' > /dev/tty
        stty -echo < /dev/tty; read -r S < /dev/tty; stty echo < /dev/tty; echo > /dev/tty
        case "$K$S" in *[!A-Za-z0-9_]*|"")
            echo "The key and secret may only contain letters, digits and _." >&2; exit 1 ;;
        esac
        DEF_IF=$(route -n get -inet default 2>/dev/null | awk '/interface:/ {print $2}')
        printf 'WAN interface [%s]: ' "$DEF_IF" > /dev/tty
        read -r IF < /dev/tty || IF=""
        IF=${IF:-$DEF_IF}
        case "$IF" in *[!A-Za-z0-9_.]*) echo "Bad interface name." >&2; exit 1 ;; esac
        printf 'Also publish IPv6 (AAAA)? [y/N] ' > /dev/tty
        read -r V6 < /dev/tty || V6=n
        case "$V6" in y*|Y*) V6=yes ;; *) V6=no ;; esac
        OLD=$(umask); umask 077
        {
            echo "# Cybervulcan GoDaddy DDNS - root only (0600). Never share this file."
            echo "GODADDY_KEY='$K'"
            echo "GODADDY_SECRET='$S'"
            echo "# Zone; empty = last two labels of the host name (e.g. cybervulcan.com)"
            echo "DOMAIN=''"
            echo "WAN_IF='$IF'"
            echo "IPV6='$V6'"
            echo "TTL=600"
        } > "$CONF"
        umask "$OLD"
        unset K S
        ;;
esac
chown root:wheel "$CONF"
chmod 0600 "$CONF"

service configd restart >/dev/null 2>&1
rm -f "$GUI_CACHE"

cat <<MSG
Cybervulcan GoDaddy DDNS installed. Credentials: $CONF (root only).

Test it now (replace the name with yours):
  configctl cybervulcan_ddns update home.cybervulcan.com
  grep cybervulcan-ddns /var/log/system/latest.log

Last step, in the web GUI: System > Settings > Cron > "+"
  Minutes: */5   Hours/Day/Month/Weekdays: *
  Command:    Cybervulcan - update GoDaddy DNS
  Parameters: home.cybervulcan.com
  Save, then Apply.
MSG
