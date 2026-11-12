#!/bin/sh
# Cybervulcan router-side bypass timer - installer for OPNsense.
#
# Installs a small script that ends an expired whole-house VPN bypass even
# when no copy of the Cybervulcan app is running. It reads the deadline the
# app stores in the BYPASS_ALL table (the 240.x.x.x marker entry) and, once
# that time has passed, empties the table and resets the bypassed
# connections - exactly what the app itself does. A "no time limit" bypass
# carries a deadline centuries away, so it is left alone.
#
# Install (OPNsense console option 8 "Shell", or SSH), as root:
#   fetch -qo - https://raw.githubusercontent.com/G0taW00dy/OPNsense-Cybervulcan/main/router/install.sh | sh
# Remove:
#   fetch -qo - https://raw.githubusercontent.com/G0taW00dy/OPNsense-Cybervulcan/main/router/install.sh | sh -s uninstall
#
# Then in the web GUI: System > Settings > Cron > "+":
#   Minutes: *   Hours/Day/Month/Weekdays: *
#   Command: "Cybervulcan - end expired whole-house VPN bypass"
#   Parameters: BYPASS_ALL      (your bypass alias name)
#
# The script never changes the saved router configuration; it only touches
# the runtime table you name. Everything it does is logged to the system log
# (System > Log Files > General, search "cybervulcan").

set -eu

SCRIPT=/usr/local/sbin/cybervulcan-bypass-expire
ACTIONS=/usr/local/opnsense/service/conf/actions.d/actions_cybervulcan.conf

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root (console option 8, or 'sudo su -' over SSH)." >&2
    exit 1
fi

if [ "${1:-}" = "uninstall" ]; then
    rm -f "$SCRIPT" "$ACTIONS"
    service configd restart >/dev/null 2>&1 || true
    echo "Cybervulcan bypass timer removed. Delete its job under System > Settings > Cron too."
    exit 0
fi

cat > "$SCRIPT" <<'EOF'
#!/bin/sh
# Cybervulcan: end an expired whole-house VPN bypass.
# Usage: cybervulcan-bypass-expire [TABLE]   (default BYPASS_ALL)
# Installed by https://github.com/G0taW00dy/OPNsense-Cybervulcan (router/install.sh)

TABLE="${1:-BYPASS_ALL}"
case "$TABLE" in
    *[!A-Za-z0-9_]*|"") logger -t cybervulcan "bad table name"; exit 2 ;;
esac

ENTRIES=$(/sbin/pfctl -t "$TABLE" -T show 2>/dev/null) || exit 0
[ -n "$ENTRIES" ] || exit 0

NOW=$(date +%s)
DEADLINE=""   # earliest marker, in epoch minutes
NETS=""       # the real (non-marker) entries = what is bypassed

for E in $ENTRIES; do
    ADDR=${E%%/*}
    OLDIFS=$IFS; IFS=.; set -- $ADDR; IFS=$OLDIFS
    if [ $# -eq 4 ] && [ "$1" -ge 240 ] 2>/dev/null && [ "$1" -le 255 ]; then
        # Marker: 240.0.0.0/4 + deadline in epoch minutes (28 bits).
        M=$(( (($1 & 15) << 24) | ($2 << 16) | ($3 << 8) | $4 ))
        if [ -z "$DEADLINE" ] || [ "$M" -lt "$DEADLINE" ]; then DEADLINE=$M; fi
    else
        NETS="$NETS $E"
    fi
done

# No marker: the app has not set a deadline yet (it adopts one itself).
[ -n "$DEADLINE" ] || exit 0
# Not due yet (also covers "no time limit").
[ "$NOW" -ge $(( DEADLINE * 60 )) ] || exit 0

/sbin/pfctl -t "$TABLE" -T flush >/dev/null 2>&1
for N in $NETS; do
    # Move bypassed connections back onto the VPN (both directions).
    /sbin/pfctl -k "$N" >/dev/null 2>&1
    /sbin/pfctl -k 0.0.0.0/0 -k "$N" >/dev/null 2>&1
done
logger -t cybervulcan "VPN bypass in $TABLE expired; table flushed, states reset for:${NETS:- (none)}"
EOF
chmod 0755 "$SCRIPT"

cat > "$ACTIONS" <<'EOF'
[bypass.expire]
command:/usr/local/sbin/cybervulcan-bypass-expire
parameters:%s
type:script
message:Cybervulcan bypass expiry check (%s)
description:Cybervulcan - end expired whole-house VPN bypass
EOF

service configd restart >/dev/null 2>&1

# Quick self-check through configd, the same path cron uses.
if configctl cybervulcan bypass expire BYPASS_ALL >/dev/null 2>&1; then
    STATUS="self-check OK"
else
    STATUS="self-check could not run (see System > Log Files > Backend)"
fi

cat <<MSG
Cybervulcan bypass timer installed ($STATUS).

Last step, in the web GUI: System > Settings > Cron > "+"
  Minutes/Hours/Day/Month/Weekdays: *
  Command:    Cybervulcan - end expired whole-house VPN bypass
  Parameters: BYPASS_ALL
  Save, then Apply.
MSG
