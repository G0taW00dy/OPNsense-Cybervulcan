#!/bin/sh
# Cybervulcan router-side helpers - installer for OPNsense.
#
# 1. Bypass timer (below).
# 2. API watchdog (v2.2.7): on 24 Nov the router's web GUI and API stopped
#    answering after a long "Find best". The console showed the router's
#    "list service status" calls (pluginctl -S, used by the dashboard and the
#    API) hanging one after another until every web worker was stuck. The
#    watchdog stops such calls once they have hung for over a minute (they
#    only read status, so stopping them is harmless), which frees the web
#    workers without a reboot, and it writes what they were waiting on to
#    /var/log/cybervulcan-watchdog.log so the root cause can be reported.
#
# Installs a small script that ends an expired whole-house VPN bypass even
# when no copy of the Cybervulcan app is running. It reads the deadline the
# app stores in the BYPASS_ALL table (the 240.x.x.x marker entry) and, once
# that time has passed, empties the table and resets the bypassed
# connections - exactly what the app itself does. A "no time limit" bypass
# carries a deadline centuries away, so it is left alone.
#
# Install (OPNsense console option 8 "Shell", or SSH), as root: copy the
# install line from the app (Help > Router timer). It downloads this script
# from the release tag matching the app and only runs it when its SHA-256
# matches the copy built into the app:
#   fetch -qo /tmp/cvinstall.sh https://raw.githubusercontent.com/<repo>/v<version>/router/install.sh \
#     && [ "$(sha256 -q /tmp/cvinstall.sh)" = "<sha256>" ] && sh /tmp/cvinstall.sh
# Remove:
#   sh /tmp/cvinstall.sh uninstall
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
WATCHDOG=/usr/local/sbin/cybervulcan-api-watchdog
ACTIONS=/usr/local/opnsense/service/conf/actions.d/actions_cybervulcan.conf

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root (console option 8, or 'sudo su -' over SSH)." >&2
    exit 1
fi

# The GUI caches its list of cron-able commands here; drop it so the change shows.
GUI_CACHE=/var/lib/php/tmp/configdmodelfield.data

if [ "${1:-}" = "uninstall" ]; then
    rm -f "$SCRIPT" "$WATCHDOG" "$ACTIONS" "$GUI_CACHE"
    service configd restart >/dev/null 2>&1 || true
    echo "Cybervulcan bypass timer and API watchdog removed. Delete their jobs under System > Settings > Cron too."
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

cat > "$WATCHDOG" <<'EOF'
#!/bin/sh
# Cybervulcan: keep the web GUI / API answering when service-status calls hang.
# Usage: cybervulcan-api-watchdog [SECONDS]   (default 60, at least 30)
# Installed by https://github.com/G0taW00dy/OPNsense-Cybervulcan (router/install.sh)
# Only ever stops 'pluginctl -S' (a read-only status listing) that has run
# longer than SECONDS. Details go to /var/log/cybervulcan-watchdog.log.

LIMIT="${1:-60}"
case "$LIMIT" in
    *[!0-9]*|"") logger -t cybervulcan "watchdog: bad limit"; exit 2 ;;
esac
[ "$LIMIT" -ge 30 ] || LIMIT=30
LOG=/var/log/cybervulcan-watchdog.log

STUCK=""
OLDEST=""
OLDEST_T=0
for P in $(pgrep -f 'pluginctl -S'); do
    T=$(ps -o etimes= -p "$P" 2>/dev/null | tr -d ' ')
    case "$T" in ''|*[!0-9]*) continue ;; esac
    [ "$T" -ge "$LIMIT" ] || continue
    STUCK="$STUCK $P"
    if [ "$T" -gt "$OLDEST_T" ]; then OLDEST=$P; OLDEST_T=$T; fi
done
[ -n "$STUCK" ] || exit 0

{
    echo "== $(date '+%Y-%m-%d %H:%M:%S') stuck service-status calls (over ${LIMIT}s):$STUCK"
    echo "-- oldest: $OLDEST (${OLDEST_T}s), kernel stack and children:"
    procstat -kk "$OLDEST" 2>&1 | tail -n 3
    pgrep -lP "$OLDEST" 2>&1
    for C in $(pgrep -P "$OLDEST"); do procstat -kk "$C" 2>&1 | tail -n 2; done
    echo "-- related processes:"
    ps -axwwo pid,ppid,etime,stat,wchan,command \
        | egrep 'php|configd|dpinger|pluginctl|rc\.|wg|lighttpd' | egrep -v egrep | cut -c1-200
    echo "-- configd (last 15 lines):"
    tail -n 15 /var/log/configd/latest.log 2>/dev/null | cut -c1-200
} >> "$LOG" 2>&1

# Keep the log small (it only grows when something hangs).
if [ "$(wc -c < "$LOG")" -gt 1048576 ]; then
    tail -n 2000 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi

kill $STUCK 2>/dev/null
N=$(echo $STUCK | wc -w | tr -d ' ')
logger -t cybervulcan "watchdog: stopped $N stuck service-status call(s), oldest ${OLDEST_T}s (details in $LOG)"
EOF
chmod 0755 "$WATCHDOG"

cat > "$ACTIONS" <<'EOF'
[bypass.expire]
command:/usr/local/sbin/cybervulcan-bypass-expire
parameters:%s
type:script
message:Cybervulcan bypass expiry check (%s)
description:Cybervulcan - end expired whole-house VPN bypass

[api.watchdog]
command:/usr/local/sbin/cybervulcan-api-watchdog
parameters:%s
type:script
message:Cybervulcan API watchdog (%s)
description:Cybervulcan - clear stuck service-status calls (keeps the web GUI answering)
EOF

service configd restart >/dev/null 2>&1
rm -f "$GUI_CACHE"

# Quick self-check through configd, the same path cron uses.
if configctl cybervulcan bypass expire BYPASS_ALL >/dev/null 2>&1 \
    && configctl cybervulcan api watchdog 60 >/dev/null 2>&1; then
    STATUS="self-check OK"
else
    STATUS="self-check could not run (see System > Log Files > Backend)"
fi

cat <<MSG
Cybervulcan bypass timer and API watchdog installed ($STATUS).

Last step, in the web GUI: System > Settings > Cron > "+" (twice):
  Minutes/Hours/Day/Month/Weekdays: *
  Command:    Cybervulcan - end expired whole-house VPN bypass
  Parameters: BYPASS_ALL
and
  Minutes/Hours/Day/Month/Weekdays: *
  Command:    Cybervulcan - clear stuck service-status calls (keeps the web GUI answering)
  Parameters: 60
  Save each, then Apply.
MSG
