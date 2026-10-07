#!/bin/sh
# stress_test.sh - Run on the LAN client to generate rapid TCP connections.
#
# Opens COUNT TCP-handshake-only connections (HEAD, no body download) spread
# across a rotating list of TARGETS, in bursts of PARALLEL concurrent curls.
# Each connection completes a full SYN/SYN-ACK/ACK — exactly what the eBPF PoC
# measures — without transferring a response body.  Used to stress the gateway
# while gw_cpu_measure.sh samples CPU on the GW.
#
# WHY MULTIPLE SERVERS: a single public server rate-limits / throttles after a
# few thousand rapid connections, which silently starves the handshake stream
# and corrupts CPU/coverage comparisons.  Rotating across several servers keeps
# the load steady.  Rotate this list again between separate test rounds.
#
# THROTTLE HANDLING: if a server fails to complete the handshake $STRIKES times
#       (default 3), it is DROPPED from rotation — no further connections are
#       sent to it — and those connections fail over to the next healthy server.
#       So a throttled server stops receiving load instead of draining attempts.
#       Override the threshold with the STRIKES env var (e.g. STRIKES=1).
#
# BEST PRACTICE: for the definitive benchmark, point at your OWN server with
#       -l (e.g. `python3 -m http.server 80` on a box you control, or a second
#       gateway).  One unlimited local server never throttles, giving fully
#       repeatable numbers.  The public pool is only a fallback.
#
# NOTE: every TARGET must serve HTTP on port 80 and complete a TCP handshake.
#       Do NOT use 1.1.1.1 (Cloudflare DNS — refuses port 80 -> no handshake,
#       so no RTT events are produced).  Prefer IPs to avoid DNS variance.
#
# Usage:
#   sh stress_test.sh [-l LOCAL_SERVER] [COUNT] [PARALLEL] [TARGET ...]
#   sh stress_test.sh 60000 50                       # default 8-server pool
#   sh stress_test.sh -l 192.168.0.50 60000 50       # your own server only
#   sh stress_test.sh 60000 50 142.251.41.163 104.16.133.229   # custom pool
#   STRIKES=1 sh stress_test.sh 60000 50             # drop a server on first fail

# --- optional -l/--local flag: use a single local server exclusively ---------
LOCAL_SERVER=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -l|--local) LOCAL_SERVER="$2"; shift 2 ;;
        -l*)        LOCAL_SERVER="${1#-l}"; shift ;;
        --)         shift; break ;;
        -*)         echo "Unknown option: $1" >&2; exit 1 ;;
        *)          break ;;
    esac
done

COUNT="${1:-300}"
PARALLEL="${2:-30}"
[ "$#" -ge 1 ] && shift
[ "$#" -ge 1 ] && shift

# Target selection priority: -l local server > positional custom pool > default.
# Using IPs avoids DNS caching/variance during the run.
if [ -n "$LOCAL_SERVER" ]; then
    TARGETS="$LOCAL_SERVER"
elif [ "$#" -gt 0 ]; then
    TARGETS="$*"
else
    TARGETS="connectivitycheck.gstatic.com cp.cloudflare.com detectportal.firefox.com \
www.msftconnecttest.com neverssl.com captive.apple.com clients3.google.com ifconfig.me"
fi

# Count servers for round-robin.
set -- $TARGETS
NSERVERS=$#

# Number of failed connects before a server is declared throttled and DROPPED
# from rotation — after this, NO new connections are sent to it.  Override with
# the STRIKES env var (a small value avoids one transient blip killing a good
# server; sustained throttling still gets the server removed quickly).
STRIKES="${STRIKES:-3}"

# NOTE (race conditions): the parallel workers share the strike files below
# WITHOUT locking.  Appends are atomic (< PIPE_BUF) so no file corruption, but
# the drop decision is best-effort: several in-flight workers can hit a
# throttled server at once before the strike count crosses $STRIKES, so a dead
# server may briefly receive up to ~$PARALLEL extra attempts during detection.
# This is bounded and negligible vs a large run.  Left as-is for now — revisit
# after performance testing to decide if atomic (mkdir/flock) locking is worth it.

# Shared scratch dir: each worker appends a "strike" line per failed connect;
# once a server reaches $STRIKES strikes, all subsequent workers skip it.
DEADDIR=$(mktemp -d 2>/dev/null || echo "/tmp/stress_dead.$$")
mkdir -p "$DEADDIR"
trap 'rm -rf "$DEADDIR"' EXIT INT TERM

echo "Stress test: $COUNT connections, ${PARALLEL} parallel"
echo "Server pool ($NSERVERS): $TARGETS"
echo "Throttle policy: drop a server after $STRIKES failed connects, fail over to next healthy server"
echo "Start time: $(date '+%H:%M:%S')"

# Each worker starts at its round-robin server and, on a failed handshake
# (time_connect == 0), records a strike and FAILS OVER to the next server —
# skipping any server that has already reached $STRIKES strikes.  A throttled
# server is thus removed from rotation and receives no new connections.
# Handshake-only via -I (HEAD): the full SYN/SYN-ACK/ACK still completes (exactly
# what the eBPF PoC keys on) without downloading a response body.  curl measures
# %{time_connect} for free, so a NONZERO value proves the handshake happened.
seq 1 "$COUNT" | xargs -P"$PARALLEL" -I{} sh -c '
    conn=$1
    set -- '"$TARGETS"'
    n=$#
    strikes='"$STRIKES"'
    deaddir="'"$DEADDIR"'"
    start=$(( conn % n ))
    i=0
    result="0.000000"
    while [ "$i" -lt "$n" ]; do
        idx=$(( (start + i) % n + 1 ))
        eval server=\${$idx}
        sf="$deaddir/$idx"
        cnt=0
        [ -f "$sf" ] && cnt=$(wc -l < "$sf" 2>/dev/null)
        if [ "$(( cnt + 0 ))" -ge "$strikes" ]; then
            i=$(( i + 1 )); continue          # server already dropped — skip it
        fi
        tc=$(curl -4 -I -o /dev/null -s --connect-timeout 5 --max-time 10 \
                  -w "%{time_connect}" "http://$server")
        case "$(printf "%s" "$tc" | tr -d ".")" in
            *[1-9]*) result="$tc"; break ;;    # handshake completed -> done
            *)       echo x >> "$sf"; i=$(( i + 1 )) ;;   # strike + fail over
        esac
    done
    echo "$result"
' _ {} | awk -v attempted="$COUNT" '
    { total++; if ($1 + 0 > 0) connected++ }
    END {
        failed = attempted - connected
        printf "Handshakes:  %d connected / %d attempted", connected, attempted
        if (attempted > 0) printf "  (%.1f%%)", connected * 100 / attempted
        printf "\n"
        if (failed > 0)
            printf "WARNING:     %d connection(s) failed on ALL servers — whole pool may be throttled; add more or use -l local server.\n", failed
    }'

# Report any servers that were dropped from rotation (reached $STRIKES strikes).
set -- $TARGETS
for f in "$DEADDIR"/*; do
    [ -e "$f" ] || continue
    idx=$(basename "$f")
    strk=0
    strk=$(wc -l < "$f" 2>/dev/null)
    if [ "$(( strk + 0 ))" -ge "$STRIKES" ]; then
        eval dead_server=\${$idx}
        echo "DROPPED:     $dead_server (throttled — removed from rotation after $STRIKES failed connects)"
    fi
done

echo "End time:   $(date '+%H:%M:%S')"
echo "Done — $COUNT connections completed across $NSERVERS servers."

