#!/bin/sh
# Regression test for the access-port default bind policy.
#
# A positive -P value without an explicit -B address must create local IPv4
# and IPv6 loopback listeners only. An explicit -B remains the opt-in for any
# externally reachable address.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="$REPO_ROOT/bin/argus"
PCAP_FIXTURE="$SCRIPT_DIR/fixtures/lsp-ping-timestamp.pcap"

REGRESSION_FAIL_MARKER="$(mktemp -t argus_regress_access_port.XXXXXX)"
OUTFILE="$(mktemp -t argus_regress_access_out.XXXXXX)"
LOGFILE="$(mktemp -t argus_regress_access_log.XXXXXX)"
LISTEN_FILE="$(mktemp -t argus_regress_access_listen.XXXXXX)"
PID=""
PORT=$((20000 + ($$ % 10000)))

cleanup() {
   if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
      kill -TERM "$PID" 2>/dev/null
      wait_for_exit "$PID" 20 || kill -9 "$PID" 2>/dev/null
   fi
   rm -f "$REGRESSION_FAIL_MARKER" "$OUTFILE" "$LOGFILE" "$LISTEN_FILE"
}
trap cleanup EXIT HUP INT TERM

if [ ! -x "$ARGUS_BIN" ]; then
   echo "error: $ARGUS_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi

if ! command -v lsof >/dev/null 2>&1; then
   echo "error: lsof is required to inspect Argus listener addresses" >&2
   exit 2
fi

# Clear any bind address inherited from /etc/argus.conf so this exercises the
# no-explicit-bind path even on systems with a site configuration.
HOME=/tmp "$ARGUS_BIN" -r "$PCAP_FIXTURE" -f -w "$OUTFILE" -B null -P "$PORT" -D 0 >"$LOGFILE" 2>&1 &
PID=$!
sleep 1

if ! kill -0 "$PID" 2>/dev/null; then
   fail "argus exited before listener inspection (see $LOGFILE)"
else
   lsof -nP -a -p "$PID" -iTCP:"$PORT" -sTCP:LISTEN -Fn >"$LISTEN_FILE" 2>/dev/null

   saw_ipv4=0
   saw_ipv6=0
   unexpected=""
   while IFS= read -r line; do
      case "$line" in
         "n127.0.0.1:$PORT") saw_ipv4=1 ;;
         "n[::1]:$PORT") saw_ipv6=1 ;;
         n*) unexpected="$unexpected $line" ;;
      esac
   done <"$LISTEN_FILE"

   if [ "$saw_ipv4" -eq 1 ]; then
      pass "access port binds IPv4 loopback by default"
   else
      fail "access port did not bind 127.0.0.1:$PORT"
   fi

   if python3 -c 'import socket; s = socket.socket(socket.AF_INET6); s.bind(("::1", 0)); s.close()' 2>/dev/null; then
      if [ "$saw_ipv6" -eq 1 ]; then
         pass "access port binds IPv6 loopback by default"
      else
         fail "access port did not bind [::1]:$PORT"
      fi
   else
      pass "IPv6 loopback is unavailable; IPv6 listener not required"
   fi

   if [ -z "$unexpected" ]; then
      pass "access port has no wildcard or non-loopback listener"
   else
      fail "unexpected access-port listener(s):$unexpected"
   fi
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
