#!/bin/sh
# Regression test for truncated GRE routing headers.
#
# The fixture advertises a GRE source-route entry longer than the captured
# frame. The parser must stop at the capture boundary rather than advancing
# the encapsulation pointer past it.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="${ARGUS_BIN:-$REPO_ROOT/bin/argus}"
PCAP_FIXTURE="$SCRIPT_DIR/fixtures/gre-heapoverflow-2.pcap"

REGRESSION_FAIL_MARKER="$(mktemp -t argus_regress_gre_bounds.XXXXXX)"
CONF="$(mktemp -t argus_regress_gre_bounds.XXXXXX.conf)"
OUTFILE="$(mktemp -t argus_regress_gre_out.XXXXXX)"
LOGFILE="$(mktemp -t argus_regress_gre_log.XXXXXX)"
PID=""

cleanup() {
   if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
      kill -TERM "$PID" 2>/dev/null
      wait_for_exit "$PID" 20 || kill -KILL "$PID" 2>/dev/null
   fi
   rm -f "$REGRESSION_FAIL_MARKER" "$CONF" "$OUTFILE" "$LOGFILE"
}
trap cleanup EXIT HUP INT TERM

if [ ! -x "$ARGUS_BIN" ]; then
   echo "error: $ARGUS_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi

cat > "$CONF" <<'EOF'
ARGUS_ENCAPS_CAPTURE=yes
EOF

HOME=/tmp "$ARGUS_BIN" -F "$CONF" -r "$PCAP_FIXTURE" -w "$OUTFILE" -P 0 -D 0 >"$LOGFILE" 2>&1 &
PID=$!

if wait_for_exit "$PID" 50; then
   if wait "$PID"; then
      pass "truncated GRE capture exited cleanly"
   else
      fail "truncated GRE capture exited non-zero (see $LOGFILE)"
   fi
   PID=""
else
   fail "truncated GRE capture did not exit within five seconds (see $LOGFILE)"
   kill -TERM "$PID" 2>/dev/null
   wait_for_exit "$PID" 20 || kill -KILL "$PID" 2>/dev/null
   wait "$PID" 2>/dev/null
   PID=""
fi

if grep -qi "AddressSanitizer\|runtime error\|ArgusFree: buffer error\|abort\|SIGABRT\|Segmentation" "$LOGFILE"; then
   fail "truncated GRE capture logged a parser or sanitizer error (see $LOGFILE)"
else
   pass "truncated GRE capture logged no parser or sanitizer error"
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
