#!/bin/sh
# Regression test for DHCP replay jitter-statistics overflow.
#
# The fixture contains a jitter interval whose square exceeds signed 64-bit
# range in nanoseconds. Jitter DSRs use microseconds, so the replay must run
# cleanly with jitter generation enabled.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="${ARGUS_BIN:-$REPO_ROOT/bin/argus}"
PCAP_FIXTURE="$SCRIPT_DIR/fixtures/dhcp-rfc4388.pcap"

REGRESSION_FAIL_MARKER="$(mktemp -t argus_regress_dhcp_time.XXXXXX)"
OUTFILE="$(mktemp -t argus_regress_dhcp_out.XXXXXX)"
LOGFILE="$(mktemp -t argus_regress_dhcp_log.XXXXXX)"
PID=""

cleanup() {
   if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
      kill -TERM "$PID" 2>/dev/null
      wait_for_exit "$PID" 20 || kill -KILL "$PID" 2>/dev/null
   fi
   rm -f "$REGRESSION_FAIL_MARKER" "$OUTFILE" "$LOGFILE"
}
trap cleanup EXIT HUP INT TERM

if [ ! -x "$ARGUS_BIN" ]; then
   echo "error: $ARGUS_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi
if [ ! -f "$PCAP_FIXTURE" ]; then
   echo "error: $PCAP_FIXTURE not found" >&2
   exit 2
fi

HOME=/tmp "$ARGUS_BIN" -J -S 5 -r "$PCAP_FIXTURE" -w "$OUTFILE" -P 0 -D 0 >"$LOGFILE" 2>&1 &
PID=$!

if wait_for_exit "$PID" 50; then
   if wait "$PID"; then
      pass "DHCP jitter-statistics replay exited cleanly"
   else
      fail "DHCP jitter-statistics replay exited non-zero (see $LOGFILE)"
   fi
   PID=""
else
   fail "DHCP jitter-statistics replay did not exit within five seconds (see $LOGFILE)"
   kill -TERM "$PID" 2>/dev/null
   wait_for_exit "$PID" 20 || kill -KILL "$PID" 2>/dev/null
   wait "$PID" 2>/dev/null
   PID=""
fi

if grep -qi "AddressSanitizer\|runtime error\|ArgusFree: buffer error\|abort\|SIGABRT\|Segmentation" "$LOGFILE"; then
   fail "DHCP jitter-statistics replay logged a parser or sanitizer error (see $LOGFILE)"
else
   pass "DHCP jitter-statistics replay logged no parser or sanitizer error"
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
