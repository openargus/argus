#!/bin/sh
# Regression test for input-filter allocation and cleanup ownership.
#
# Resource-file and command-line filters are cloned into each offline source.
# Their strings must all use the libc allocation family because source cleanup
# releases them with free().

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="$REPO_ROOT/bin/argus"
PCAP_FIXTURE="$SCRIPT_DIR/fixtures/lsp-ping-timestamp.pcap"

REGRESSION_FAIL_MARKER="$(mktemp -t argus_regress_filter_cleanup.XXXXXX)"
FILTER_CONF="$(mktemp -t argus_regress_filter_cleanup.XXXXXX.conf)"
EMPTY_CONF="$(mktemp -t argus_regress_filter_cleanup.XXXXXX.conf)"
OUTFILE=""
LOGFILE=""
PID=""

cleanup() {
   if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
      kill -TERM "$PID" 2>/dev/null
      wait_for_exit "$PID" 20 || kill -KILL "$PID" 2>/dev/null
   fi
   rm -f "$REGRESSION_FAIL_MARKER" "$FILTER_CONF" "$EMPTY_CONF" "$OUTFILE" "$LOGFILE"
}
trap cleanup EXIT HUP INT TERM

if [ ! -x "$ARGUS_BIN" ]; then
   echo "error: $ARGUS_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi

cat > "$FILTER_CONF" <<'EOF'
ARGUS_FILTER=udp
EOF

run_case() {
   label="$1"
   conf="$2"
   shift 2

   OUTFILE="$(mktemp -t argus_regress_filter_out.XXXXXX)"
   LOGFILE="$(mktemp -t argus_regress_filter_log.XXXXXX)"
   HOME=/tmp "$ARGUS_BIN" -F "$conf" -r "$PCAP_FIXTURE" -w "$OUTFILE" -P 0 -D 0 "$@" >"$LOGFILE" 2>&1 &
   PID=$!

   if wait_for_exit "$PID" 50; then
      if wait "$PID"; then
         pass "$label: exited cleanly"
      else
         fail "$label: exited non-zero (see $LOGFILE)"
      fi
      PID=""
   else
      fail "$label: did not exit within five seconds (see $LOGFILE)"
      kill -TERM "$PID" 2>/dev/null
      wait_for_exit "$PID" 20 || kill -KILL "$PID" 2>/dev/null
      wait "$PID" 2>/dev/null
      PID=""
   fi

   if [ -s "$OUTFILE" ]; then
      pass "$label: matching packet produced output"
   else
      fail "$label: matching packet produced no output"
   fi

   if grep -qi "ArgusFree: buffer error\|abort\|SIGABRT\|Segmentation" "$LOGFILE"; then
      fail "$label: logged an allocation or abort error (see $LOGFILE)"
   else
      pass "$label: no allocation or abort error logged"
   fi

   rm -f "$OUTFILE" "$LOGFILE"
   OUTFILE=""
   LOGFILE=""
}

run_case "resource-file filter" "$FILTER_CONF"
run_case "command-line filter" "$EMPTY_CONF" -- udp
run_case "resource-file and command-line filter" "$FILTER_CONF" -- udp

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
