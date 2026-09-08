#!/bin/sh
# Regression test for F-38 and F-48.
#
# F-38: ArgusScheduleShutDown() (SIGHUP/SIGINT/SIGTERM handler) had its
#   ArgusShutDownFlag/ArgusShutDownSig assignments nested inside "#ifdef
#   ARGUSDEBUG", so a production build (ARGUSDEBUG undefined) never set the
#   flag every capture-read loop polls to notice a shutdown request.
# F-48: the sFlow datagram-socket read loop additionally didn't check
#   ArgusShutDownFlag in its own loop condition at all (unlike its sibling
#   loops), and separately called a blocking recvfrom() on every select()
#   timeout tick (checking "select() >= 0" instead of "> 0"), so it could
#   never re-check the shutdown flag while idle even after F-38's fix.
#
# This test reproduces both bugs' precise trigger condition -- a capture
# loop with nothing to read, sent a shutdown signal -- against two of the
# affected loops:
#   1. The sFlow UDP-socket loop (F-48's primary repro), using a local
#      "-i sflow://127.0.0.1:<port>" listener with no traffic sent to it.
#   2. The offline "-f" (tail -f-style) follow-mode loop, using a real pcap
#      already fully consumed (EOF reached, waiting for more data that
#      never arrives).
#
# Both scenarios hung indefinitely (10+ seconds, until force-killed) prior
# to the F-38/F-48 fixes; both must now exit within a few seconds of
# SIGTERM.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="$REPO_ROOT/bin/argus"
PCAP_FIXTURE="$REPO_ROOT/security-review/fuzz/corpus/tcp_syn.bin"
# The fuzz corpus's raw Ethernet-frame fixtures aren't pcap files; use the
# repo's own small SLL fixture instead, which is a real, valid pcap.
PCAP_FIXTURE="$SCRIPT_DIR/fixtures/lsp-ping-timestamp.pcap"

REGRESSION_FAIL_MARKER="$(mktemp -t argus_regress_f38_f48.XXXXXX)"
trap 'rm -f "$REGRESSION_FAIL_MARKER"' EXIT

if [ ! -x "$ARGUS_BIN" ]; then
   echo "error: $ARGUS_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi

MAX_WAIT_TENTHS=50   # 5 seconds -- generous margin over the fixed ~0.3s exit time,
                      # comfortably under the old bug's 10+ second hang.

# --- Scenario 1: sFlow UDP listener, no traffic, SIGTERM ---------------------------------

SFLOW_PORT=$((16000 + ($$ % 4000)))   # vary port per-run to avoid clashing with a stale listener
OUT1="$(mktemp -t argus_regress_sflow_out.XXXXXX)"
LOG1="$(mktemp -t argus_regress_sflow_log.XXXXXX)"

HOME=/tmp "$ARGUS_BIN" -i "sflow://127.0.0.1:${SFLOW_PORT}" -w "$OUT1" -P 0 -D 0 >"$LOG1" 2>&1 &
PID1=$!
sleep 1   # let it fully start and enter the sFlow read loop before signaling

if ! kill -0 "$PID1" 2>/dev/null; then
   fail "sFlow scenario: argus exited on its own before SIGTERM was sent (see $LOG1)"
else
   kill -TERM "$PID1"
   if wait_for_exit "$PID1" "$MAX_WAIT_TENTHS"; then
      pass "sFlow scenario (F-48): exited cleanly $((ELAPSED_TENTHS))/10s after SIGTERM"
   else
      fail "sFlow scenario (F-48): still running ${MAX_WAIT_TENTHS}0ms after SIGTERM -- shutdown-flag/blocking-recvfrom regression"
      kill -9 "$PID1" 2>/dev/null
   fi
fi
rm -f "$OUT1" "$LOG1"

# --- Scenario 2: "-f" tail-follow mode, pcap fully consumed, SIGTERM --------------------

OUT2="$(mktemp -t argus_regress_ftail_out.XXXXXX)"
LOG2="$(mktemp -t argus_regress_ftail_log.XXXXXX)"

HOME=/tmp "$ARGUS_BIN" -r "$PCAP_FIXTURE" -f -w "$OUT2" -P 0 -D 0 >"$LOG2" 2>&1 &
PID2=$!
sleep 1   # the fixture pcap is tiny; give it time to finish reading and enter the follow-wait loop

if ! kill -0 "$PID2" 2>/dev/null; then
   fail "-f tail-follow scenario: argus exited on its own before SIGTERM was sent (see $LOG2)"
else
   kill -TERM "$PID2"
   if wait_for_exit "$PID2" "$MAX_WAIT_TENTHS"; then
      pass "-f tail-follow scenario (F-38): exited cleanly $((ELAPSED_TENTHS))/10s after SIGTERM"
   else
      fail "-f tail-follow scenario (F-38): still running ${MAX_WAIT_TENTHS}0ms after SIGTERM -- shutdown-flag regression"
      kill -9 "$PID2" 2>/dev/null
   fi
fi
rm -f "$OUT2" "$LOG2"

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
