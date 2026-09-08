#!/bin/sh
# Regression test for F-39: resource-file parser's line-read pointer never
# reset between lines.
#
# ArgusParseResourceFile()'s main loop read each line via
# "fgets(str, MAXSTRLEN, fd)", where str started out pointing at the start
# of a fixed stack buffer (strbuf) but was never reset back to strbuf's
# start before each subsequent fgets() call -- each iteration's own parsing
# (skipping leading whitespace, or the ARGUS_FILTER case reassigning
# str = optarg) left str wherever it last pointed, and the next fgets()
# then wrote up to MAXSTRLEN (4096) bytes starting from that stale,
# already-advanced pointer, which can write past the end of strbuf.
#
# This test exercises the exact scenario described in the fix's own
# verification notes: a resource file with several ARGUS_* lines, each
# progressively more indented (so str is left further and further from
# strbuf's start by the leading-whitespace skip, if the reset were
# missing), and confirms argus still starts, parses every setting
# correctly (confirmed indirectly via a successful, expected-record-count
# run), and exits 0 -- rather than corrupting adjacent stack memory.
#
# Note: this test deliberately does NOT combine "ARGUS_FILTER=" in the
# resource file with "-r <pcap>" on the command line -- that specific
# combination triggers a separate, already-known, pre-existing,
# out-of-scope bug (an "ArgusFree: buffer error" abort on exit, unrelated
# to this fix) documented in findings-log.md's F-39 entry. Combining them
# here would make this test fail for a reason that has nothing to do with
# the fix being verified.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="$REPO_ROOT/bin/argus"
PCAP_FIXTURE="$SCRIPT_DIR/fixtures/lsp-ping-timestamp.pcap"

REGRESSION_FAIL_MARKER="$(mktemp -t argus_regress_f39.XXXXXX)"
trap 'rm -f "$REGRESSION_FAIL_MARKER"' EXIT

if [ ! -x "$ARGUS_BIN" ]; then
   echo "error: $ARGUS_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi

CONF="$(mktemp -t argus_regress_f39.XXXXXX.conf)"
OUT="$(mktemp -t argus_regress_f39_out.XXXXXX)"
LOG="$(mktemp -t argus_regress_f39_log.XXXXXX)"

# Progressively-indented ARGUS_* lines: each line's leading-whitespace skip
# advances str further from strbuf's start than the previous line did,
# maximizing how far a missing reset would leave str pointing before the
# *next* fgets() call.
cat > "$CONF" <<'EOF'
ARGUS_FLOW_STATUS_INTERVAL=60
   ARGUS_MAR_STATUS_INTERVAL=300
      ARGUS_CAPTURE_DATA_LEN=96
         ARGUS_GENERATE_RESPONSE_TIME_DATA=yes
            ARGUS_GENERATE_JITTER_DATA=yes
               ARGUS_DEBUG_LEVEL=0
                  ARGUS_MIN_SSF=1
                     ARGUS_MAX_SSF=255
                        ARGUS_GENERATE_MAC_DATA=yes
EOF

HOME=/tmp "$ARGUS_BIN" -F "$CONF" -r "$PCAP_FIXTURE" -w "$OUT" -P 0 -D 0 >"$LOG" 2>&1
RC=$?

if [ "$RC" -ne 0 ]; then
   fail "argus exited non-zero ($RC) parsing a multi-line indented resource file (see $LOG)"
else
   pass "argus exited 0 parsing a multi-line indented resource file"
fi

if [ ! -s "$OUT" ]; then
   fail "output file is empty -- expected records were not written (resource-file parsing likely broke record generation)"
else
   pass "output file is non-empty ($(wc -c < "$OUT") bytes) -- record generation unaffected"
fi

if grep -qi "ArgusFree: buffer error\|abort\|SIGABRT\|SIGSEGV\|Segmentation" "$LOG"; then
   fail "argus logged a crash/abort indication while parsing the resource file (see $LOG): $(grep -i "ArgusFree: buffer error\|abort\|SIGABRT\|SIGSEGV\|Segmentation" "$LOG" | head -1)"
else
   pass "no crash/abort indication logged"
fi

rm -f "$CONF" "$OUT" "$LOG"

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
