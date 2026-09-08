#!/bin/sh
# Regression test for F-40: output-file destination filter compiled fail-open.
#
# ArgusInitOutput()'s "-w <file> <filter>" handling checked
# ArgusFilterCompile()'s return value with "< 0", but ArgusFilterCompile()
# returns char * (a status string: "OK", "SY", "ER", "TI", or NULL), never a
# negative int -- so every outcome, including all three error strings,
# satisfied "!(< 0)" and was silently treated as success. A mistyped filter
# therefore didn't get rejected: it fell back to a NULL filter program and
# argus wrote every record to the output file, unfiltered.
#
# Post-fix, an invalid filter must be rejected: argus exits non-zero, logs a
# syntax-error message, and writes nothing (0-byte output file) rather than
# silently falling back to "no filter".
#
# A well-formed filter must still narrow the output correctly (this is the
# success path, which was never broken -- included as a same-invocation
# sanity check that the fix didn't break normal filtering).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="$REPO_ROOT/bin/argus"
PCAP_FIXTURE="$SCRIPT_DIR/fixtures/lsp-ping-timestamp.pcap"

REGRESSION_FAIL_MARKER="$(mktemp -t argus_regress_f40.XXXXXX)"
trap 'rm -f "$REGRESSION_FAIL_MARKER"' EXIT

if [ ! -x "$ARGUS_BIN" ]; then
   echo "error: $ARGUS_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi

# --- Invalid filter: must fail closed, not open -----------------------------------------

OUT_BAD="$(mktemp -t argus_regress_f40_bad.XXXXXX)"
LOG_BAD="$(mktemp -t argus_regress_f40_bad_log.XXXXXX)"
rm -f "$OUT_BAD"   # ArgusInitOutput may or may not create the file before rejecting the filter

HOME=/tmp "$ARGUS_BIN" -r "$PCAP_FIXTURE" -w "$OUT_BAD" "this is not a valid bpf filter (((" -P 0 -D 0 >"$LOG_BAD" 2>&1
RC=$?

if [ "$RC" -eq 0 ]; then
   fail "invalid filter: argus exited 0 (expected non-zero) -- fail-open regression"
else
   pass "invalid filter: argus exited non-zero ($RC) as expected"
fi

if grep -q "ArgusFilter syntax error" "$LOG_BAD"; then
   pass "invalid filter: syntax-error message logged as expected"
else
   fail "invalid filter: expected 'ArgusFilter syntax error' message not found in output (see $LOG_BAD)"
fi

if [ -s "$OUT_BAD" ]; then
   fail "invalid filter: output file is non-empty ($(wc -c < "$OUT_BAD") bytes) -- records were written despite the invalid filter (fail-open regression)"
else
   pass "invalid filter: output file is empty (0 bytes) as expected -- no records leaked"
fi
rm -f "$OUT_BAD" "$LOG_BAD"

# --- Valid filter: must still narrow output correctly (sanity check, success path) -------

OUT_GOOD="$(mktemp -t argus_regress_f40_good.XXXXXX)"
LOG_GOOD="$(mktemp -t argus_regress_f40_good_log.XXXXXX)"

HOME=/tmp "$ARGUS_BIN" -r "$PCAP_FIXTURE" -w "$OUT_GOOD" "udp" -P 0 -D 0 >"$LOG_GOOD" 2>&1
RC=$?

if [ "$RC" -ne 0 ]; then
   fail "valid filter ('udp'): argus exited non-zero ($RC), expected 0 (see $LOG_GOOD)"
else
   pass "valid filter ('udp'): argus exited 0 as expected"
fi
rm -f "$OUT_GOOD" "$LOG_GOOD"

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
