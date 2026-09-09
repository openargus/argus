#!/bin/sh
# Best-effort stress/race regression test for F-37, F-43, and F-46.
#
# F-37: DLT_LINUX_SLL ("Linux cooked capture") packet-dispatch bounds bugs
#   in ArgusSllPacket().
# F-43: a single process-wide global scratch buffer (ArgusSllPkt) used by
#   ArgusSllPacket() to synthesize a fake Ethernet header, written by every
#   concurrent SLL-capturing source's own capture thread with no
#   synchronization -- an unsynchronized data race across threads.
# F-46: the global allocation-tracking mutex (memory.lock, common/argus_util.c)
#   was never pthread_mutex_init()'d, so ArgusMalloc/ArgusCalloc/ArgusFree's
#   locking around a shared allocation-tracking list provided no actual
#   mutual exclusion -- corrupting that list, and from there the heap
#   allocator's own metadata, across concurrent per-source threads.
#
# All three bugs are concurrency-dependent: they require multiple SLL-
# capturing source threads running at the same time to have any chance of
# manifesting, and even then only did so intermittently during the
# original investigation (the F-46 writeup reports roughly 1-in-3 failure
# runs pre-fix, dropping to 1-in-100 post-fix for an unrelated residual
# anomaly). This is fundamentally different from the other regression
# tests in this directory, which reproduce a deterministic bug on every
# run: a clean run here does NOT prove the underlying race is still fixed,
# it only fails to demonstrate a regression on this run. Treat a pass here
# as "no regression detected in N iterations", not as a guarantee.
#
# This script builds a scratch, ASan/UBSan-instrumented copy of the real
# multi-threaded bin/argus (NOT the fuzz_process_packet harness, which has
# no real pthread concurrency) in a temp directory, then runs it against
# every DLT_LINUX_SLL pcap fixture in this directory simultaneously (as
# "-r file1 file2 ... fileN", which argus opens as independent concurrent
# per-source capture threads) for several iterations, checking each run's
# output for any ASan/UBSan error report.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

REGRESSION_FAIL_MARKER="$(mktemp -t argus_regress_stress.XXXXXX)"
trap 'rm -f "$REGRESSION_FAIL_MARKER"' EXIT

ITERATIONS="${STRESS_ITERATIONS:-20}"

SLL_FIXTURES="$SCRIPT_DIR/fixtures/babel.pcap \
$SCRIPT_DIR/fixtures/bgp-infinite-loop.pcap \
$SCRIPT_DIR/fixtures/forces1.pcap \
$SCRIPT_DIR/fixtures/icmp-cksum-oobr-1.pcap \
$SCRIPT_DIR/fixtures/isis-infinite-loop.pcap \
$SCRIPT_DIR/fixtures/ldp-infinite-loop.pcap \
$SCRIPT_DIR/fixtures/lsp-ping-timestamp.pcap \
$SCRIPT_DIR/fixtures/mptcp-aa-echo.pcap"

for f in $SLL_FIXTURES; do
   if [ ! -f "$f" ]; then
      echo "error: fixture $f not found" >&2
      exit 2
   fi
done

BUILD_DIR="$(mktemp -d -t argus_regress_stress_build.XXXXXX)"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "Building scratch ASan/UBSan bin/argus in $BUILD_DIR (this takes a few seconds)..."
cp -R "$REPO_ROOT/." "$BUILD_DIR/src" 2>/dev/null
cd "$BUILD_DIR/src"
make distclean >/dev/null 2>&1

if ! CC=clang \
   CFLAGS="-fsanitize=address,undefined -fno-sanitize=alignment -fno-sanitize-recover=all -g -O1" \
   LDFLAGS="-fsanitize=address,undefined" \
   ./configure >"$BUILD_DIR/configure.log" 2>&1; then
   echo "error: ASan configure failed -- see $BUILD_DIR/configure.log" >&2
   exit 2
fi

if ! make -j4 >"$BUILD_DIR/build.log" 2>&1; then
   echo "error: ASan build failed -- see $BUILD_DIR/build.log" >&2
   exit 2
fi

ASAN_ARGUS="$BUILD_DIR/src/bin/argus"
if [ ! -x "$ASAN_ARGUS" ]; then
   echo "error: expected ASan binary not found at $ASAN_ARGUS" >&2
   exit 2
fi

echo "Running $ITERATIONS iterations of an $(echo $SLL_FIXTURES | wc -w | tr -d ' ')-source concurrent SLL playback..."

crash_count=0
for i in $(seq 1 "$ITERATIONS"); do
   OUT="$(mktemp -t argus_regress_stress_out.XXXXXX)"
   LOG="$(mktemp -t argus_regress_stress_log.XXXXXX)"

   HOME=/tmp "$ASAN_ARGUS" -r $SLL_FIXTURES -w "$OUT" -P 0 -D 0 >"$LOG" 2>&1
   RC=$?

   if [ "$RC" -ne 0 ] || grep -qE "ERROR: AddressSanitizer|ERROR: UndefinedBehaviorSanitizer|runtime error:|SUMMARY: (Address|Undefined)Sanitizer" "$LOG"; then
      crash_count=$((crash_count + 1))
      echo "  iteration $i: FAILURE (exit $RC) -- log saved at $LOG"
      cat "$LOG"
   else
      rm -f "$LOG"
   fi
   rm -f "$OUT"
done

if [ "$crash_count" -gt 0 ]; then
   fail "$crash_count/$ITERATIONS iterations crashed or reported an ASan/UBSan error -- possible F-37/F-43/F-46 regression"
else
   pass "$ITERATIONS/$ITERATIONS iterations completed cleanly, no ASan/UBSan errors (best-effort race check -- see this script's header comment)"
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
