#!/bin/sh
# Runs every deterministic regression test in this directory, plus (unless
# skipped) the best-effort concurrency stress test, and prints a final
# pass/fail summary. Intended for both local use and CI
# (.github/workflows/ci.yml's "security-regression-tests" job).
#
# Usage:
#   sh security-review/regression-tests/run_all.sh
#   SKIP_STRESS_TEST=1 sh security-review/regression-tests/run_all.sh   # skip the slower stress test
#   STRESS_ITERATIONS=50 sh security-review/regression-tests/run_all.sh # more stress iterations
#
# Requires bin/argus to already be built (./configure && make -j4) before
# running the deterministic tests. The stress test builds its own separate
# scratch ASan copy and does not need bin/argus to be pre-built.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

if [ ! -x "bin/argus" ]; then
   echo "error: bin/argus not found -- run './configure && make -j4' first" >&2
   exit 2
fi

overall_rc=0
ran=0
failed=0

echo "=== Deterministic regression tests ==="
for t in "$SCRIPT_DIR"/test_*.sh; do
   [ -f "$t" ] || continue
   ran=$((ran + 1))
   echo ""
   echo "--- $(basename "$t") ---"
   if sh "$t"; then
      :
   else
      failed=$((failed + 1))
      overall_rc=1
   fi
done

if [ "${SKIP_STRESS_TEST:-0}" != "1" ]; then
   echo ""
   echo "=== Best-effort concurrency stress test (F-37/F-43/F-46) ==="
   ran=$((ran + 1))
   echo ""
   echo "--- $(basename "$SCRIPT_DIR/stress_multi_source_sll.sh") ---"
   if sh "$SCRIPT_DIR/stress_multi_source_sll.sh"; then
      :
   else
      failed=$((failed + 1))
      overall_rc=1
   fi
else
   echo ""
   echo "(SKIP_STRESS_TEST=1 set -- skipping the concurrency stress test)"
fi

echo ""
echo "=== Summary: $((ran - failed))/$ran test scripts passed ==="
exit "$overall_rc"
