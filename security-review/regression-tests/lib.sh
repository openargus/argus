#!/bin/sh
# Shared helpers for security-review/regression-tests scripts.
#
# Each test_*.sh script sources this file, then calls the helper functions
# below. Keeping this logic in one place avoids each test re-implementing
# its own (easy to get subtly wrong) process-wait/timeout loop.

# wait_for_exit PID MAX_TENTHS
#   Polls every 0.1s (up to MAX_TENTHS tenths of a second) for PID to exit.
#   Sets ELAPSED_TENTHS to the number of 0.1s ticks actually waited.
#   Returns 0 if the process exited on its own, 1 if it was still running
#   when MAX_TENTHS was reached (caller is responsible for force-killing it
#   in that case -- this function does not kill anything itself).
wait_for_exit() {
   pid="$1"
   max_tenths="$2"
   i=0
   while [ "$i" -lt "$max_tenths" ]; do
      if ! kill -0 "$pid" 2>/dev/null; then
         ELAPSED_TENTHS="$i"
         return 0
      fi
      sleep 0.1
      i=$((i + 1))
   done
   ELAPSED_TENTHS="$max_tenths"
   return 1
}

# pass MESSAGE
pass() {
   echo "PASS: $1"
}

# fail MESSAGE
#   Prints a FAIL line and records the failure by writing to $REGRESSION_FAIL_MARKER
#   (a scratch file the caller created) rather than exiting immediately, so a single
#   test script can report every check it performed, not just the first failure.
#   The marker file must end up non-empty (checked via "[ -s ... ]" by callers) --
#   write a byte into it, don't truncate it to empty.
fail() {
   echo "FAIL: $1"
   echo "1" >> "${REGRESSION_FAIL_MARKER:?REGRESSION_FAIL_MARKER not set by caller}"
}
