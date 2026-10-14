#!/bin/sh
# Regression test for truncated ENC and NULL packet callbacks.
#
# Each generated pcap independently shortens the captured or wire length below
# the callback's fixed link header. The callbacks must reject both conditions
# before fixed-header access, pointer arithmetic, or subtraction.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="${ARGUS_BIN:-$REPO_ROOT/bin/argus}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/argus_regress_enc_null.XXXXXX")"
REGRESSION_FAIL_MARKER="$WORKDIR/fail"
PID=""

cleanup() {
   if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
      kill -TERM "$PID" 2>/dev/null
      wait_for_exit "$PID" 20 || kill -KILL "$PID" 2>/dev/null
   fi
   rm -rf "$WORKDIR"
}
trap cleanup EXIT HUP INT TERM

if [ ! -x "$ARGUS_BIN" ]; then
   echo "error: $ARGUS_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi

make_truncated_pcap() {
   pcap_path="$1"
   dlt="$2"
   captured_length="$3"
   wire_length="$4"

   python3 - "$pcap_path" "$dlt" "$captured_length" "$wire_length" <<'PY'
import struct
import sys

path, dlt, captured_length, wire_length = sys.argv[1:]
captured_length = int(captured_length)
with open(path, "wb") as output:
    # Classic little-endian pcap, version 2.4.
    output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, int(dlt)))
    output.write(struct.pack("<IIII", 0, 0, captured_length, int(wire_length)))
    output.write(b"\x00" * captured_length)
PY
}

run_case() {
   label="$1"
   pcap_path="$2"
   case_name="$3"
   output_path="$WORKDIR/$case_name.argus"
   log_path="$WORKDIR/$case_name.log"

   HOME=/tmp "$ARGUS_BIN" -r "$pcap_path" -w "$output_path" -P 0 -D 0 >"$log_path" 2>&1 &
   PID=$!

   if wait_for_exit "$PID" 50; then
      if wait "$PID"; then
         pass "$label exited cleanly"
      else
         fail "$label exited non-zero (see $log_path)"
      fi
      PID=""
   else
      fail "$label did not exit within five seconds (see $log_path)"
      kill -TERM "$PID" 2>/dev/null
      wait_for_exit "$PID" 20 || kill -KILL "$PID" 2>/dev/null
      wait "$PID" 2>/dev/null
      PID=""
   fi

   if grep -qi "AddressSanitizer\|runtime error\|ArgusFree: buffer error\|abort\|SIGABRT\|Segmentation" "$log_path"; then
      fail "$label logged a parser or sanitizer error (see $log_path)"
   else
      pass "$label logged no parser or sanitizer error"
   fi

   if grep -qi "unsupported device type" "$log_path"; then
      fail "$label did not reach its packet callback (see $log_path)"
   else
      pass "$label reached a supported packet callback"
   fi
}

# `include/net/dlt.h` uses DLT_ENC=13 on OpenBSD and 109 elsewhere.
case "$(uname -s)" in
   OpenBSD) ENC_DLT=13 ;;
   *)       ENC_DLT=109 ;;
esac

# NULL=0 on all supported platforms; its header is four bytes. ENC is 12.
make_truncated_pcap "$WORKDIR/enc_capture.pcap" "$ENC_DLT" 1 64
make_truncated_pcap "$WORKDIR/enc_wire.pcap" "$ENC_DLT" 12 1
make_truncated_pcap "$WORKDIR/null_capture.pcap" 0 1 64
make_truncated_pcap "$WORKDIR/null_wire.pcap" 0 4 1

run_case "ENC short capture" "$WORKDIR/enc_capture.pcap" "enc_capture"
run_case "ENC short wire length" "$WORKDIR/enc_wire.pcap" "enc_wire"
run_case "NULL short capture" "$WORKDIR/null_capture.pcap" "null_capture"
run_case "NULL short wire length" "$WORKDIR/null_wire.pcap" "null_wire"

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
