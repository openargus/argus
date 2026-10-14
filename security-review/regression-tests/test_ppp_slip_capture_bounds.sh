#!/bin/sh
# Regression test for truncated PPP, PPP/BSDOS, and SLIP packet callbacks.
#
# Each generated pcap contains one captured byte with a larger wire length.
# The callbacks must reject it before forming an inner-header pointer or
# reading a PPP/BSDOS protocol field.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="${ARGUS_BIN:-$REPO_ROOT/bin/argus}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/argus_regress_ppp_slip.XXXXXX")"
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
   wire_length="$3"
   packet_byte="${4:-0}"

   python3 - "$pcap_path" "$dlt" "$wire_length" "$packet_byte" <<'PY'
import struct
import sys

path, dlt, wire_length, packet_byte = sys.argv[1:]
with open(path, "wb") as output:
    # Classic little-endian pcap, version 2.4, one byte captured.
    output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, int(dlt)))
    output.write(struct.pack("<IIII", 0, 0, 1, int(wire_length)))
    output.write(bytes([int(packet_byte, 0)]))
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
         pass "$label capture exited cleanly"
      else
         fail "$label capture exited non-zero (see $log_path)"
      fi
      PID=""
   else
      fail "$label capture did not exit within five seconds (see $log_path)"
      kill -TERM "$PID" 2>/dev/null
      wait_for_exit "$PID" 20 || kill -KILL "$PID" 2>/dev/null
      wait "$PID" 2>/dev/null
      PID=""
   fi

   if grep -qi "AddressSanitizer\|runtime error\|ArgusFree: buffer error\|abort\|SIGABRT\|Segmentation" "$log_path"; then
      fail "$label capture logged a parser or sanitizer error (see $log_path)"
   else
      pass "$label capture logged no parser or sanitizer error"
   fi

   if grep -qi "unsupported device type" "$log_path"; then
      fail "$label capture did not reach its packet callback (see $log_path)"
   else
      pass "$label capture reached a supported packet callback"
   fi
}

# `include/net/dlt.h` uses a distinct PPP/BSDOS value on FreeBSD and NetBSD.
case "$(uname -s)" in
   FreeBSD|NetBSD) PPP_BSDOS_DLT=14 ;;
   *)              PPP_BSDOS_DLT=16 ;;
esac

# SLIP=8 and PPP=9 on all supported platforms.
make_truncated_pcap "$WORKDIR/ppp.pcap" 9 64
make_truncated_pcap "$WORKDIR/ppp_bsdos.pcap" "$PPP_BSDOS_DLT" 1
make_truncated_pcap "$WORKDIR/ppp_bsdos_address.pcap" "$PPP_BSDOS_DLT" 2 0xff
make_truncated_pcap "$WORKDIR/slip.pcap" 8 64

run_case "PPP" "$WORKDIR/ppp.pcap" "ppp"
run_case "PPP/BSDOS" "$WORKDIR/ppp_bsdos.pcap" "ppp_bsdos"
run_case "PPP/BSDOS address/control" "$WORKDIR/ppp_bsdos_address.pcap" "ppp_bsdos_address"
run_case "SLIP" "$WORKDIR/slip.pcap" "slip"

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
