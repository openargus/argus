#!/bin/sh
# Regression test for FDDI conversion bounds.
#
# FDDI frames are converted into Ethernet frames before model processing. The
# conversion must reject short or internally inconsistent captures before
# reading FDDI/LLC fields, and copy only captured payload into its fixed buffer.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="${ARGUS_BIN:-$REPO_ROOT/bin/argus}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/argus_regress_fddi.XXXXXX")"
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

python3 - "$WORKDIR" <<'PY'
import struct
import sys

workdir = sys.argv[1]
snaplen = 65543

def write_pcap(name, data, wire_length):
    with open(f"{workdir}/{name}.pcap", "wb") as output:
        # Classic little-endian pcap, version 2.4, DLT_FDDI=10.
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 10))
        output.write(struct.pack("<IIII", 0, 0, len(data), wire_length))
        output.write(data)

def fddi_snap(payload=b""):
    # FDDI FC, destination/source addresses, SNAP LLC, and IPv4 EtherType.
    return b"\x50" + b"\x01\x02\x03\x04\x05\x06" + b"\x07\x08\x09\x0a\x0b\x0c" + b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + payload

write_pcap("short_capture", b"\x50", 64)
write_pcap("short_header", fddi_snap()[:-1], 64)
write_pcap("truncated_payload", fddi_snap(), 64)
write_pcap("short_wire", fddi_snap(), 20)
write_pcap("oversized_capture", fddi_snap(b"\x00" * (65543 - len(fddi_snap()))), 65543)

ipv4_udp = bytes.fromhex("4500001c0000000040110000c0000201c0000202") + bytes.fromhex("04d2005000080000")
write_pcap("valid_ipv4", fddi_snap(ipv4_udp), len(fddi_snap(ipv4_udp)))
PY

run_case() {
   label="$1"
   case_name="$2"
   expect_output="$3"
   pcap_path="$WORKDIR/$case_name.pcap"
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
      fail "$label did not reach the FDDI packet callback (see $log_path)"
   else
      pass "$label reached a supported FDDI packet callback"
   fi

   if [ "$expect_output" = "yes" ]; then
      if [ -s "$output_path" ]; then
         pass "$label produced an Argus record"
      else
         fail "$label did not produce an Argus record (see $log_path)"
      fi
   fi
}

run_case "FDDI short capture" "short_capture" no
run_case "FDDI short FDDI/LLC header" "short_header" no
run_case "FDDI truncated payload" "truncated_payload" no
run_case "FDDI short wire length" "short_wire" no
run_case "FDDI oversized converted capture" "oversized_capture" no
run_case "FDDI valid IPv4 frame" "valid_ipv4" yes

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
