#!/bin/sh
# Regression test for malformed ERF/DAG records.
#
# The raw .erf input path must validate the fixed record length before reading
# its payload, then reject short Ethernet, PPP, and CHDLC framing before any
# header access or length subtraction. Complete records must retain parsing.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="${ARGUS_BIN:-$REPO_ROOT/bin/argus}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/argus_regress_erf.XXXXXX")"
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

TYPE_HDLC_POS = 1
TYPE_ETH = 2
TYPE_PAD = 48
DAG_REC_SIZE = 16

def erf_record(record_type, payload=b"", wire_length=None, record_length=None,
               timestamp=0):
    if wire_length is None:
        wire_length = len(payload)
    if record_length is None:
        record_length = DAG_REC_SIZE + len(payload)
    # ERF timestamps are little-endian; record and wire lengths are big-endian.
    return (struct.pack("<Q", timestamp) +
            struct.pack("!BBHHH", record_type, 0, record_length, 0, wire_length) +
            payload)

def write_erf(name, records):
    with open(f"{workdir}/{name}.erf", "wb") as output:
        for record in records:
            output.write(record)

def write_pcap(name, frame):
    with open(f"{workdir}/{name}", "wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        output.write(struct.pack("<IIII", 1, 0, len(frame), len(frame)))
        output.write(frame)

ipv4_udp = bytes.fromhex("4500001c0000000040110000c0000201c0000202")
ipv4_udp += bytes.fromhex("04d2005000080000")
ethernet = bytes.fromhex("0200000000020200000000010800") + ipv4_udp
ppp = bytes.fromhex("ff030021") + ipv4_udp
chdlc = bytes.fromhex("0f000800") + ipv4_udp
ipv4_udp_second = bytes.fromhex("4500001c0000000040110000c0000203c0000204")
ipv4_udp_second += bytes.fromhex("162e003500080000")
ethernet_second = bytes.fromhex("0200000000040200000000030800") + ipv4_udp_second

valid_eth = erf_record(TYPE_ETH, b"\x00\x00" + ethernet, len(ethernet),
                       timestamp=0x0000000100000000)
valid_ppp = erf_record(TYPE_HDLC_POS, ppp)
valid_chdlc = erf_record(TYPE_HDLC_POS, chdlc)
padded_eth = erf_record(TYPE_ETH, b"\x00\x00" + ethernet + bytes(16), len(ethernet))
valid_eth_second = erf_record(TYPE_ETH, b"\x00\x00" + ethernet_second, len(ethernet_second))

write_erf("rlen_zero", [erf_record(TYPE_ETH, record_length=0)])
write_erf("rlen_short", [erf_record(TYPE_ETH, record_length=DAG_REC_SIZE - 1)])
write_erf("empty_pad", [erf_record(TYPE_PAD, record_length=DAG_REC_SIZE, wire_length=0)])
write_erf("empty_record", [erf_record(TYPE_ETH, record_length=DAG_REC_SIZE)])
write_erf("truncated_payload", [erf_record(TYPE_ETH, record_length=DAG_REC_SIZE + 1)])
write_erf("eth_short_subheader", [erf_record(TYPE_ETH, b"\x00", len(ethernet))])
write_erf("eth_short_frame", [erf_record(TYPE_ETH, b"\x00\x00", len(ethernet))])
write_erf("eth_short_capture", [erf_record(TYPE_ETH, b"\x00\x00" + ethernet[:13], len(ethernet))])
write_erf("hdlc_one_byte", [erf_record(TYPE_HDLC_POS, b"\xff", len(ppp))])
write_erf("ppp_address_control_only", [erf_record(TYPE_HDLC_POS, b"\xff\x03", len(ppp))])
write_erf("ppp_short_protocol", [erf_record(TYPE_HDLC_POS, b"\xff\x03\x00", len(ppp))])
write_erf("chdlc_short_header", [erf_record(TYPE_HDLC_POS, b"\x0f\x00\x08", len(chdlc))])
write_erf("valid_eth", [valid_eth])
write_erf("valid_ppp", [valid_ppp])
write_erf("valid_chdlc", [valid_chdlc])
write_erf("padded_eth", [padded_eth])
write_erf("malformed_then_valid", [erf_record(TYPE_ETH, b"\x00", len(ethernet)), valid_eth])
write_erf("multi_first", [valid_eth])
write_erf("multi_second", [valid_eth_second])
write_pcap("valid_name.erf.pcap", ethernet)
PY

check_log() {
   label="$1"
   log_path="$2"
   input_kind="$3"

   if grep -Eqi "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|heap-buffer-overflow|abort|SIGABRT|Segmentation" "$log_path"; then
      fail "$label logged a parser or sanitizer error (see $log_path)"
   else
      pass "$label logged no parser or sanitizer error"
   fi

   if [ "$input_kind" = "erf" ] && grep -qi "unknown packet file format\|unsupported device type" "$log_path"; then
      fail "$label did not reach the ERF/DAG input path (see $log_path)"
   elif [ "$input_kind" = "erf" ]; then
      pass "$label reached the ERF/DAG input path"
   fi
}

has_flow_records() {
   python3 - "$1" "$2" <<'PY'
import struct
import sys

data = open(sys.argv[1], "rb").read()
required = int(sys.argv[2])
offset = 0
count = 0
while offset + 4 <= len(data):
    length_be = struct.unpack("!H", data[offset + 2:offset + 4])[0]
    length_le = struct.unpack("<H", data[offset + 2:offset + 4])[0]
    length = next((value for value in (length_be, length_le)
                   if value and value * 4 <= len(data) - offset), 0)
    if not length:
        break
    if data[offset] & 0xF0 in (0x10, 0x30, 0x50):
        count += 1
    offset += length * 4
sys.exit(0 if count >= required else 1)
PY
}

run_case() {
   label="$1"
   case_name="$2"
   expect_output="$3"
   expected_log="$4"
   erf_path="$WORKDIR/$case_name.erf"
   output_path="$WORKDIR/$case_name.argus"
   log_path="$WORKDIR/$case_name.log"

   HOME=/tmp "$ARGUS_BIN" -r "$erf_path" -w "$output_path" -P 0 -D 0 >"$log_path" 2>&1 &
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

   check_log "$label" "$log_path" erf

   if [ -n "$expected_log" ]; then
      if grep -Fqi "$expected_log" "$log_path"; then
         pass "$label logged the expected rejection"
      else
         fail "$label did not log the expected rejection (see $log_path)"
      fi
   fi

   if [ ! -f "$output_path" ]; then
      fail "$label did not create an Argus output file (see $log_path)"
      return
   fi

   if [ "$expect_output" = "yes" ]; then
      if has_flow_records "$output_path" 1; then
         pass "$label produced an Argus flow record"
      else
         fail "$label did not produce an Argus flow record (see $log_path)"
      fi
   elif has_flow_records "$output_path" 1; then
      fail "$label produced an Argus flow record for rejected input (see $log_path)"
   else
      pass "$label produced no Argus flow record"
   fi
}

run_multi_raw_case() {
   output_path="$WORKDIR/multi_raw.argus"
   log_path="$WORKDIR/multi_raw.log"

   HOME=/tmp "$ARGUS_BIN" -r "$WORKDIR/multi_first.erf" "$WORKDIR/multi_second.erf" \
      -w "$output_path" -P 0 -D 0 >"$log_path" 2>&1 &
   PID=$!

   if wait_for_exit "$PID" 50; then
      if wait "$PID"; then
         pass "multiple ERF inputs exited cleanly"
      else
         fail "multiple ERF inputs exited non-zero (see $log_path)"
      fi
      PID=""
   else
      fail "multiple ERF inputs did not exit within five seconds (see $log_path)"
      kill -TERM "$PID" 2>/dev/null
      wait_for_exit "$PID" 20 || kill -KILL "$PID" 2>/dev/null
      wait "$PID" 2>/dev/null
      PID=""
   fi

   check_log "multiple ERF inputs" "$log_path" erf

   if [ ! -f "$output_path" ]; then
      fail "multiple ERF inputs did not create an Argus output file (see $log_path)"
   elif has_flow_records "$output_path" 2; then
      pass "multiple ERF inputs produced flow records from both files"
   else
      fail "multiple ERF inputs did not produce flow records from both files (see $log_path)"
   fi
}

run_pcap_extension_case() {
   input_path="$WORKDIR/valid_name.erf.pcap"
   output_path="$WORKDIR/valid_name.erf.pcap.argus"
   log_path="$WORKDIR/valid_name.erf.pcap.log"

   HOME=/tmp "$ARGUS_BIN" -r "$input_path" -w "$output_path" -P 0 -D 0 >"$log_path" 2>&1 &
   PID=$!

   if wait_for_exit "$PID" 50; then
      if wait "$PID"; then
         pass "pcap filename containing .erf exited cleanly"
      else
         fail "pcap filename containing .erf exited non-zero (see $log_path)"
      fi
      PID=""
   else
      fail "pcap filename containing .erf did not exit within five seconds (see $log_path)"
      kill -TERM "$PID" 2>/dev/null
      wait_for_exit "$PID" 20 || kill -KILL "$PID" 2>/dev/null
      wait "$PID" 2>/dev/null
      PID=""
   fi

   check_log "pcap filename containing .erf" "$log_path" pcap

   if [ ! -f "$output_path" ]; then
      fail "pcap filename containing .erf did not create an Argus output file (see $log_path)"
   elif has_flow_records "$output_path" 1; then
      pass "pcap filename containing .erf retained libpcap processing"
   else
      fail "pcap filename containing .erf did not produce an Argus flow record (see $log_path)"
   fi
}

run_case "ERF zero record length" "rlen_zero" no "invalid ERF record length"
run_case "ERF short record length" "rlen_short" no "invalid ERF record length"
run_case "ERF empty PAD record" "empty_pad" no ""
run_case "ERF empty non-PAD record" "empty_record" no "invalid empty ERF record"
run_case "ERF truncated payload" "truncated_payload" no "truncated ERF payload"
run_case "ERF short Ethernet subheader" "eth_short_subheader" no ""
run_case "ERF short Ethernet frame" "eth_short_frame" no ""
run_case "ERF short captured Ethernet frame" "eth_short_capture" no ""
run_case "ERF one-byte HDLC frame" "hdlc_one_byte" no ""
run_case "ERF PPP address/control only" "ppp_address_control_only" no ""
run_case "ERF PPP short protocol" "ppp_short_protocol" no ""
run_case "ERF short CHDLC header" "chdlc_short_header" no ""
run_case "ERF valid Ethernet frame" "valid_eth" yes ""
run_case "ERF valid PPP frame" "valid_ppp" yes ""
run_case "ERF valid CHDLC frame" "valid_chdlc" yes ""
run_case "ERF padded Ethernet capture" "padded_eth" yes ""
run_case "ERF malformed frame followed by valid Ethernet" "malformed_then_valid" yes ""
run_multi_raw_case
run_pcap_extension_case

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
