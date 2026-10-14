#!/bin/sh
# Regression test for truncated sFlow datagrams.
#
# The offline sflow:<pcap> and live sflow:// paths must reject malformed
# datagrams without aborting the sensor or reading beyond the datagram or a
# sampled packet header. A valid sFlow v5 header sample is included to keep
# the normal parsing and sampled-packet paths covered.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="${ARGUS_BIN:-$REPO_ROOT/bin/argus}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/argus_regress_sflow.XXXXXX")"
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

def u32(value):
    return struct.pack("!I", value)

def pad(data):
    return data + (b"\x00" * ((-len(data)) % 4))

def sampled_header(protocol, header):
    # headerProtocol, sampledPacketSize, stripped, headerLen, header bytes
    return u32(protocol) + u32(len(header)) + u32(0) + u32(len(header)) + header

def flow_sample(records):
    # v5 regular flow sample body, followed by its XDR-encoded records.
    body = b"".join(u32(value) for value in (1, 0, 1, 1, 0, 0, 0, len(records)))
    for tag, record in records:
        body += u32(tag) + u32(len(record)) + pad(record)
    return u32(1) + u32(len(body)) + body

def sflow_v5(records):
    # version, IPv4 agent address, sub-agent, sequence, uptime, sample count
    datagram = u32(5) + u32(1) + b"\xc0\x00\x02\x01"
    datagram += u32(0) + u32(1) + u32(1) + u32(1)
    return datagram + flow_sample(records)

def ethernet_ipv4_udp(payload):
    ethernet = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    total_length = 20 + 8 + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 0, 0, 64, 17, 0,
        b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02",
    )
    udp = struct.pack("!HHHH", 6343, 6343, 8 + len(payload), 0)
    return ethernet + ipv4 + udp + payload

def write_pcap(name, payloads):
    with open(f"{workdir}/{name}.pcap", "wb") as output:
        # Classic little-endian pcap, version 2.4, DLT_EN10MB.
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, payload in enumerate(payloads):
            frame = ethernet_ipv4_udp(payload)
            output.write(struct.pack("<IIII", index, 0, len(frame), len(frame)))
            output.write(frame)

# Exact primitive-read repro: no complete uint32_t version field.
one_byte = b"\x05"

# The agent-address helper must not copy a truncated IPv6 address.
truncated_agent_ipv6 = u32(5) + u32(2) + (b"\x20\x01" * 4)

# Extended-user string: charset plus a declared 100-byte string with no bytes.
oversized_string = sflow_v5([(1004, u32(0) + u32(100))])

# Packet-header record declares 100 sampled-header bytes but supplies none.
truncated_header = sflow_v5([(1, u32(1) + u32(100) + u32(0) + u32(100))])

# These valid record envelopes deliberately contain undersized sampled headers.
# They reach the packet-header decoders and ArgusSflowPacket() safely.
short_ipv4_header = sflow_v5([(1, sampled_header(11, b"\x45"))])
short_ipv6_header = sflow_v5([(1, sampled_header(12, b"\x60"))])
short_ethernet_header = sflow_v5([(1, sampled_header(1, ethernet_ipv4_udp(b"")[:14]))])

valid_packet_header = ethernet_ipv4_udp(b"")
valid = sflow_v5([(1, sampled_header(1, valid_packet_header))])

for name, payload in {
    "one_byte": one_byte,
    "truncated_agent_ipv6": truncated_agent_ipv6,
    "oversized_string": oversized_string,
    "truncated_header": truncated_header,
    "short_ipv4_header": short_ipv4_header,
    "short_ipv6_header": short_ipv6_header,
    "short_ethernet_header": short_ethernet_header,
    "valid": valid,
}.items():
    write_pcap(name, [payload])

# This proves an offline source continues parsing after a malformed datagram.
write_pcap("malformed_then_valid", [oversized_string, valid])

with open(f"{workdir}/live_payloads.bin", "wb") as output:
    for payload in (one_byte, oversized_string, truncated_agent_ipv6, valid):
        output.write(struct.pack("!I", len(payload)))
        output.write(payload)
PY

check_log() {
   label="$1"
   log_path="$2"

   if grep -Eqi "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|heap-buffer-overflow|abort|SIGABRT|Segmentation" "$log_path"; then
      fail "$label logged a parser or sanitizer error (see $log_path)"
   else
      pass "$label logged no parser or sanitizer error"
   fi
}

run_offline_case() {
   label="$1"
   case_name="$2"
   expect_output="$3"
   pcap_path="$WORKDIR/$case_name.pcap"
   output_path="$WORKDIR/$case_name.argus"
   log_path="$WORKDIR/$case_name.log"

   HOME=/tmp "$ARGUS_BIN" -r "sflow:$pcap_path" -w "$output_path" -P 0 -D 0 >"$log_path" 2>&1 &
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

   check_log "$label" "$log_path"

   if [ "$expect_output" = "yes" ]; then
      if [ -s "$output_path" ]; then
         pass "$label produced an Argus record"
      else
         fail "$label did not produce an Argus record (see $log_path)"
      fi
   fi
}

run_offline_case "sFlow one-byte datagram" "one_byte" no
run_offline_case "sFlow truncated IPv6 agent address" "truncated_agent_ipv6" no
run_offline_case "sFlow oversized encoded string" "oversized_string" no
run_offline_case "sFlow truncated sampled-header record" "truncated_header" no
run_offline_case "sFlow short IPv4 sampled header" "short_ipv4_header" no
run_offline_case "sFlow short IPv6 sampled header" "short_ipv6_header" no
run_offline_case "sFlow short Ethernet sampled header" "short_ethernet_header" no
run_offline_case "sFlow valid sampled packet" "valid" yes
run_offline_case "sFlow malformed datagram followed by valid packet" "malformed_then_valid" yes

SFLOW_PORT=$((20000 + ($$ % 2000)))
LIVE_OUTPUT="$WORKDIR/live.argus"
LIVE_LOG="$WORKDIR/live.log"

HOME=/tmp "$ARGUS_BIN" -i "sflow://127.0.0.1:${SFLOW_PORT}" -w "$LIVE_OUTPUT" -P 0 -D 0 >"$LIVE_LOG" 2>&1 &
PID=$!
sleep 1

if ! kill -0 "$PID" 2>/dev/null; then
   fail "live sFlow listener exited before malformed datagrams were sent (see $LIVE_LOG)"
else
   python3 - "$SFLOW_PORT" "$WORKDIR/live_payloads.bin" <<'PY'
import socket
import struct
import sys

port = int(sys.argv[1])
payload_path = sys.argv[2]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
with open(payload_path, "rb") as source:
    while True:
        length_bytes = source.read(4)
        if not length_bytes:
            break
        length = struct.unpack("!I", length_bytes)[0]
        sock.sendto(source.read(length), ("127.0.0.1", port))
sock.close()
PY
   sleep 1

   if kill -0 "$PID" 2>/dev/null; then
      pass "live sFlow listener remained running after malformed and valid datagrams"
   else
      fail "live sFlow listener exited after malformed datagrams (see $LIVE_LOG)"
   fi
fi

if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
   kill -TERM "$PID"
   if ! wait_for_exit "$PID" 20; then
      kill -KILL "$PID" 2>/dev/null
   fi
   wait "$PID" 2>/dev/null
   PID=""
fi

check_log "live sFlow datagram handling" "$LIVE_LOG"

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
