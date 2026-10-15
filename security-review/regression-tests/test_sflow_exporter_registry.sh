#!/bin/sh
# Regression test for bounded offline sFlow exporter registration.
#
# Exporters are owned by each offline sFlow source. A configured capacity must
# retain known IPv4/IPv6 exporters while safely dropping a new exporter without
# allocating another source/model or indexing beyond the registry.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="${ARGUS_BIN:-$REPO_ROOT/bin/argus}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/argus_regress_sflow_registry.XXXXXX")"
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

cat >"$WORKDIR/argus.conf" <<'EOF'
ARGUS_HASHTABLE_SIZE=2
ARGUS_SFLOW_MAX_EXPORTERS=2
EOF

python3 - "$WORKDIR" <<'PY'
import struct
import sys

workdir = sys.argv[1]

def u32(value):
    return struct.pack("!I", value)

def pad(data):
    return data + (b"\x00" * ((-len(data)) % 4))

def sampled_header(header):
    return u32(1) + u32(len(header)) + u32(0) + u32(len(header)) + header

def flow_sample(header):
    body = b"".join(u32(value) for value in (1, 0, 1, 1, 0, 0, 0, 1))
    record = sampled_header(header)
    body += u32(1) + u32(len(record)) + pad(record)
    return u32(1) + u32(len(body)) + body

def sflow_v5(agent_type, agent, sequence, header):
    datagram = u32(5) + u32(agent_type) + agent
    datagram += u32(0) + u32(sequence) + u32(sequence) + u32(1)
    return datagram + flow_sample(header)

def ethernet_ipv4_udp(source, destination, sport, dport):
    ethernet = bytes.fromhex("0200000000020200000000010800")
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 28, 0, 0, 64, 17, 0, source, destination,
    )
    udp = struct.pack("!HHHH", sport, dport, 8, 0)
    return ethernet + ipv4 + udp

def write_pcap(name, payloads):
    with open(f"{workdir}/{name}.pcap", "wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, payload in enumerate(payloads):
            udp = struct.pack("!HHHH", 6343, 6343, 8 + len(payload), 0)
            outer_ipv4 = struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0, 20 + len(udp) + len(payload), 0, 0, 64, 17, 0,
                b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02",
            )
            packet = bytes.fromhex("0200000000020200000000010800") + outer_ipv4 + udp + payload
            # Keep realtime replay short while ensuring a nonzero prior timestamp.
            output.write(struct.pack("<IIII", 1, index * 1000, len(packet), len(packet)))
            output.write(packet)

headers = [
    ethernet_ipv4_udp(b"\x0a\x00\x00\x01", b"\x0a\x00\x01\x01", 1001, 2001),
    ethernet_ipv4_udp(b"\x0a\x00\x00\x02", b"\x0a\x00\x01\x02", 1002, 2002),
    ethernet_ipv4_udp(b"\x0a\x00\x00\x03", b"\x0a\x00\x01\x03", 1003, 2003),
    ethernet_ipv4_udp(b"\x0a\x00\x00\x04", b"\x0a\x00\x01\x04", 1004, 2004),
    ethernet_ipv4_udp(b"\x0a\x00\x00\x05", b"\x0a\x00\x01\x05", 1005, 2005),
    ethernet_ipv4_udp(b"\x0a\x00\x00\x06", b"\x0a\x00\x01\x06", 1006, 2006),
]

agent_v4 = b"\xc0\x00\x02\x0a"
agent_v6 = bytes.fromhex("20010db8000000000000000000000001")
agent_v6_peer = bytes.fromhex("20010db8000000000000000000000002")
agent_overflow = b"\xc0\x00\x02\x0b"
agent_v4_right = b"\xc0\x00\x02\x1a"
agent_v6_right = bytes.fromhex("20010db8000000000000000000000002")
agent_overflow_right = b"\xc0\x00\x02\x1b"

write_pcap("capacity", [
    sflow_v5(1, agent_v4, 1, headers[0]),
    sflow_v5(2, agent_v6, 2, headers[1]),
    sflow_v5(1, agent_overflow, 3, headers[2]),
    sflow_v5(2, agent_v6, 4, headers[3]),
])
# The IPv6 agents differ only in the final byte. Both must consume a slot.
write_pcap("ipv6_identity", [
    sflow_v5(2, agent_v6, 1, headers[0]),
    sflow_v5(2, agent_v6_peer, 2, headers[1]),
    sflow_v5(1, agent_overflow, 3, headers[2]),
    sflow_v5(2, agent_v6, 4, headers[3]),
])
write_pcap("concurrent_left", [
    sflow_v5(1, agent_v4, 1, headers[0]),
    sflow_v5(2, agent_v6, 2, headers[1]),
    sflow_v5(1, agent_overflow, 3, headers[2]),
])
write_pcap("concurrent_right", [
    sflow_v5(1, agent_v4_right, 1, headers[3]),
    sflow_v5(2, agent_v6_right, 2, headers[4]),
    sflow_v5(1, agent_overflow_right, 3, headers[5]),
])
PY

check_log() {
   label="$1"
   log_path="$2"

   if grep -Eqi "AddressSanitizer|UndefinedBehaviorSanitizer|ThreadSanitizer|runtime error:|heap-buffer-overflow|abort|SIGABRT|Segmentation" "$log_path"; then
      fail "$label logged a parser or sanitizer error (see $log_path)"
   else
      pass "$label logged no parser or sanitizer error"
   fi
}

assert_flow_tuples() {
   python3 - "$1" "$2" "$3" <<'PY'
import socket
import struct
import sys

data = open(sys.argv[1], "rb").read()

def flow_signature(spec):
    source, sport, destination, dport = spec.split(":")
    return (socket.inet_aton(source) + socket.inet_aton(destination) +
            bytes((17, 0)) + struct.pack("!HH", int(sport), int(dport)))

for spec in filter(None, sys.argv[2].split(",")):
    if data.count(flow_signature(spec)) != 1:
        print(f"missing or duplicate expected flow {spec}", file=sys.stderr)
        sys.exit(1)

for spec in filter(None, sys.argv[3].split(",")):
    if flow_signature(spec) in data:
        print(f"unexpected overflow flow {spec}", file=sys.stderr)
        sys.exit(1)
PY
}

run_case() {
   label="$1"
   input_args="$2"
   expected_limit_logs="$3"
   expected_flows="$4"
   rejected_flows="$5"
   extra_args="$6"
   output_path="$WORKDIR/$label.argus"
   log_path="$WORKDIR/$label.log"

   # shellcheck disable=SC2086
   HOME=/tmp "$ARGUS_BIN" -F "$WORKDIR/argus.conf" $extra_args -r $input_args \
      -w "$output_path" -P 0 -D 0 >"$log_path" 2>&1 &
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

   limit_logs="$(grep -Fic "sFlow exporter limit 2 reached" "$log_path" || true)"
   if [ "$limit_logs" -eq "$expected_limit_logs" ]; then
      pass "$label logged $expected_limit_logs bounded exporter rejection(s)"
   else
      fail "$label logged $limit_logs bounded exporter rejection(s); expected $expected_limit_logs (see $log_path)"
   fi

   if [ -z "$expected_flows" ]; then
      return
   elif [ ! -f "$output_path" ]; then
      fail "$label did not create an Argus output file (see $log_path)"
   elif assert_flow_tuples "$output_path" "$expected_flows" "$rejected_flows"; then
      pass "$label retained registered exporters and excluded the overflow exporter"
   else
      fail "$label did not retain exactly the expected exporter flows (see $log_path)"
   fi
}

run_case "sflow_exporter_capacity" "sflow:$WORKDIR/capacity.pcap" 1 \
    "10.0.0.1:1001:10.0.1.1:2001,10.0.0.2:1002:10.0.1.2:2002,10.0.0.4:1004:10.0.1.4:2004" \
    "10.0.0.3:1003:10.0.1.3:2003"
run_case "sflow_exporter_realtime" "sflow:$WORKDIR/capacity.pcap" 1 \
    "10.0.0.1:1001:10.0.1.1:2001,10.0.0.2:1002:10.0.1.2:2002,10.0.0.4:1004:10.0.1.4:2004" \
    "10.0.0.3:1003:10.0.1.3:2003" "-T 1"
run_case "sflow_exporter_ipv6_identity" "sflow:$WORKDIR/ipv6_identity.pcap" 1 \
    "10.0.0.1:1001:10.0.1.1:2001,10.0.0.2:1002:10.0.1.2:2002,10.0.0.4:1004:10.0.1.4:2004" \
    "10.0.0.3:1003:10.0.1.3:2003"
run_case "sflow_exporter_concurrent" "sflow:$WORKDIR/concurrent_left.pcap sflow:$WORKDIR/concurrent_right.pcap" 2 \
    "10.0.0.1:1001:10.0.1.1:2001,10.0.0.2:1002:10.0.1.2:2002,10.0.0.4:1004:10.0.1.4:2004,10.0.0.5:1005:10.0.1.5:2005" \
    "10.0.0.3:1003:10.0.1.3:2003,10.0.0.6:1006:10.0.1.6:2006"

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
