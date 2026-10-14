#!/bin/sh
# Regression test for malformed Cisco NetFlow datagrams.
#
# The offline cisco:<pcap> path must reject truncated version headers, fixed
# records, and NetFlow v9 FlowSets/templates without reading beyond a UDP
# datagram. Valid v5 and v9 records retain the supported parsing paths.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="${ARGUS_BIN:-$REPO_ROOT/bin/argus}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/argus_regress_netflow.XXXXXX")"
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

def ethernet_ipv4_udp(payload, udp_length=None,
                      source=b"\xc0\x00\x02\x01", destination=b"\xc0\x00\x02\x02"):
    ethernet = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    total_length = 20 + 8 + len(payload)
    if udp_length is None:
        udp_length = 8 + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 0, 0, 64, 17, 0,
        source, destination,
    )
    udp = struct.pack("!HHHH", 2055, 2055, udp_length, 0)
    return ethernet + ipv4 + udp + payload

def ethernet_ipv6_udp(payload, source, destination, udp_length=None):
    ethernet = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x86\xdd"
    if udp_length is None:
        udp_length = 8 + len(payload)
    ipv6 = struct.pack("!IHBB16s16s", 0x60000000, 8 + len(payload), 17, 64,
                       source, destination)
    udp = struct.pack("!HHHH", 2055, 2055, udp_length, 0)
    return ethernet + ipv6 + udp + payload

def write_pcap_frames(name, frames):
    with open(f"{workdir}/{name}.pcap", "wb") as output:
        # Classic little-endian pcap, version 2.4, DLT_EN10MB.
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for index, item in enumerate(frames):
            if isinstance(item, tuple):
                frame, timestamp = item
            else:
                frame, timestamp = item, index
            output.write(struct.pack("<IIII", timestamp, 0, len(frame), len(frame)))
            output.write(frame)

def write_pcap(name, payloads):
    frames = []
    for packet in payloads:
        if isinstance(packet, tuple):
            payload, udp_length = packet
        else:
            payload, udp_length = packet, None
        frames.append(ethernet_ipv4_udp(payload, udp_length))
    write_pcap_frames(name, frames)

def v1_header(count):
    return struct.pack("!HHIII", 1, count, 1000, 1700000000, 0)

def v5_header(count):
    return struct.pack("!HHIIIIBBH", 5, count, 1000, 1700000000, 0, 1, 0, 0, 0)

def v6_header(count):
    return struct.pack("!HHIIIIBBH", 6, count, 1000, 1700000000, 0, 1, 0, 0, 0)

def v7_header(count):
    return struct.pack("!HHIIIII", 7, count, 1000, 1700000000, 0, 1, 0)

def v8_header(count):
    return struct.pack("!HHIIIIBBBBI", 8, count, 1000, 1700000000, 0, 1, 0, 0, 0, 0, 0)

def v9_header(count, source_id=1):
    return struct.pack("!HHIIII", 9, count, 1000, 1700000000, 1, source_id)

def flowset(flowset_id, body, length=None):
    if length is None:
        length = 4 + len(body)
    return struct.pack("!HH", flowset_id, length) + body

v1_entry = bytes(48)
v5_entry = struct.pack(
    "!IIIHHIIIIHHBBBBHHBBH",
    0xC0000201, 0xC0000202, 0, 1, 2, 1, 60, 100, 200,
    12345, 443, 0, 0x10, 6, 0, 0, 0, 24, 24, 0,
)
v6_entry = bytes(52)
v7_entry = bytes(52)

assert len(v1_header(0)) == 16
assert len(v5_header(0)) == 24
assert len(v6_header(0)) == 24
assert len(v7_header(0)) == 24
assert len(v8_header(0)) == 28
assert len(v9_header(0)) == 20
assert len(v1_entry) == 48
assert len(v5_entry) == 48
assert len(v6_entry) == 52
assert len(v7_entry) == 52

def v9_template_body_for_id(template_id):
    return struct.pack("!HHHHHHHHHH", template_id, 4, 1, 4, 2, 4, 8, 4, 12, 4)

def v9_template_for_id(template_id):
    return flowset(0, v9_template_body_for_id(template_id))

def v9_data_for_id(template_id, body=None):
    if body is None:
        body = struct.pack("!IIII", 60, 1, 0xC0000201, 0xC0000202)
    return flowset(template_id, body)

v9_template_body = v9_template_body_for_id(256)
v9_template = v9_template_for_id(256)
v9_long_template_body = struct.pack("!HHHHHHHHHHHH", 256, 5, 1, 4, 2, 4, 8, 4, 12, 4, 4, 4)
v9_long_template = flowset(0, v9_long_template_body)
v9_very_long_template_body = struct.pack(
    "!HHHHHHHHHHHHHHHHHH", 256, 8, 1, 4, 2, 4, 8, 4, 12, 4,
    4, 4, 4, 4, 4, 4, 4, 4,
)
v9_very_long_template = flowset(0, v9_very_long_template_body)
v9_one_byte_packet_template = flowset(0, struct.pack("!HHHH", 256, 1, 2, 1))
v9_overwide_template = flowset(0, struct.pack("!HHHHHH", 512, 2, 1, 65535, 2, 1))
v9_data = v9_data_for_id(256)
v9_very_long_data = flowset(256, struct.pack(
    "!IIIIIIII", 60, 1, 0xC0000201, 0xC0000202, 17, 18, 19, 20,
))
valid_v9 = v9_header(2) + v9_template + v9_data
valid_v5 = v5_header(1) + v5_entry

payloads = {
    # No complete version field and the report's v5 version-only reproduction.
    "one_byte": b"\x00",
    "v5_version_only": struct.pack("!H", 5),
    # Every supported version must have its complete fixed header.
    "v1_header_minus_one": v1_header(0)[:-1],
    "v5_header_minus_one": v5_header(0)[:-1],
    "v6_header_minus_one": v6_header(0)[:-1],
    "v7_header_minus_one": v7_header(0)[:-1],
    "v8_header_minus_one": v8_header(0)[:-1],
    "v9_header_minus_one": v9_header(0)[:-1],
    # A declared record cannot be accepted unless its complete entry exists.
    "v1_entry_minus_one": v1_header(1) + v1_entry[:-1],
    "v5_entry_minus_one": v5_header(1) + v5_entry[:-1],
    "v6_entry_minus_one": v6_header(1) + v6_entry[:-1],
    "v7_entry_minus_one": v7_header(1) + v7_entry[:-1],
    "v5_count_mismatch": v5_header(2) + v5_entry,
    # Unsupported and unknown versions must exit without a zero-progress loop.
    "v8_full_header": v8_header(0),
    "unknown_version": struct.pack("!H", 10) + b"\x00\x00",
    # A v9 FlowSet must have a full header and a valid in-datagram length.
    "v9_short_flowset_header": v9_header(0) + b"\x00\x00\x00",
    "v9_zero_flowset_length": v9_header(0) + flowset(0, b"", 0),
    "v9_short_flowset_length": v9_header(0) + flowset(0, b"", 3),
    "v9_flowset_past_end": v9_header(0) + flowset(0, b"\x01", 32),
    # Template records must be complete and have nonzero field lengths.
    "v9_empty_template": v9_header(0) + flowset(0, b""),
    "v9_missing_template_field": v9_header(0) + flowset(0, struct.pack("!HH", 256, 1)),
    "v9_trailing_template_byte": v9_header(0) + flowset(0, v9_template_body + b"\x00"),
    "v9_zero_length_field": v9_header(0) + flowset(0, struct.pack("!HHHH", 256, 1, 8, 0)),
    # A v9 record cannot be wider than its enclosing 16-bit FlowSet payload.
    "v9_overwide_template": v9_header(2, 53) + v9_overwide_template + flowset(512, b""),
    "v9_invalid_template_then_data": v9_header(2) + flowset(0, v9_template_body + b"\x00") + v9_data,
    "v9_template_then_short_data": v9_header(2) + v9_template + flowset(256, b"\x00\x00\x00\x3c", 20),
    "valid_v5": valid_v5,
    "valid_v9": valid_v9,
}

for name, payload in payloads.items():
    write_pcap(name, [payload])

# A malformed datagram must not prevent processing of a later valid one.
write_pcap("malformed_then_valid", [payloads["v9_flowset_past_end"], valid_v5])
# The IP payload has a complete v5 record, but the UDP header declares no payload.
write_pcap("v5_past_udp_length", [(valid_v5, 8)])
# Malformed templates from distinct exporters must not create persistent cache state.
write_pcap(
    "v9_multi_source_malformed_templates",
    [v9_header(0, source_id) + flowset(0, struct.pack("!HH", 256, 1)) for source_id in range(1, 21)],
)
# Valid templates from many exporter/source-id pairs must remain isolated.
write_pcap(
    "v9_template_source_cache",
    [v9_header(1, source_id) + v9_template for source_id in range(1, 21)] + [v9_header(1, 20) + v9_data],
)
# NetFlow v9 template IDs are scoped to exporter address and source ID. A
# second exporter with the same source ID must not replace the first template.
exporter_a = b"\xc0\x00\x02\x01"
exporter_b = b"\xc0\x00\x02\x02"
collector = b"\xc0\x00\x02\xfe"
write_pcap_frames(
    "v9_ipv4_exporter_isolation",
    [
        ethernet_ipv4_udp(v9_header(1, 7) + v9_template, source=exporter_a, destination=collector),
        ethernet_ipv4_udp(v9_header(1, 7) + v9_long_template, source=exporter_b, destination=collector),
        ethernet_ipv4_udp(v9_header(1, 7) + v9_data, source=exporter_a, destination=collector),
    ],
)
write_pcap_frames(
    "v9_ipv4_exporter_isolation_reverse",
    [
        ethernet_ipv4_udp(v9_header(1, 7) + v9_template,
                          source=b"\xc0\x00\x02\xfe", destination=exporter_a),
        ethernet_ipv4_udp(v9_header(1, 7) + v9_long_template,
                          source=b"\xc0\x00\x02\xfd", destination=exporter_a),
        ethernet_ipv4_udp(v9_header(1, 7) + v9_data,
                          source=b"\xc0\x00\x02\xfe", destination=exporter_a),
    ],
)
exporter_v6_a = bytes.fromhex("20010db8000000000000000000000001")
exporter_v6_b = bytes.fromhex("20010db8000000000000000000000002")
collector_v6 = bytes.fromhex("20010db80000000000000000000000ff")
write_pcap_frames(
    "v9_ipv6_exporter_isolation",
    [
        ethernet_ipv6_udp(v9_header(1, 7) + v9_template, exporter_v6_a, collector_v6),
        ethernet_ipv6_udp(v9_header(1, 7) + v9_long_template, exporter_v6_b, collector_v6),
        ethernet_ipv6_udp(v9_header(1, 7) + v9_data, exporter_v6_a, collector_v6),
    ],
)
write_pcap_frames(
    "v9_ipv6_exporter_isolation_reverse",
    [
        ethernet_ipv6_udp(v9_header(1, 7) + v9_template,
                          bytes.fromhex("20010db80000000000000000000000fe"), exporter_v6_a),
        ethernet_ipv6_udp(v9_header(1, 7) + v9_long_template,
                          bytes.fromhex("20010db80000000000000000000000fd"), exporter_v6_a),
        ethernet_ipv6_udp(v9_header(1, 7) + v9_data,
                          bytes.fromhex("20010db80000000000000000000000fe"), exporter_v6_a),
    ],
)
# The default cache admits 256 active exporters and rejects a new source
# without evicting an existing exporter's template state.
overflow_templates = [v9_header(1, source_id) + v9_template for source_id in range(1, 258)]
write_pcap("v9_template_source_cache_overflow", overflow_templates + [v9_header(1, 257) + v9_data])
write_pcap("v9_template_source_cache_retains_existing", overflow_templates + [v9_header(1, 1) + v9_data])
# An invalid over-wide template must not consume an exporter-cache slot. The
# final valid exporter remains admitted only when the first source was rejected.
write_pcap(
    "v9_overwide_template_does_not_fill_cache",
    [v9_header(1, 1) + v9_overwide_template] +
    [v9_header(1, source_id) + v9_template for source_id in range(2, 258)] +
    [v9_header(1, 257) + v9_data],
)
# A single FlowSet has a bounded number of staged template records. Rejection
# must be transactional, so the last template is not available for later data.
flowset_limit_templates = b"".join(v9_template_body_for_id(template_id)
                                    for template_id in range(256, 385))
write_pcap(
    "v9_template_flowset_limit",
    [v9_header(1, 33) + flowset(0, flowset_limit_templates),
     v9_header(1, 33) + v9_data_for_id(384)],
)
# The same staging budget applies across every template FlowSet in one v9
# datagram, so splitting a template flood cannot bypass the bound.
aggregate_template_flowset_a = b"".join(v9_template_body_for_id(template_id)
                                         for template_id in range(256, 384))
aggregate_template_flowset_b = b"".join(v9_template_body_for_id(template_id)
                                         for template_id in range(384, 512))
write_pcap(
    "v9_template_datagram_limit",
    [v9_header(2, 34) + flowset(0, aggregate_template_flowset_a) +
     flowset(0, aggregate_template_flowset_b),
     v9_header(1, 34) + v9_data_for_id(511)],
)
# A stale template cache entry must release its source slot before fresh
# exporters are admitted at the source-cache limit.
expiry_frames = [(ethernet_ipv4_udp(v9_header(1, 1) + v9_template), 0)]
expiry_frames.extend(
    (ethernet_ipv4_udp(v9_header(1, source_id) + v9_template), 1800)
    for source_id in range(2, 258)
)
expiry_frames.append((ethernet_ipv4_udp(v9_header(1, 257) + v9_data), 1800))
write_pcap_frames("v9_template_cache_expiry", expiry_frames)
# Fill the total-template budget without crossing the source-cache limit.
template_count_ids = range(256, 1281)
write_pcap(
    "v9_template_count_cache_limit",
    [v9_header(1, 41) + v9_template_for_id(template_id)
     for template_id in template_count_ids] + [v9_header(1, 41) + v9_data_for_id(1280)],
)
# A 16-MiB template-byte budget prevents otherwise valid, oversized template
# streams from retaining unbounded field definitions.
large_template_field_count = 16369
large_template_ids = range(2000, 2257)
def large_template(template_id):
    body = struct.pack("!HH", template_id, large_template_field_count)
    body += struct.pack("!HH", 1, 4) * large_template_field_count
    return flowset(0, body)
write_pcap(
    "v9_template_byte_cache_limit",
    [v9_header(1, 42) + large_template(template_id)
     for template_id in large_template_ids] + [
         v9_header(1, 42) + v9_data_for_id(2256, b"\x00" * (large_template_field_count * 4))
    ],
)
# A one-byte data template can otherwise expand a small v9 packet into many
# Argus output records. The per-datagram limit must apply across FlowSets.
dense_v9_data = flowset(256, b"\x01" * 1024)
write_pcap(
    "v9_data_record_limit",
    [v9_header(1, 52) + v9_one_byte_packet_template,
     v9_header(2, 52) + dense_v9_data + dense_v9_data],
)
# Empty data FlowSets for a wide template must not repeatedly scan every
# template field. The 129th FlowSet exceeds the per-datagram work budget.
wide_data_field_count = 8000
wide_data_template = flowset(
    0, struct.pack("!HH", 513, wide_data_field_count) +
    v9_template_body_for_id(513)[4:] +
    struct.pack("!HH", 999, 1) * (wide_data_field_count - 4),
)
wide_empty_data_flowsets = b"".join(flowset(513, b"") for _ in range(128))
wide_valid_data = flowset(
    513, v9_data_for_id(256)[4:] + b"\x00" * (wide_data_field_count - 4),
)
write_pcap(
    "v9_data_flowset_limit",
    [v9_header(130, 54) + wide_data_template + wide_empty_data_flowsets + wide_valid_data],
)
# Separate cisco: inputs run with independent model state and may be processed
# concurrently when Argus is built with thread support.
write_pcap("v9_multi_source_a", [v9_header(1, 11) + v9_template, v9_header(1, 11) + v9_data])
write_pcap("v9_multi_source_b", [v9_header(1, 11) + v9_very_long_template, v9_header(1, 11) + v9_very_long_data])
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

has_netflow_record() {
   python3 - "$1" <<'PY'
import struct
import sys

data = open(sys.argv[1], "rb").read()
offset = 0
while offset + 4 <= len(data):
    length_be = struct.unpack("!H", data[offset + 2:offset + 4])[0]
    length_le = struct.unpack("<H", data[offset + 2:offset + 4])[0]
    length = next((value for value in (length_be, length_le)
                   if value and value * 4 <= len(data) - offset), 0)
    if not length:
        break
    if data[offset] & 0xF0 == 0x30:
        sys.exit(0)
    offset += length * 4
sys.exit(1)
PY
}

netflow_record_count() {
    python3 - "$1" <<'PY'
import struct
import sys

data = open(sys.argv[1], "rb").read()
offset = 0
count = 0
while offset + 4 <= len(data):
    length_be = struct.unpack("!H", data[offset + 2:offset + 4])[0]
    length_le = struct.unpack("<H", data[offset + 2:offset + 4])[0]
    length = next((value for value in (length_be, length_le)
                   if value and value * 4 <= len(data) - offset), 0)
    if not length:
        break
    if data[offset] & 0xF0 == 0x30:
        count += 1
    offset += length * 4
print(count)
PY
}

run_offline_case() {
   label="$1"
   case_name="$2"
   expect_output="$3"
   expected_records="${4:-}"
   pcap_path="$WORKDIR/$case_name.pcap"
   output_path="$WORKDIR/$case_name.argus"
   log_path="$WORKDIR/$case_name.log"

   HOME=/tmp "$ARGUS_BIN" -r "cisco:$pcap_path" -w "$output_path" -P 0 -D 0 >"$log_path" 2>&1 &
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

   if [ -n "$expected_records" ]; then
      record_count="$(netflow_record_count "$output_path")"
      if [ "$record_count" = "$expected_records" ]; then
         pass "$label produced $expected_records NetFlow-originated Argus records"
      else
         fail "$label produced $record_count NetFlow-originated Argus records, expected $expected_records (see $log_path)"
      fi
      return
   fi

   if has_netflow_record "$output_path"; then
      if [ "$expect_output" = "yes" ]; then
         pass "$label produced a NetFlow-originated Argus record"
      else
         fail "$label produced a NetFlow-originated record for rejected input (see $log_path)"
      fi
   elif [ "$expect_output" = "yes" ]; then
      fail "$label did not produce a NetFlow-originated Argus record (see $log_path)"
   else
      pass "$label produced no NetFlow-originated Argus record"
    fi
}

run_multi_source_case() {
    label="$1"
    first_case="$2"
    second_case="$3"
    expected_records="$4"
    output_path="$WORKDIR/${first_case}_${second_case}.argus"
    log_path="$WORKDIR/${first_case}_${second_case}.log"

    HOME=/tmp "$ARGUS_BIN" -r "cisco:$WORKDIR/$first_case.pcap" "cisco:$WORKDIR/$second_case.pcap" \
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
    record_count="$(netflow_record_count "$output_path")"
    if [ "$record_count" = "$expected_records" ]; then
       pass "$label produced $expected_records isolated NetFlow-originated Argus records"
    else
       fail "$label produced $record_count NetFlow-originated Argus records, expected $expected_records (see $log_path)"
    fi
}

run_offline_case "NetFlow one-byte version" "one_byte" no
run_offline_case "NetFlow v5 version-only datagram" "v5_version_only" no
run_offline_case "NetFlow v1 short header" "v1_header_minus_one" no
run_offline_case "NetFlow v5 short header" "v5_header_minus_one" no
run_offline_case "NetFlow v6 short header" "v6_header_minus_one" no
run_offline_case "NetFlow v7 short header" "v7_header_minus_one" no
run_offline_case "NetFlow v8 short header" "v8_header_minus_one" no
run_offline_case "NetFlow v9 short header" "v9_header_minus_one" no
run_offline_case "NetFlow v1 short entry" "v1_entry_minus_one" no
run_offline_case "NetFlow v5 short entry" "v5_entry_minus_one" no
run_offline_case "NetFlow v6 short entry" "v6_entry_minus_one" no
run_offline_case "NetFlow v7 short entry" "v7_entry_minus_one" no
run_offline_case "NetFlow v5 count mismatch" "v5_count_mismatch" no
run_offline_case "NetFlow v8 unsupported header" "v8_full_header" no
run_offline_case "NetFlow unknown version" "unknown_version" no
run_offline_case "NetFlow v9 short FlowSet header" "v9_short_flowset_header" no
run_offline_case "NetFlow v9 zero FlowSet length" "v9_zero_flowset_length" no
run_offline_case "NetFlow v9 short FlowSet length" "v9_short_flowset_length" no
run_offline_case "NetFlow v9 FlowSet past datagram end" "v9_flowset_past_end" no
run_offline_case "NetFlow v9 empty template" "v9_empty_template" no
run_offline_case "NetFlow v9 missing template field" "v9_missing_template_field" no
run_offline_case "NetFlow v9 trailing template byte" "v9_trailing_template_byte" no
run_offline_case "NetFlow v9 zero-length template field" "v9_zero_length_field" no
run_offline_case "NetFlow v9 overwide template" "v9_overwide_template" no
run_offline_case "NetFlow v9 invalid template followed by data" "v9_invalid_template_then_data" no
run_offline_case "NetFlow v9 template followed by short data" "v9_template_then_short_data" no
run_offline_case "NetFlow v5 data past UDP length" "v5_past_udp_length" no
run_offline_case "NetFlow v9 malformed multi-source templates" "v9_multi_source_malformed_templates" no
run_offline_case "NetFlow v9 multi-source template cache" "v9_template_source_cache" yes
run_offline_case "NetFlow v9 IPv4 exporter template isolation" "v9_ipv4_exporter_isolation" yes
run_offline_case "NetFlow v9 reverse IPv4 exporter template isolation" "v9_ipv4_exporter_isolation_reverse" yes
run_offline_case "NetFlow v9 IPv6 exporter template isolation" "v9_ipv6_exporter_isolation" yes
run_offline_case "NetFlow v9 reverse IPv6 exporter template isolation" "v9_ipv6_exporter_isolation_reverse" yes
run_offline_case "NetFlow v9 cache limit rejects new exporter" "v9_template_source_cache_overflow" no
run_offline_case "NetFlow v9 cache limit retains existing exporter" "v9_template_source_cache_retains_existing" yes
run_offline_case "NetFlow v9 overwide template does not fill cache" "v9_overwide_template_does_not_fill_cache" yes
run_offline_case "NetFlow v9 FlowSet staging limit" "v9_template_flowset_limit" no
run_offline_case "NetFlow v9 datagram staging limit" "v9_template_datagram_limit" no
run_offline_case "NetFlow v9 cache expiry reclaims exporter slot" "v9_template_cache_expiry" yes
run_offline_case "NetFlow v9 template-count cache limit" "v9_template_count_cache_limit" no
run_offline_case "NetFlow v9 template-byte cache limit" "v9_template_byte_cache_limit" no
run_offline_case "NetFlow v9 data record limit" "v9_data_record_limit" yes 1024
run_offline_case "NetFlow v9 data FlowSet work limit" "v9_data_flowset_limit" no 0
run_multi_source_case "NetFlow v9 concurrent source models" "v9_multi_source_a" "v9_multi_source_b" 2
run_offline_case "NetFlow valid v5 record" "valid_v5" yes
run_offline_case "NetFlow valid v9 record" "valid_v9" yes
run_offline_case "NetFlow malformed datagram followed by valid v5 record" "malformed_then_valid" yes

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
