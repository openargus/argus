#!/bin/sh
# Regression test for PRP-1 detection and MAC-DSR v2 accounting.
#
# The generated Ethernet capture contains valid LAN A/B RCTs, a VLAN/FCS RCT,
# same-LAN duplicate/gap/out-of-order sequences, malformed RCTs, a truncated
# RCT, and an intentionally dual-valid FCS/no-FCS RCT.  It also replays a
# Linux cooked (SLL) PRP frame. The latter two ambiguity/truncation cases must
# remain unknown rather than being reported as malformed.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="${ARGUS_BIN:-$REPO_ROOT/bin/argus}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/argus_regress_prp.XXXXXX")"
REGRESSION_FAIL_MARKER="$WORKDIR/fail"
CONF="$WORKDIR/mac.conf"
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
if ! command -v python3 >/dev/null 2>&1; then
   echo "error: python3 is required for the PRP regression test" >&2
   exit 2
fi

cat > "$CONF" <<'EOF'
ARGUS_GENERATE_MAC_DATA=yes
EOF

if python3 - "$WORKDIR" <<'PY'
import json
import struct
import sys

workdir = sys.argv[1]

SRC_MAC = bytes.fromhex("020000000001")
DST_MAC = bytes.fromhex("020000000002")
OTHER_SRC_MAC = bytes.fromhex("020000000011")
OTHER_DST_MAC = bytes.fromhex("020000000012")
SRC_IP = bytes((10, 0, 0, 1))
DST_IP = bytes((10, 0, 0, 2))
OTHER_SRC_IP = bytes((10, 0, 1, 1))
OTHER_DST_IP = bytes((10, 0, 1, 2))


def ipv4_udp(src, dst, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0,
                       64, 17, 0, src, dst) + udp


def ethernet(payload, src=SRC_MAC, dst=DST_MAC, vlan=False, stacked_vlan=False):
    if vlan:
        # Use ordinary 802.1Q tags for both levels so Argus' normal packet
        # dispatcher reaches the IP flow while the PRP parser verifies that
        # both tag headers are excluded from the LSDU size.
        tags = 2 if stacked_vlan else 1
        header = dst + src + struct.pack("!H", 0x8100)
        for index in range(tags):
            next_type = 0x8100 if index + 1 < tags else 0x0800
            header += struct.pack("!HH", index + 9, next_type)
        return header + payload
    return dst + src + struct.pack("!H", 0x0800) + payload


def prp(sequence, lan_id, payload, vlan=False, stacked_vlan=False, fcs=False, size_delta=0,
        src=SRC_MAC, dst=DST_MAC):
    # PRP LSDU size covers the original payload and RCT, but not Ethernet,
    # VLAN, or FCS bytes.
    lsdu_size = len(payload) + 6 + size_delta
    assert 0 < lsdu_size < 0x1000
    rct = struct.pack("!HHH", sequence, (lan_id << 12) | lsdu_size, 0x88FB)
    return ethernet(payload + rct + (b"\0" * 4 if fcs else b""), src, dst,
                    vlan, stacked_vlan)


def ambiguous_prp(payload):
    # The RCT at n-10 validates if the final four bytes are FCS.  Its suffix
    # is also the sequence field for a second, valid RCT at n-6.  The packet
    # therefore has two valid FCS/no-FCS interpretations and must be unknown.
    fcs_lsdu_size = len(payload) + 6
    normal_lsdu_size = len(payload) + 10
    tail = struct.pack("!HHH", 777, 0xA000 | fcs_lsdu_size, 0x88FB)
    tail += struct.pack("!HH", 0xA000 | normal_lsdu_size, 0x88FB)
    return ethernet(payload + tail)


def write_pcap(path, records, linktype=1):
    with open(path, "wb") as output:
        # Classic little-endian pcap, version 2.4.
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for sec, usec, frame, captured_length in records:
            if captured_length is None:
                captured_length = len(frame)
            assert 0 <= captured_length <= len(frame)
            output.write(struct.pack("<IIII", sec, usec, captured_length, len(frame)))
            output.write(frame[:captured_length])


forward = ipv4_udp(SRC_IP, DST_IP, 1000, 2000, b"p")
reverse = ipv4_udp(DST_IP, SRC_IP, 2000, 1000, b"r")
ordinary = ipv4_udp(OTHER_SRC_IP, OTHER_DST_IP, 3000, 4000, b"n")

truncated = prp(999, 0xA, forward)
main = []
source_frames = []
destination_frames = []


def add_main(sec, usec, frame, direction, captured_length=None):
    main.append((sec, usec, frame, captured_length))
    if direction == "source":
        source_frames.append(frame)
    elif direction == "destination":
        destination_frames.append(frame)


add_main(1, 100000, prp(100, 0xA, forward), "source")
add_main(1, 110000, prp(100, 0xB, forward), "source")
add_main(1, 120000, prp(102, 0xA, forward), "source")
add_main(1, 130000, prp(102, 0xA, forward), "source")
add_main(1, 140000, prp(101, 0xA, forward), "source")
add_main(1, 150000, prp(102, 0xB, forward), "source")
add_main(1, 160000, prp(500, 0xA, reverse, src=DST_MAC, dst=SRC_MAC), "destination")
add_main(1, 170000, prp(499, 0xA, reverse, src=DST_MAC, dst=SRC_MAC), "destination")
# A known suffix with a non-PRP LAN ID is malformed in the source direction.
add_main(1, 180000, prp(900, 0xC, forward), "source")
# A known suffix with an invalid LSDU length is malformed in the destination direction.
add_main(1, 190000, prp(901, 0xB, reverse, size_delta=1,
                         src=DST_MAC, dst=SRC_MAC), "destination")
# This validates only when VLAN and FCS bytes are excluded from the LSDU size.
add_main(1, 200000, prp(103, 0xB, forward, vlan=True, fcs=True), "source")
# This separately verifies stacked-VLAN LSDU adjustment without an FCS.
add_main(1, 205000, prp(104, 0xB, forward, vlan=True, stacked_vlan=True), "source")
# The wire frame contains a PRP suffix, but the capture ends before it.  It is unknown.
add_main(1, 210000, truncated, "source", len(truncated) - 2)
add_main(1, 220000, ambiguous_prp(forward), "source")
# Arrival order differs from timestamp order.  RCT first/last snapshots use time order.
add_main(1, 50000, prp(103, 0xA, forward), "source")
main.append((1, 230000, ethernet(ordinary, OTHER_SRC_MAC, OTHER_DST_MAC), None))

write_pcap(f"{workdir}/main.pcap", main)

reset_payload = ipv4_udp(SRC_IP, DST_IP, 1000, 2000, b"reset")
write_pcap(f"{workdir}/reset.pcap", [
    (1, 0, prp(100, 0xA, reset_payload), None),
    (3, 0, prp(102, 0xA, reset_payload), None),
])

# Linux cooked capture omits the physical Ethernet header.  Argus synthesizes
# one for flow/MAC processing, while its metric remains the original SLL
# payload length.  The PRP RCT still belongs at the actual payload tail.
sll_rct = struct.pack("!HHH", 333, 0xA000 | (len(forward) + 6), 0x88FB)
sll_header = struct.pack("!HHH8sH", 0, 1, len(SRC_MAC), SRC_MAC + b"\0\0", 0x0800)
write_pcap(f"{workdir}/sll.pcap", [(4, 0, sll_header + forward + sll_rct, None)], 113)

with open(f"{workdir}/expected.json", "w", encoding="utf-8") as output:
    json.dump({
        "source_packets": len(source_frames),
        "source_bytes": sum(map(len, source_frames)),
        "destination_packets": len(destination_frames),
        "destination_bytes": sum(map(len, destination_frames)),
        "lan_a_size": 0xA000 | (len(forward) + 6),
        "lan_b_size": 0xB000 | (len(forward) + 6),
        "sll_bytes": len(forward) + len(sll_rct),
    }, output)
PY
then
   pass "generated PRP-1 regression captures"
else
   fail "could not generate PRP-1 regression captures"
fi

run_sensor() {
   label="$1"
   pcap_path="$2"
   output_path="$3"
   shift 3
   log_path="$output_path.log"

   HOME=/tmp "$ARGUS_BIN" -X "$@" -r "$pcap_path" -w "$output_path" -P 0 -D 0 >"$log_path" 2>&1 &
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
}

run_sensor "PRP CLI-MAC replay" "$WORKDIR/main.pcap" "$WORKDIR/main-cli.argus" -m
run_sensor "PRP config-MAC replay" "$WORKDIR/main.pcap" "$WORKDIR/main-config.argus" -F "$CONF"
run_sensor "PRP no-MAC replay" "$WORKDIR/main.pcap" "$WORKDIR/main-nomac.argus"
run_sensor "PRP report-window replay" "$WORKDIR/reset.pcap" "$WORKDIR/reset.argus" -m -S 1
run_sensor "PRP Linux-SLL replay" "$WORKDIR/sll.pcap" "$WORKDIR/sll.argus" -m

if python3 - "$WORKDIR/main-cli.argus" "$WORKDIR/main-config.argus" \
               "$WORKDIR/main-nomac.argus" "$WORKDIR/reset.argus" \
               "$WORKDIR/sll.argus" "$WORKDIR/expected.json" <<'PY'
import json
import struct
import sys

cli_path, config_path, nomac_path, reset_path, sll_path, expected_path = sys.argv[1:]
with open(expected_path, encoding="utf-8") as input_file:
    expected = json.load(input_file)

FLOW_TYPE = 0x02
METER_TYPE = 0x10
MAC_TYPE = 0x42
FAR_TYPE = 0x10
MAC_V2 = 2
MAC_V2_WORDS = 67
MAC_SRC_PRP = 0x04
MAC_DST_PRP = 0x08
PRP_LAN_A = 0x01
PRP_LAN_B = 0x02
PRP_MALFORMED = 0x04
PRP_FLOW_SCOPE = 0x08
PRP_LAN_A_RESEED = 0x10


def records(path):
    data = open(path, "rb").read()
    offset = 0
    parsed = []
    while offset < len(data):
        if len(data) - offset < 4:
            raise AssertionError(f"truncated record header in {path}")
        record_type, cause, words = struct.unpack_from("!BBH", data, offset)
        size = words * 4
        if words == 0 or offset + size > len(data):
            raise AssertionError(f"invalid record length in {path}")
        if record_type & 0xF0 == FAR_TYPE:
            dsrs = []
            cursor = offset + 4
            end = offset + size
            while cursor < end:
                if end - cursor < 4:
                    raise AssertionError(f"truncated DSR header in {path}")
                dsr_type, subtype, qualifier, short_length = struct.unpack_from("!BBBB", data, cursor)
                if dsr_type & 0x80:
                    dsr_words = 1
                elif dsr_type == 0x50:  # ARGUS_DATA_DSR has a 16-bit length.
                    dsr_words = struct.unpack_from("!H", data, cursor + 2)[0]
                else:
                    dsr_words = short_length
                if dsr_words == 0 or cursor + dsr_words * 4 > end:
                    raise AssertionError(f"invalid DSR length in {path}")
                dsrs.append({
                    "type": dsr_type,
                    "subtype": subtype,
                    "qualifier": qualifier,
                    "words": dsr_words,
                    "offset": cursor,
                    "data": data,
                })
                cursor += dsr_words * 4
            if cursor != end:
                raise AssertionError(f"DSR chain did not end on record boundary in {path}")
            parsed.append((cause, dsrs))
        offset += size
    return parsed


def dsr(dsrs, type_code):
    return [item for item in dsrs if (item["type"] & 0x7F) == type_code]


def flow_key(dsrs):
    keys = dsr(dsrs, FLOW_TYPE)
    if len(keys) != 1:
        return None
    item = keys[0]
    # Classic IPv4 5-tuple: source, destination, IP protocol, transport
    # protocol, source port, destination port.
    if item["subtype"] != 1 or (item["qualifier"] & 0x1F) != 1 or item["words"] < 5:
        return None
    return struct.unpack_from("!IIBBHH", item["data"], item["offset"] + 4)


def matching_flow(path, source, destination, sport, dport):
    wanted = (source, destination, 17, 0, sport, dport)
    return [dsrs for _, dsrs in records(path) if flow_key(dsrs) == wanted]


def rct(data, offset):
    sequence, lan_size, sec, usec = struct.unpack_from("!HHII", data, offset)
    return {"sequence": sequence, "lan_size": lan_size, "time": (sec, usec)}


def lan(data, offset):
    packets, gaps, out_of_order, duplicates = struct.unpack_from("!QQQQ", data, offset)
    return {
        "packets": packets,
        "gaps": gaps,
        "out_of_order": out_of_order,
        "duplicates": duplicates,
        "first": rct(data, offset + 32),
        "last": rct(data, offset + 44),
    }


def direction(data, offset):
    flags, malformed = struct.unpack_from("!IQ", data, offset)
    return {
        "flags": flags,
        "malformed": malformed,
        "lan_a": lan(data, offset + 12),
        "lan_b": lan(data, offset + 68),
    }


def mac(dsrs):
    values = dsr(dsrs, MAC_TYPE)
    if len(values) != 1:
        raise AssertionError("expected exactly one MAC DSR")
    item = values[0]
    result = {
        "subtype": item["subtype"],
        "qualifier": item["qualifier"],
        "words": item["words"],
    }
    if item["subtype"] == MAC_V2:
        if item["words"] != MAC_V2_WORDS:
            raise AssertionError("MAC-v2 DSR did not have the declared 67-word length")
        # Four-byte DSR header plus the legacy 16-byte MAC payload.
        result["source"] = direction(item["data"], item["offset"] + 20)
        result["destination"] = direction(item["data"], item["offset"] + 144)
    return result


def metric(dsrs):
    values = dsr(dsrs, METER_TYPE)
    if len(values) != 1:
        raise AssertionError("expected exactly one metric DSR")
    item = values[0]
    # The tiny deterministic traffic set uses the existing source/destination
    # short metric representation.
    if (item["subtype"], item["qualifier"], item["words"]) != (1, 2, 3):
        raise AssertionError("unexpected metric DSR representation")
    return struct.unpack_from("!HHHH", item["data"], item["offset"] + 4)


def metric_totals(dsrs):
    values = dsr(dsrs, METER_TYPE)
    if len(values) != 1:
        raise AssertionError("expected exactly one metric DSR")
    item = values[0]
    if item["subtype"] != 1:
        raise AssertionError("unexpected metric DSR subtype")
    offset = item["offset"] + 4
    formats = {
        1: ("!BBBB", lambda values: values),
        2: ("!HHHH", lambda values: values),
        3: ("!IIII", lambda values: values),
        4: ("!QQQQ", lambda values: values),
        5: ("!BB", lambda values: (values[0], values[1], 0, 0)),
        6: ("!HH", lambda values: (values[0], values[1], 0, 0)),
        7: ("!II", lambda values: (values[0], values[1], 0, 0)),
        8: ("!QQ", lambda values: (values[0], values[1], 0, 0)),
        9: ("!BB", lambda values: (0, 0, values[0], values[1])),
        10: ("!HH", lambda values: (0, 0, values[0], values[1])),
        11: ("!II", lambda values: (0, 0, values[0], values[1])),
        12: ("!QQ", lambda values: (0, 0, values[0], values[1])),
    }
    if item["qualifier"] not in formats:
        raise AssertionError("unexpected metric DSR representation")
    fmt, expand = formats[item["qualifier"]]
    return expand(struct.unpack_from(fmt, item["data"], offset))


def assert_rct(value, sequence, lan_size, timestamp):
    # Argus builds may use microsecond or nanosecond timestamp precision; the
    # extension follows the sensor's selected precision just like TIME_DSR.
    accepted_times = {timestamp, (timestamp[0], timestamp[1] * 1000)}
    assert value["sequence"] == sequence and value["lan_size"] == lan_size and \
        value["time"] in accepted_times, value


def assert_primary_accounting(path):
    flows = matching_flow(path, 0x0A000001, 0x0A000002, 1000, 2000)
    assert len(flows) == 1, len(flows)
    primary = flows[0]
    src_packets, src_bytes, dst_packets, dst_bytes = metric(primary)
    assert (src_packets, src_bytes, dst_packets, dst_bytes) == (
        expected["source_packets"], expected["source_bytes"],
        expected["destination_packets"], expected["destination_bytes"]), (
        src_packets, src_bytes, dst_packets, dst_bytes)

    value = mac(primary)
    assert value["subtype"] == MAC_V2
    assert value["words"] == MAC_V2_WORDS
    assert value["qualifier"] & (MAC_SRC_PRP | MAC_DST_PRP) == (MAC_SRC_PRP | MAC_DST_PRP)

    source = value["source"]
    destination = value["destination"]
    assert source["flags"] & (PRP_LAN_A | PRP_LAN_B | PRP_MALFORMED | PRP_FLOW_SCOPE) == \
        (PRP_LAN_A | PRP_LAN_B | PRP_MALFORMED | PRP_FLOW_SCOPE)
    assert destination["flags"] & (PRP_LAN_A | PRP_MALFORMED | PRP_FLOW_SCOPE) == \
        (PRP_LAN_A | PRP_MALFORMED | PRP_FLOW_SCOPE)
    assert source["malformed"] == 1
    assert destination["malformed"] == 1

    assert (source["lan_a"]["packets"], source["lan_a"]["gaps"],
            source["lan_a"]["out_of_order"], source["lan_a"]["duplicates"]) == (5, 1, 1, 1)
    assert_rct(source["lan_a"]["first"], 103, expected["lan_a_size"], (1, 50000))
    assert_rct(source["lan_a"]["last"], 101, expected["lan_a_size"], (1, 140000))

    assert (source["lan_b"]["packets"], source["lan_b"]["gaps"],
            source["lan_b"]["out_of_order"], source["lan_b"]["duplicates"]) == (4, 1, 0, 0)
    assert_rct(source["lan_b"]["first"], 100, expected["lan_b_size"], (1, 110000))
    assert_rct(source["lan_b"]["last"], 104, expected["lan_b_size"], (1, 205000))

    assert (destination["lan_a"]["packets"], destination["lan_a"]["gaps"],
            destination["lan_a"]["out_of_order"], destination["lan_a"]["duplicates"]) == (2, 0, 1, 0)
    assert_rct(destination["lan_a"]["first"], 500, expected["lan_a_size"], (1, 160000))
    assert_rct(destination["lan_a"]["last"], 499, expected["lan_a_size"], (1, 170000))
    assert destination["lan_b"]["packets"] == 0


assert_primary_accounting(cli_path)
assert_primary_accounting(config_path)

# A non-PRP Ethernet flow continues to use the byte-for-byte legacy v0 MAC DSR.
ordinary_flows = matching_flow(cli_path, 0x0A000101, 0x0A000102, 3000, 4000)
assert len(ordinary_flows) == 1, len(ordinary_flows)
ordinary_mac = mac(ordinary_flows[0])
assert (ordinary_mac["subtype"], ordinary_mac["qualifier"], ordinary_mac["words"]) == (0, 0, 5)

# -X clears the host configuration and this replay intentionally omits -m.
# PRP parsing still runs, but it must not add any MAC DSR to emitted records.
assert not [item for _, dsrs in records(nomac_path) for item in dsr(dsrs, MAC_TYPE)]

# A status report between the two LAN-A packets clears report-window values but
# preserves the hidden per-flow cursor.  Thus the new window sees seq 102 as a
# one-packet gap after seq 100, not as its initial sequence.
reset_flows = matching_flow(reset_path, 0x0A000001, 0x0A000002, 1000, 2000)
windows = []
for flow in reset_flows:
    value = mac(flow)
    if value["subtype"] != MAC_V2:
        continue
    for side in (value["source"], value["destination"]):
        if side["lan_a"]["packets"]:
            windows.append(side)
assert any(side["lan_a"]["first"]["sequence"] == 100 and
           side["lan_a"]["packets"] == 1 and side["lan_a"]["gaps"] == 0
           for side in windows), windows
assert any(side["lan_a"]["first"]["sequence"] == 102 and
           side["lan_a"]["packets"] == 1 and side["lan_a"]["gaps"] == 1 and
           not (side["flags"] & PRP_LAN_A_RESEED)
           for side in windows), windows

# DLT_LINUX_SLL has no physical Ethernet header in the capture.  Its synthetic
# Ethernet header must not make the RCT look 14 bytes early or alter the LSDU.
sll_flows = matching_flow(sll_path, 0x0A000001, 0x0A000002, 1000, 2000)
assert len(sll_flows) == 1, len(sll_flows)
sll_mac = mac(sll_flows[0])
assert sll_mac["subtype"] == MAC_V2
src_packets, src_bytes, dst_packets, dst_bytes = metric_totals(sll_flows[0])
assert (src_packets + dst_packets, src_bytes + dst_bytes) == (1, expected["sll_bytes"])
sll_sides = (sll_mac["source"], sll_mac["destination"])
assert any(side["lan_a"]["packets"] == 1 and
           side["lan_a"]["first"]["sequence"] == 333 and
           side["lan_a"]["first"]["lan_size"] == expected["lan_a_size"]
           for side in sll_sides), sll_sides
PY
then
   pass "PRP MAC-v2 wire format, accounting, reset behavior, SLL parsing, and MAC gate are correct"
else
   fail "PRP MAC-v2 output validation failed"
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
