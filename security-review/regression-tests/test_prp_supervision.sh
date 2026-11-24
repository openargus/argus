#!/bin/sh
# Regression coverage for IEC 62439-3 PRP supervision frames.
#
# Exercise direct and VLAN EtherType dispatch, PRP-0/PRP-1 bodies, known and
# unknown TLVs, malformed and truncated bodies, a validated RCT/FCS boundary,
# bounded claim conflicts, and -C User Data DSR retention.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARGUS_BIN="${ARGUS_BIN:-$REPO_ROOT/bin/argus}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/argus_regress_prp_supervision.XXXXXX")"
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
if ! command -v python3 >/dev/null 2>&1; then
   echo "error: python3 is required for the PRP supervision regression test" >&2
   exit 2
fi

if python3 - "$WORKDIR/input.pcap" "$WORKDIR/reset.pcap" "$WORKDIR/expected.json" <<'PY'
import json
import struct
import sys

pcap_path, reset_path, expected_path = sys.argv[1:]

PRESENT = 0x00000001
VALID = 0x00000002
MALFORMED = 0x00000004
TRUNCATED = 0x00000008
HAS_SEQUENCE = 0x00000010
REPORTER = 0x00000020
NODE_A = 0x00000040
NODE_B = 0x00000080
REDBOX = 0x00000100
VDAN = 0x00000200
EOT = 0x00000400
PADDING = 0x00000800
CLAIM_CONFLICT = 0x00001000

DST = bytes.fromhex("01154e000100")
NODE_A_MAC = bytes.fromhex("0200000000aa")
NODE_B_MAC = bytes.fromhex("0200000000bb")
ALT_NODE_A_MAC = bytes.fromhex("0200000000ab")
REDBOX_MAC = bytes.fromhex("0200000000cc")
VDAN_MAC = bytes.fromhex("0200000000dd")

records = []
expected = {}
reset_records = []


def source(number):
    return bytes((2, 0, 0, 0, 1, number))


def supervision_header(version, path, sequence=0):
    data = struct.pack("!H", ((path & 0x0f) << 12) | (version & 0x0fff))
    if version:
        data += struct.pack("!H", sequence)
    return data


def tlv(kind, value):
    assert len(value) <= 255
    return bytes((kind, len(value))) + value


def ethernet(body, src, vlan=False):
    if vlan:
        return (DST + src + struct.pack("!H", 0x8100) +
                struct.pack("!HH", 42, 0x88fb) + body), 18
    return DST + src + struct.pack("!H", 0x88fb) + body, 14


def add(name, number, body, flags, version, path, sequence, node_mode=0,
        node_a=None, node_b=None, redbox=None, vdan=None, vlan=False,
        captured_length=None):
    frame, payload_offset = ethernet(body, source(number), vlan)
    if captured_length is None:
        captured_length = len(frame)
    assert payload_offset <= captured_length <= len(frame)
    reporter = source(number)
    expected[reporter.hex()] = {
        "name": name,
        "flags": flags,
        "version": version,
        "path": path,
        "sequence": sequence,
        "node_mode": node_mode,
        "reporter": reporter.hex(),
        "node_a": None if node_a is None else node_a.hex(),
        "node_b": None if node_b is None else node_b.hex(),
        "redbox": None if redbox is None else redbox.hex(),
        "vdan": None if vdan is None else vdan.hex(),
        "vlan": vlan,
        "control_payload": frame[payload_offset:captured_length].hex(),
    }
    records.append((len(records) + 1, frame, captured_length))


# A PRP-1 announcement carrying every supported identity role, EOT, and
# Ethernet padding.  The source remains the reporter even though its claims
# are independently represented.
add("v1-full", 1,
    supervision_header(1, 1, 0x1234) +
    tlv(20, NODE_A_MAC + NODE_B_MAC) +
    tlv(30, REDBOX_MAC) + tlv(31, VDAN_MAC) + b"\x00\x00\x00\x00\x00",
    PRESENT | VALID | HAS_SEQUENCE | REPORTER | NODE_A | NODE_B | REDBOX |
    VDAN | EOT | PADDING,
    1, 1, 0x1234, 20, NODE_A_MAC, NODE_B_MAC, REDBOX_MAC, VDAN_MAC)

# The EtherType is after an 802.1Q header and uses the duplicate-accept node
# TLV.  A decoded Network DSR here proves post-VLAN dispatch reached PRP.
add("v1-vlan", 2,
    supervision_header(1, 2, 0x4321) + tlv(21, NODE_A_MAC) + b"\x00\x00",
    PRESENT | VALID | HAS_SEQUENCE | REPORTER | NODE_A | EOT,
    1, 2, 0x4321, 21, NODE_A_MAC, vlan=True)

# PRP-0 has no supervision sequence.  A two-address node can be followed by
# a RedBox TLV; it must not be prematurely treated as padding.
add("v0-node-redbox", 3,
    supervision_header(0, 3) + tlv(20, NODE_A_MAC + NODE_B_MAC) +
    tlv(30, REDBOX_MAC) + b"\x00\x00\x00\x00",
    PRESENT | VALID | REPORTER | NODE_A | NODE_B | REDBOX | PADDING,
    0, 3, 0, 20, NODE_A_MAC, NODE_B_MAC, REDBOX_MAC)

# A PRP-0 VDAN announcement ends the TLV data and leaves padding.
add("v0-vdan", 4,
    supervision_header(0, 4) + tlv(31, VDAN_MAC) + b"\x00\x00\x00\x00",
    PRESENT | VALID | REPORTER | VDAN | PADDING,
    0, 4, 0, 0, vdan=VDAN_MAC)

# Known TLV lengths are validated.  Its parsed header sequence remains a
# bounded observation, but version/path are not marked valid or promoted.
add("malformed-node", 5,
    supervision_header(1, 1, 0x1234) + b"\x14\x05abcde\x00\x00",
    PRESENT | MALFORMED | HAS_SEQUENCE | REPORTER | EOT,
    0, 0, 0x1234)

# The trailer begins with bytes that would look like a node TLV if parsed as
# payload.  A valid RCT before FCS must instead provide the hard parser bound.
rct_body = supervision_header(1, 1, 0xabcd) + tlv(20, NODE_A_MAC)
rct = struct.pack("!HHH", 0x1406, 0xa000 | (len(rct_body) + 6), 0x88fb)
add("rct-fcs-boundary", 6, rct_body + rct + b"\x00\x00\x00\x00",
    PRESENT | VALID | HAS_SEQUENCE | REPORTER | NODE_A,
    1, 1, 0xabcd, 20, NODE_A_MAC)

# The record's wire length includes a complete node announcement, but its
# captured length stops four bytes early.  It must be reported as truncated,
# never as a valid or malformed fully captured TLV list.
truncated_body = supervision_header(1, 1, 0x1234) + tlv(20, NODE_A_MAC) + b"\x00\x00"
truncated_frame, _ = ethernet(truncated_body, source(7))
add("truncated", 7, truncated_body,
    PRESENT | TRUNCATED | HAS_SEQUENCE | REPORTER,
    0, 0, 0x1234, captured_length=len(truncated_frame) - 4)

# Unknown, length-bounded TLVs are skipped without invalidating the known
# supervision header or preventing a later EOT.
add("unknown-tlv", 8,
    supervision_header(1, 1, 0x8888) + tlv(99, b"abc") + b"\x00\x00",
    PRESENT | VALID | HAS_SEQUENCE | REPORTER | EOT,
    1, 1, 0x8888)

# Only type 0 / length 0 is EOT.  A nonzero EOT length is malformed.
add("bad-eot", 9,
    supervision_header(1, 1, 0x9999) + b"\x00\x01\x00",
    PRESENT | MALFORMED | HAS_SEQUENCE | REPORTER,
    0, 0, 0x9999)

# Repeated roles keep their first observation and explicitly report conflict.
add("claim-conflict", 10,
    supervision_header(1, 5, 0x5555) + tlv(20, NODE_A_MAC) +
    tlv(20, ALT_NODE_A_MAC) + b"\x00\x00",
    PRESENT | VALID | HAS_SEQUENCE | REPORTER | NODE_A | EOT |
    CLAIM_CONFLICT,
    1, 5, 0x5555, 20, NODE_A_MAC)


with open(pcap_path, "wb") as output:
    output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for second, frame, captured_length in records:
        output.write(struct.pack("<IIII", second, 0, captured_length, len(frame)))
        output.write(frame[:captured_length])

# Separate report windows must not retain a prior reporter's role claims.
# Re-use the outer Ethernet flow key, but announce a different node after the
# first one has been emitted and reset by the one-second reporting interval.
for second, sequence, node in ((1, 0x7001, NODE_A_MAC),
                               (3, 0x7002, ALT_NODE_A_MAC)):
    body = supervision_header(1, 1, sequence) + tlv(20, node) + b"\x00\x00"
    frame, _ = ethernet(body, source(11))
    reset_records.append((second, frame))

with open(reset_path, "wb") as output:
    output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for second, frame in reset_records:
        output.write(struct.pack("<IIII", second, 0, len(frame), len(frame)))
        output.write(frame)

with open(expected_path, "w", encoding="utf-8") as output:
    json.dump({
        "records": expected,
        "reset": {
            "reporter": source(11).hex(),
            "flags": PRESENT | VALID | HAS_SEQUENCE | REPORTER | NODE_A | EOT,
            "nodes": {"28673": NODE_A_MAC.hex(), "28674": ALT_NODE_A_MAC.hex()},
        },
    }, output, sort_keys=True)
PY
then
   pass "generated PRP supervision regression capture"
else
   fail "could not generate PRP supervision regression capture"
fi

run_sensor() {
   label="$1"
   pcap_path="$2"
   output_path="$3"
   shift 3
   log_path="$output_path.log"

   HOME="$WORKDIR/home" "$ARGUS_BIN" -X "$@" -r "$pcap_path" \
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

   if grep -qi "AddressSanitizer\|runtime error\|ArgusFree: buffer error\|abort\|SIGABRT\|Segmentation" "$log_path"; then
      fail "$label logged a parser or sanitizer error (see $log_path)"
   else
      pass "$label logged no parser or sanitizer error"
   fi
}

mkdir -p "$WORKDIR/home"
run_sensor "PRP supervision replay" "$WORKDIR/input.pcap" "$WORKDIR/supervision.argus" -m
run_sensor "PRP supervision control replay" "$WORKDIR/input.pcap" "$WORKDIR/control.argus" -C
run_sensor "PRP supervision report-window replay" "$WORKDIR/reset.pcap" "$WORKDIR/reset.argus" -S 1

if python3 - "$WORKDIR/supervision.argus" "$WORKDIR/control.argus" \
                "$WORKDIR/reset.argus" "$WORKDIR/expected.json" <<'PY'
import json
import struct
import sys

normal_path, control_path, reset_path, expected_path = sys.argv[1:]
with open(expected_path, encoding="utf-8") as input_file:
    expected_input = json.load(input_file)
expected = expected_input["records"]

FAR_TYPE = 0x10
NETWORK_TYPE = 0x30
NETWORK_PRP_SUBTYPE = 0x46
NETWORK_PRP_WORDS = 11
DATA_TYPE = 0x50
VLAN_TYPE = 0x40


def dsr_words(data, offset, end):
    if end - offset < 4:
        raise AssertionError("truncated DSR header")
    type_code, subtype, _, short_words = struct.unpack_from("!BBBB", data, offset)
    if type_code & 0x80:
        words = 1
    elif subtype & 0x80:
        words = struct.unpack_from("!H", data, offset + 2)[0]
    else:
        words = short_words
    if words == 0 or offset + words * 4 > end:
        raise AssertionError("invalid DSR length")
    return type_code, subtype, words


def flow_records(path):
    data = open(path, "rb").read()
    result = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise AssertionError("truncated record header")
        type_code, _, words = struct.unpack_from("!BBH", data, offset)
        end = offset + words * 4
        if words == 0 or end > len(data):
            raise AssertionError("invalid record length")
        if (type_code & 0xf0) == FAR_TYPE:
            dsrs = []
            cursor = offset + 4
            while cursor < end:
                dsr_type, subtype, dsr_len = dsr_words(data, cursor, end)
                dsrs.append((dsr_type, subtype, cursor, dsr_len))
                cursor += dsr_len * 4
            if cursor != end:
                raise AssertionError("DSR chain does not end at record boundary")
            result.append((data, dsrs))
        offset = end
    return result


def supervision_record(data, dsrs):
    matches = [(offset, words) for kind, subtype, offset, words in dsrs
               if (kind & 0x7f) == NETWORK_TYPE and subtype == NETWORK_PRP_SUBTYPE]
    if len(matches) != 1:
        raise AssertionError("expected exactly one PRP Network DSR")
    offset, words = matches[0]
    if words != NETWORK_PRP_WORDS:
        raise AssertionError("PRP Network DSR is not the fixed 11-word layout")
    flags, version, sequence = struct.unpack_from("!IHH", data, offset + 4)
    values = {
        "flags": flags,
        "version": version,
        "sequence": sequence,
        "path": data[offset + 12],
        "node_mode": data[offset + 13],
        "reporter": data[offset + 14:offset + 20].hex(),
        "node_a": data[offset + 20:offset + 26].hex(),
        "node_b": data[offset + 26:offset + 32].hex(),
        "redbox": data[offset + 32:offset + 38].hex(),
        "vdan": data[offset + 38:offset + 44].hex(),
    }
    return values


normal = {}
normal_dsrs = {}
for data, dsrs in flow_records(normal_path):
    value = supervision_record(data, dsrs)
    reporter = value["reporter"]
    if reporter in normal:
        raise AssertionError("duplicate reporter flow: " + reporter)
    normal[reporter] = value
    normal_dsrs[reporter] = dsrs

if set(normal) != set(expected):
    raise AssertionError("wrong PRP supervision reporters: %r" % sorted(normal))

for reporter, want in expected.items():
    got = normal[reporter]
    for field in ("flags", "version", "path", "sequence", "node_mode", "reporter"):
        if got[field] != want[field]:
            raise AssertionError("%s: %s is %r, expected %r" %
                                 (want["name"], field, got[field], want[field]))
    for field in ("node_a", "node_b", "redbox", "vdan"):
        want_value = want[field]
        if want_value is None:
            want_value = "000000000000"
        if got[field] != want_value:
            raise AssertionError("%s: %s is %r, expected %r" %
                                 (want["name"], field, got[field], want_value))

# The VLAN supervision frame must retain its regular VLAN DSR as well as PRP
# metadata, proving 0x88fb was recognized after the tag rather than before it.
vlan_reporters = [key for key, value in expected.items() if value["vlan"]]
assert vlan_reporters == ["020000000102"]
if not any((kind & 0x7f) == VLAN_TYPE for kind, _, _, _ in normal_dsrs[vlan_reporters[0]]):
    raise AssertionError("post-VLAN PRP frame did not retain a VLAN DSR")

# Check -C's regular User Data DSR path, including the full payload through a
# validated RCT/FCS.  Its bytes begin at the post-VLAN EtherType payload.
control = {}
for data, dsrs in flow_records(control_path):
    value = supervision_record(data, dsrs)
    reporter = value["reporter"]
    matches = [(offset, words) for kind, _, offset, words in dsrs
               if (kind & 0x7f) == DATA_TYPE]
    if len(matches) != 1:
        raise AssertionError("expected one User Data DSR for " + reporter)
    offset, words = matches[0]
    if words < 2:
        raise AssertionError("short User Data DSR")
    count = struct.unpack_from("!H", data, offset + 6)[0]
    payload = data[offset + 8:offset + 8 + count]
    control[reporter] = payload.hex()

if set(control) != set(expected):
    raise AssertionError("control replay omitted a supervision flow")
for reporter, want in expected.items():
    if control[reporter] != want["control_payload"]:
        raise AssertionError("control payload was not retained for " + want["name"])

# After Argus sends the first report window, ArgusZeroRecord drops the bounded
# PRP Network DSR. The next frame sharing the same L2 flow must therefore
# start a fresh claim set rather than retaining the first node or reporting a
# false conflict.
reset_want = expected_input["reset"]
reset_values = []
for data, dsrs in flow_records(reset_path):
    value = supervision_record(data, dsrs)
    if value["reporter"] == reset_want["reporter"]:
        reset_values.append(value)
if len(reset_values) < 2:
    raise AssertionError("expected two PRP supervision report-window outputs")
seen_reset_sequences = {}
for value in reset_values:
    if value["sequence"] in (0x7001, 0x7002):
        if value["flags"] != reset_want["flags"]:
            raise AssertionError("report-window reset retained stale supervision flags")
        if value["flags"] & 0x00001000:
            raise AssertionError("report-window reset reported a stale claim conflict")
        seen_reset_sequences[str(value["sequence"])] = value["node_a"]
if seen_reset_sequences != reset_want["nodes"]:
    raise AssertionError("report-window reset retained a stale node claim")
PY
then
   pass "PRP supervision Network DSR parsing, bounds, RCT boundary, and control capture are correct"
else
   fail "PRP supervision output validation failed"
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
