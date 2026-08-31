# Argus Data Model & DSR Reference

**Status:** Verified against source.
**Source of truth:** `include/argus_out.h`, `include/argus_def.h` in the sensor repo (as of commit
`a74b1239`, Aug 2026, VERSION 5.0.3), cross-checked against DSR-populating code in both the sensor repo
(`~/Saber/argus/argus`) and the client repo (`~/Saber/argus/clients`).
**Supersedes:** the "Data Structures" and "DSR (Destination Specific Record) System" sections previously
found in `ARCHITECTURE.md` and `docs/architecture.md`, which described a simplified/inaccurate model
(non-existent fields, wrong DSR names, wrong values). Those sections should be rewritten to point here.

This document describes the actual on-disk/on-wire binary format Argus uses to encode flow, management,
and event records, and the corresponding in-memory C structures. If you are building a downstream parser,
integrating with a collector, or doing security review of the parsing code, this is the layer to understand
first — nearly every protocol parser in `argus/Argus*.c` ultimately populates one or more of these structures.

### Sensor model vs. client model — read this before the DSR table

**The `ArgusFlow`/DSR type space defined in the header files is shared by both the sensor and the client
programs, but the two do not populate the same subset of it.** This is a deliberate architectural split,
not an inconsistency:

- **The sensor** (`argus` daemon, this repo) can only produce DSRs that are derivable from packet content
  or packet dynamics as observed at capture time — addresses, ports, protocol fields, TCP state, timing,
  jitter, MPLS/VLAN/tunnel headers, etc. It has no access to external context (routing tables, DNS,
  geolocation databases, other flow records) at the moment it emits a record.
- **The clients** (`argus-clients` repo — `radium`, `racluster`, `ralabel`, `radns`, `rahisto`, etc.)
  operate on already-emitted flow records, often streams of them, and can therefore add DSRs that require
  either (a) cross-record correlation, (b) external reference data, or (c) aggregation across many records
  — none of which a single-packet-at-a-time sensor can do. Examples confirmed directly in the clients
  source: `ralabel`/`common/argus_label_geoip.c` (GeoIP city/country lookup — external database, not in
  any packet), `common/argus_label.c` (record correlation/labeling), `racluster`/`racount`
  (`ARGUS_AGR_DSR` — statistical aggregation across many records), `radns` (DNS name resolution/labeling).

This split is *why* several DSR array indices are "shared" between two differently-named DSRs in the
header — the header defines one flat index space for both programs, but sensor and client each only ever
populate one member of a given shared slot, so there's no actual runtime collision. Each entry in the table
in §4 is now labeled **Sensor** or **Client** based on direct confirmation of where it's populated in source
(searched for `dsrs[ARGUS_..._INDEX] = ` across both repos), rather than left as an open question.

---

## 1. Record Types (top level)

Every record on the wire starts with a 4-byte `ArgusRecordHeader`:

```c
// include/argus_out.h:975
struct ArgusRecordHeader {
   unsigned char type;   // record type (see below) + version, packed
   unsigned char cause;  // cause code + options, packed
   u_int16_t     len;    // total record length in 32-bit words? see note below
};
```

The `type` byte is nominally 4 bits of record-type and 4 bits of version (see comment at
`include/argus_def.h` line ~962), and `cause` is 4 bits of cause code plus 4 bits of options.
The implementation keeps these as two full bytes (not C bitfields) specifically to avoid
endianness/bitfield portability issues across platforms — see the comment directly above
`struct ArgusRecordHeader` in `argus_out.h`.

**Record type values** (`include/argus_def.h:150-158`):

| Constant | Value | Meaning |
|---|---|---|
| `ARGUS_MAR` | `0x80` | Management/status record (sensor health, not a flow) |
| `ARGUS_FAR` | `0x10` | Flow Audit Record — the normal flow record |
| `ARGUS_INDEX` | `0x20` | Index record |
| `ARGUS_NETFLOW` | `0x30` | Record originated from imported Cisco NetFlow |
| `ARGUS_EVENT` | `0x40` | Event/message record |
| `ARGUS_FLOW` | `0x50` | Flow/metric record for non-Argus-native flow data |
| `ARGUS_DATASUP` | `0x60` | Supplemental data record |
| `ARGUS_ARCHIVAL` | `0x70` | Archival data record |

**Record version** (`include/argus_def.h:174-181`): current default is `ARGUS_VERSION_5` (5.x wire format).
Argus can still read/write older wire formats — see `argus_def_v2.h`, `argus_v3_def.h`. **A parser or
security reviewer must check the version field and select the correct struct layout**; the v2/v3/v5 DSR
type codes and struct shapes are not interchangeable (see §5).

**Cause codes** (`include/argus_def.h:203-215`) — describes *why* this record was emitted, e.g.:

| Constant | Value | Meaning |
|---|---|---|
| `ARGUS_START` | `0x10` | Initial record for a new flow |
| `ARGUS_STATUS` | `0x20` | Continuation/status update for an existing flow |
| `ARGUS_STOP` | `0x30` | Flow closed/terminated normally |
| `ARGUS_TIMEOUT` | `0x40` | Flow record timed out |
| `ARGUS_FLUSH` | `0x50` | System-initiated flush |
| `ARGUS_SHUTDOWN` | `0x60` | Administrative shutdown |
| `ARGUS_CLOSED` | `0x70` | Argus-initiated shutdown |
| `ARGUS_ERROR` | `0x80` | Major error condition |
| `ARGUS_MAR_SUPPLEMENTAL` | `0x90` | Supplemental MAR |
| `ARGUS_MAR_INTERFACE` | `0xA0` | Interface-specific MAR |

**The top-level record union** (`include/argus_out.h:981`):

```c
struct ArgusRecord {
   struct ArgusRecordHeader hdr;
   union {
      struct ArgusMarStruct    mar;    // ARGUS_MAR
      struct ArgusMarInfStruct inf;    // ARGUS_MAR_INTERFACE
      struct ArgusMarSupStruct sup;    // ARGUS_MAR_SUPPLEMENTAL
      struct ArgusFarStruct    far;    // ARGUS_FAR
      struct ArgusEventStruct  event;  // ARGUS_EVENT
   } ar_un;
};
```

Which member of `ar_un` is valid is determined entirely by `hdr.type`. This union pattern (fixed header +
type-discriminated union) repeats at every level of the format, and is the single most important thing to
understand about this codebase's data model.

---

## 2. Flow Records (`ARGUS_FAR`)

A flow record's body is:

```c
// include/argus_out.h:958
struct ArgusFarStruct {
   struct ArgusFlow flow;
};
```

`struct ArgusFlow` (`argus_out.h:490`) is itself a DSR header plus a union of **16** protocol-specific flow
descriptors — this is the flow 5-tuple (or equivalent) that identifies *which* flow this record is about:

```c
struct ArgusFlow {
   struct ArgusDSRHeader hdr;
   union {
      struct ArgusIPv6Flow       ipv6;     // IPv6 5-tuple
      struct ArgusIPFlow           ip;     // IPv4 5-tuple
      struct ArgusEtherMacFlow    mac;     // L2 MAC pair
      struct ArgusICMPv6Flow   icmpv6;
      struct ArgusICMPFlow       icmp;
      struct ArgusIGMPv6Flow   igmpv6;
      struct ArgusIGMPFlow       igmp;
      struct ArgusESPv6Flow     espv6;
      struct ArgusESPFlow         esp;
      struct ArgusArpFlow         arp;
      struct ArgusRarpFlow       rarp;
      struct ArgusIPv6FragFlow fragv6;
      struct ArgusIPFragFlow     frag;
      struct ArgusLcpFlow         lcp;
      struct ArgusIsisFlow       isis;
      struct ArgusWlanFlow       wlan;
      struct ArgusUdtFlow         udt;
   } flow_un;
};
```

The two most common members in practice, for ordinary IP traffic:

```c
struct ArgusIPFlow {                  // argus_out.h:462
   unsigned int   ip_src, ip_dst;      // IPv4 addresses, network byte order
   unsigned char  ip_p, tp_p;          // IP protocol number, transport protocol
   unsigned short sport, dport;        // ports (0 for non-port protocols)
   unsigned char  smask, dmask;        // subnet mask bits, if aggregated
};

struct ArgusIPv6Flow {                // argus_out.h:469
   unsigned int   ip_src[4], ip_dst[4];
   unsigned int   flow:20, resv:4, ip_p:8;  // IPv6 flow label + protocol (bit order is endian-dependent!)
   unsigned short sport, dport;
   unsigned short smask, dmask;
};
```

**Security note:** the `IPv6Flow`/`ICMPv6Flow`/`IGMPv6Flow`/`ESPv6Flow` structs pack a 20-bit flow label and
an 8-bit protocol field into a 32-bit bitfield whose layout is conditional on `_LITTLE_ENDIAN`. Any code that
serializes/deserializes these fields across architectures, or that a fuzzer/reviewer inspects, needs to
account for this — it's a classic source of cross-platform parsing bugs.

Everything else about a flow (its metrics, timing, TCP state, etc.) is **not** stored inline in
`ArgusFarStruct` — it lives in the DSR chain, described next. `struct ArgusFarStruct` only carries the flow
*key*.

---

## 3. The DSR Chain — how a full flow record is actually assembled

The in-memory, fully-parsed representation of one flow is `struct ArgusRecordStruct`
(`include/argus_out.h:1061`), which contains a fixed-size array of DSR pointers:

```c
#define ARGUSMAXDSRTYPE   25          // argus_def.h:322

struct ArgusRecordStruct {
   struct ArgusQueueHeader qhdr;
   unsigned int status, dsrindex, trans, autoid;
   ...
   struct ArgusDSRHeader *dsrs[ARGUSMAXDSRTYPE];   // <-- the DSR chain
   ...
};
```

`dsrindex` is a bitmask (one bit per array slot) indicating which DSR slots are populated for this record —
`ArgusModeler.c` sets/clears bits as it fills in `dsrs[ARGUS_x_INDEX]` while processing a flow (e.g.
`flow->dsrs[ARGUS_METRIC_INDEX] = ...` at `ArgusModeler.c:2367`). This is why the wire format is
self-describing/extensible: a reader walks the DSR chain and only interprets slots that are actually present.

On the wire (and in the backing `struct ArgusCanonRecord`, `argus_out.h:1029`), each DSR begins with the
same 2–4 byte header:

```c
// argus_out.h:76
struct ArgusDSRHeader {
   unsigned char type;      // DSR type code, see table in §4
   unsigned char subtype;   // DSR-specific subtype/qualifier
   union {
      struct ArgusDSRfixLen      fl;    // fixed 2-byte value  (TV form)
      struct ArgusDSRvar8bitLen  vl8;   // qual(1) + len(1)    (TLV form, short)
      struct ArgusDSRvar16bitLen vl16;  // len(2)              (TLV form, long)
   } dsr_un;
};
```

### TV vs. TLV encoding (from `argus_def.h` lines ~330-360, verbatim wire diagram)

Argus DSRs come in two shapes, distinguished by the high bit of the type byte:

**Type-Value (TV), fixed 4 bytes total, `type` bit7 = 1 (i.e. type >= 0x80):**
```
 0               1               2               3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1|    Type     |    SubType    |          Argus DSR Data       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Type-Length-Value (TLV), variable length, `type` bit7 = 0:**
```
 0               1               2               3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|    Type     |    SubType    |   Qualifier   |     Length    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Argus DSR Data ...                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

All DSRs are 32-bit aligned. For TLV records, the SubType field's own high bit (`ARGUS_LEN_16BITS = 0x80`,
`argus_def.h:423`) indicates whether the length that follows is 8-bit (`vl8.len`) or 16-bit (`vl16.len`) —
i.e. the length-width is itself encoded in a bit of the subtype byte, not a separate flag. **This is a subtle
and important detail for anyone hand-writing a parser or fuzz harness**: you cannot know how many length
bytes to read without first inspecting bit 7 of subtype.

**Length units are 32-bit words, not bytes** — confirmed at both the record level and the DSR level:
- Record level: every read site multiplies by 4, e.g. `len = ntohs(output->ArgusInitMar->hdr.len) * 4;`
  (`ArgusOutput.c:214`), and the writer sets `retn->hdr.len = sizeof(struct ArgusRecord) / 4` (`ArgusModeler.c:1652`).
- DSR level: writers set `len` directly in words, e.g. `flow->hdr.argus_dsrvl8.len = 5` for a 20-byte flow
  struct, `mac->hdr.argus_dsrvl8.len = 5` (`ArgusModeler.c:2081`, `2457`). A DSR's length in bytes is
  therefore `len * 4`.

This resolves what was previously an open question in this document (see §8 history) — **do not multiply
or divide by anything other than 4** when converting between the on-wire `len` field and an actual byte
count, at either the record or DSR level.

---

## 4. Complete DSR Type Table (v5, current)

This is the authoritative list, cross-referenced from `include/argus_def.h` type/index `#define`s and
confirmed against actual `dsrs[ARGUS_x_INDEX] = ...` assignments — searched across **both** the sensor
repo (`~/Saber/argus/argus`) and the client repo (`~/Saber/argus/clients`) to determine, per DSR, whether
it is produced by the sensor at capture time, by client-side post-processing, or both. See the "Sensor
model vs. client model" note at the top of this document for why the split exists.

| Index | Type constant | Type code | Backing struct | Produced by | Purpose |
|---|---|---|---|---|---|
| 0 | `ARGUS_TRANSPORT_DSR` | `0x01` | `ArgusTransportStruct` | **Sensor** | Source ID + sequence number (identifies which probe/record-stream this came from) |
| 1 | `ARGUS_FLOW_DSR` | `0x02` | `ArgusFlow` (see §2) | **Sensor** | Flow key / 5-tuple, derived directly from packet headers |
| 2 | `ARGUS_TIME_DSR` | `0x03` | `ArgusTimeObject` | **Sensor** | Start/end timestamps, src & dst |
| 3 | `ARGUS_METER_DSR` (metric) | `0x10` | `ArgusMetricStruct` | **Sensor** | Packet/byte/appbyte counters, src & dst — direct packet-dynamics measurement |
| 4 | `ARGUS_AGR_DSR` | `0x60` | `ArgusAgrStruct` | **Client** (`racluster`, `racount`) | Aggregation count + activity/idle stats across *multiple* records — inherently a multi-record client capability, not a per-packet sensor one |
| 5 | `ARGUS_NETWORK_DSR` | `0x30` | `ArgusNetworkStruct` (union: TCP/ICMP/UDT/RTP/IGMP/DHCP/ESP/ARP/AH/LCP/ISIS) | **Sensor** | Protocol-specific state (e.g. TCP handshake/seq/ack), all derived from packet content |
| 5 *(shares slot)* | `ARGUS_FRAG_DSR` | — | `ArgusFragObject` | **Sensor** | IP fragmentation reassembly state — mutually exclusive with `ARGUS_NETWORK_DSR` per record (a record is either about fragmentation or normal protocol state, never both), so the shared index is safe |
| 6 | `ARGUS_VLAN_DSR` | `0x40` | `ArgusVlanStruct` | **Sensor** | Source/dest VLAN IDs, read directly from the 802.1Q header |
| 7 | `ARGUS_MPLS_DSR` | `0x44` | `ArgusMplsStruct` | **Sensor** | Source/dest MPLS labels, read directly from the MPLS shim header |
| 8 | `ARGUS_JITTER_DSR` | `0x46` | `ArgusJitterStruct` | **Sensor** | Active/idle jitter statistics — computed from inter-packet arrival timing at capture time |
| 9 | `ARGUS_IPATTR_DSR` | `0x48` | `ArgusIPAttrStruct` | **Sensor** | TTL, TOS, IP ID, IP-options presence — all raw IP header fields |
| 10 | `ARGUS_PSIZE_DSR` | `0x12` | `ArgusPacketSizeStruct` | **Sensor** | Packet-size distribution histogram — computed from observed packet lengths |
| 11 | `ARGUS_DATA_DSR` (src) | `0x50` | `ArgusDataStruct` | **Sensor** | Captured source user/application data (raw payload bytes, if capture is enabled) |
| 12 | `ARGUS_DATA_DSR` (dst) | `0x50` | `ArgusDataStruct` | **Sensor** | Captured destination user/application data |
| 13 | `ARGUS_MAC_DSR` | `0x42` | `ArgusMacStruct` | **Sensor** | Layer-2 MAC header info |
| 14 | `ARGUS_ICMP_DSR` | `0x34` | `ArgusIcmpStruct` | **Sensor** (`ArgusIcmp.c`) | ICMP type/code/etc. |
| 15 | `ARGUS_ENCAPS_DSR` | `0x20` | `ArgusEncapsStruct` | **Sensor** | Encapsulation byte counts/buffers (tunneling overhead accounting) |
| 16 | *(time-adjust, `ARGUS_TIME_ADJ_INDEX`)* | — | — | **Sensor** | Clock-drift adjustment bookkeeping (see MAR `drift` field, §6) |
| 17 | `ARGUS_BEHAVIOR_DSR` | `0x54` | `ArgusBehaviorStruct` | **Sensor** (`ArgusTcp.c`) | TCP/SSH keystroke-timing behavior detection — derived purely from packet inter-arrival dynamics |
| 17 *(shares slot)* | `ARGUS_COR_DSR` | `0x62` | `ArgusCorrelateStruct` | **Client** (`common/argus_client.c`) | Cross-record correlation metadata — requires seeing multiple related records, impossible for a single-packet-driven sensor |
| 18 | `ARGUS_HISTO_DSR` | `0x47` | `ArgusHistoObject` | **Client** (`rahisto`, `ratop`) | General-purpose histogram DSR used by client-side analysis/visualization tools |
| 18 *(shares slot)* | `ARGUS_COCODE_DSR` | `0x64` | `ArgusCountryCodeStruct` | **Client** (`ralabel` / `argus_label_geoip.c`) | Geo-IP country code lookup — external database, not derivable from packet content |
| 19 | `ARGUS_LABEL_DSR` | `0x66` | `ArgusLabelStruct` | **Client** (`common/argus_label.c`) | Free-form service/classification label attached during client-side labeling/enrichment |
| 20 | `ARGUS_ASN_DSR` | `0x32` | `ArgusAsnStruct` | **Client** (`argus_label.c`, `argus_label_geoip.c`) — **with one sensor exception**, see note below | Source/dest/intermediate Autonomous System numbers |
| 21 | `ARGUS_FLOW_HASH_DSR` | `0x07` | `ArgusFlowHashStruct` | **Sensor** | Precomputed flow hash + index, used for hash-table lookup during flow aggregation |
| 22 | `ARGUS_VXLAN_DSR` | `0x43` | `ArgusVxLanStruct` | **Sensor** | VXLAN VNI + inner flow, read directly from the VXLAN header |
| 23 | `ARGUS_GRE_DSR` | `0x41` | `ArgusGreStruct` | **Sensor** | GRE flags/proto + inner flow |
| 24 | `ARGUS_GENEVE_DSR` | `0x45` | `ArgusGeneveStruct` | **Sensor** | Geneve VNI/options + inner flow |

**Note on `ARGUS_ASN_DSR` (index 20):** the sensor's `ArgusNetflow.c` (NetFlow v9/IPFIX *import* path) also
writes this DSR. This is not a counterexample to the sensor/client rule above — it's consistent with it: a
NetFlow v9 exporter (typically a router) can embed an ASN value that it derived from its own routing table
before ever sending the record to Argus. The Argus sensor is not deriving the ASN from packet content in
this case, it is simply passing through a field that arrived pre-populated in an externally-generated
NetFlow record. When Argus itself is the flow generator (packets captured directly off the wire, not
imported NetFlow), ASN population is exclusively a client-side (`ralabel`) operation.

**Every index-sharing case above (5, 17, 18) is now resolved and explained** — each pair is either mutually
exclusive within the sensor (index 5) or split cleanly along the sensor/client boundary (17, 18), so there
is no genuine runtime ambiguity in the current codebase. This replaces the open question in the previous
revision of this document.

Additional type codes exist for less common protocols and were not individually re-verified for this
revision — confirm current usage in source before relying on them: `ARGUS_IB_DSR (0x35)`,
`ARGUS_ISIS_DSR (0x36)`, `ARGUS_RSVP_DSR (0x37)`, `ARGUS_ESP_DSR (0x38)`, `ARGUS_LCP_DSR (0x39)`.

---

## 5. Version compatibility (v2 / v3 / v5)

This codebase carries **three parallel DSR type systems** for backward compatibility:

- **v5 (current default, `ARGUS_VERSION_5`)** — described above, defined in `include/argus_def.h`.
- **v3** — `include/argus_v3_def.h` (1082 lines), its own struct set (`ArgusV3MarStruct`,
  `ArgusV3AddrStruct`, `ArgusV3TransportStruct`, etc.), largely paralleling v5 but not binary compatible.
- **v2 (legacy)** — `include/argus_def_v2.h`, with an entirely distinct type-code namespace, e.g.
  `ARGUS_V2_TCP_DSR = 0x11`, `ARGUS_V2_MPLS_DSR = 0x28`, `ARGUS_V2_ARP_DSR = 0x20` — **these numeric values
  overlap/collide with unrelated v5 type codes** (e.g. v5 `ARGUS_ARP` semantics live inside the `ArgusFlow`
  union, not as a standalone DSR type 0x20 the way v2 encodes it). **Any parser, fuzzer, or security review
  must gate all type-code interpretation on the record's version field first** — interpreting a v2 record's
  bytes using v5 type-code meanings (or vice versa) will silently produce wrong data rather than an error.

The cookie values used to identify a MAR/stream as belonging to a given version are explicit constants:

```c
#define ARGUS_V2_COOKIE   0xE5617ACB
#define ARGUS_V3_COOKIE   0xE5712DCB
#define ARGUS_V5_COOKIE   0xE57150CB
#define ARGUS_COOKIE      ARGUS_V5_COOKIE   // current default
```

---

## 6. Management (MAR) and Event Records

Not every record is a flow. Two other top-level bodies matter for CONOPS/ops-health purposes:

**`ArgusMarStruct`** (`argus_out.h:855`) — periodic sensor status/heartbeat record. Notable fields:
`pktsRcvd`/`bytesRcvd` (totals), `records`/`flows`/`dropped` (processing health), `queue`/`output`/`clients`
(internal queue depth and connected client count), `fallow` (fallow-TCP-queue count — see recent commit
history on `ARGUS_TCP_FALLOW_TIMEOUT`), `interfaceType`/`interfaceStatus`. **This is the record type an
operator/CONOPS document should point to for "is my sensor healthy and keeping up" monitoring.**

**`ArgusEventStruct`** (`argus_out.h:847`) — carries transport + time + a `ArgusDataStruct` payload for
out-of-band system events/messages (not traffic flows).

---

## 7. Practical guidance for downstream work

For **CONOPS / data handling** documentation:
- The flow key (`ArgusFlow`) contains raw IP/MAC addresses and, depending on config, captured
  application-layer bytes (`ArgusDataStruct` via `ARGUS_DATA_DSR`). Any data-sensitivity/retention
  discussion needs to explicitly address whether `ARGUS_USER_DATA` capture (subtype `0x03`,
  `argus_def.h` ~1770) is enabled, since that is raw payload capture, not metadata.
- MAR records are the correct basis for sensor-health monitoring language in a CONOPS/runbook.
- **The sensor/client split (see top of this document) should shape the CONOPS deployment model directly.**
  If SABER's use case requires GeoIP labeling, ASN attribution, DNS labeling, cross-record correlation, or
  flow aggregation/clustering, those are **not** sensor features — they require deploying and operating the
  corresponding client-side tooling (`ralabel`, `radns`, `racluster`, `radium`, etc. from the clients repo)
  downstream of the sensor. The CONOPS should describe this as a two-tier architecture (sensor tier +
  enrichment/correlation tier), not assume the sensor alone produces analyst-ready enriched records.
- Conversely, anything the sensor *does* claim to produce (§4, "Sensor" column) is derivable purely from
  observed packet content/dynamics — useful for CONOPS language about what the sensor can attest to
  independent of any external data source or third-party database.

For **security review**:
- Highest-risk surface is anywhere raw packet bytes are used to populate the `ArgusFlow` union or
  `ArgusNetworkStruct` union in `ArgusModeler.c` and the protocol parsers — bounds/length validation on
  attacker-controlled TLV `len` fields (§3) should be reviewed first.
  Pay particular attention to the 20-bit bitfield packing in IPv6-family flow structs (§2) for
  endianness-dependent parsing bugs.
- The three-version type-code system (§5) is a review target in its own right: confirm every consumer of
  a DSR/record `type` byte first branches on record version before interpreting type codes.
- **Scoping note:** since this repo (the sensor) never parses or writes the client-only DSRs (`AGR`, `COR`,
  `HISTO`, `COCODE`, `LABEL`, and normally `ASN`), a security review of *this* codebase can exclude those
  code paths entirely — they don't exist here. They should instead be in scope for a separate review of the
  `~/Saber/argus/clients` repo. This meaningfully narrows the sensor's attack surface to the DSRs marked
  "Sensor" in §4, all of which are populated directly from untrusted packet bytes and are therefore the
  correct fuzzing/review priority for the sensor specifically.

---

## 8. Open items / follow-up verification

Resolved in this revision (previously flagged as open): the shared-index ambiguity for indices 5, 17, and
18 is now explained by the sensor/client split (§4); the client repo is available and was used to confirm
attribution directly rather than by inference. The TLV/record length-unit question (bytes vs. words) is
also resolved — confirmed to be 32-bit words at both the record and DSR level (§3).

Still open:

1. Confirm whether `ARGUS_ICMP_DSR` is ever written standalone vs. only ever nested inside
   `ArgusNetworkStruct`'s `net_union` — the type constant exists independently but current call sites
   (`ArgusIcmp.c:351`) suggest it may always be reached via the network-DSR union path.
2. `ARGUS_IB_DSR`, `ARGUS_ISIS_DSR`, `ARGUS_RSVP_DSR`, `ARGUS_ESP_DSR`, `ARGUS_LCP_DSR` were not
   individually re-verified for sensor-vs-client attribution in this pass — do so before relying on them.
3. This document has not yet been cross-checked against `man/man8/argus.8` for consistency — worth doing
   as a final pass once the architecture doc rewrite is complete.
