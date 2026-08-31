# Argus Sensor Architecture

**Status:** Verified against source.
**Scope:** This document covers the **Argus sensor only** (`~/Saber/argus/argus`, the `argus` daemon) —
the packet-capture, flow-classification, and record-generation engine. It does not cover the client
programs (`ra`, `racluster`, `radium`, `ralabel`, etc., in `~/Saber/argus/clients`), except where a client
capability needs to be mentioned to correctly scope what the sensor does *not* do. See
`docs/data-model.md` §"Sensor model vs. client model" for why that boundary matters.
**Supersedes:** this file replaces the previous version's "Core Components," "Data Structures," "DSR
System," "Output System," and "Extension Points" sections, several of which described functions, files,
and mechanisms that do not exist in the source (see inline notes below where a prior claim is corrected).
**Related:** `docs/data-model.md` is the authoritative reference for the wire format, DSR types, and
record structures — this document describes *how the sensor produces* that data, not the format itself.

---

## 1. What the sensor actually does

Argus's job, stated precisely: **process network packets, classify them into flow models, track each
flow's state and aggregate metrics as packets arrive, and periodically emit flow records.** That's the
whole scope. Everything else — correlation across records, enrichment from external data sources
(GeoIP, DNS, ASN lookups), clustering/aggregation across many flows — is a client-side capability and is
architecturally excluded from the sensor by design (it requires data the sensor doesn't have access to at
packet-capture time).

## 2. Process Structure

`main()` (`argus/argus.c:300`) constructs four cooperating components and then runs the capture loop:

```c
ArgusModel      = ArgusNewModeler();                          // flow classification/tracking engine
ArgusSourceTask = ArgusNewSource(ArgusModel);                  // packet capture (libpcap)
ArgusDumpTask   = ArgusNewDump(ArgusSourceTask, NULL);          // optional raw packet capture-to-file
ArgusOutputTask = ArgusNewOutput(ArgusSourceTask, ArgusModel);  // record writer / socket server
```

These map to `struct ArgusSourceStruct`, `struct ArgusModelerStruct`, and `struct ArgusOutputStruct`
respectively (defined in `ArgusSource.h`, `ArgusModeler.h`, `ArgusOutput.h`). If built with
`ARGUS_THREADS` defined, capture, modeling, and output each run on separate `pthread`s (confirmed:
`pthread_create` calls in `ArgusOutput.c:415`, `ArgusEvents.c:120`, and threading-conditional code
throughout `ArgusModeler.c`). Without `ARGUS_THREADS`, the pipeline runs single-threaded, driven by the
same event loop.

```
┌──────────────────────────────────────────────────────────────────────┐
│                            argus daemon                              │
│                                                                       │
│  ┌──────────────┐    ┌───────────────────┐    ┌──────────────────┐   │
│  │ ArgusSource  │───▶│   ArgusModeler     │───▶│   ArgusOutput    │   │
│  │ (capture)    │    │ (classify, track,  │    │ (record write /  │   │
│  │ ArgusSource.c│    │  aggregate)        │    │  socket server)  │   │
│  │              │    │ ArgusModeler.c     │    │ ArgusOutput.c    │   │
│  └──────┬───────┘    └────────────────────┘    └──────────────────┘   │
│         │                                                             │
│         ▼                                                             │
│  ┌──────────────┐                                                     │
│  │ libpcap      │  (interfaces, or -r <file>)                         │
│  └──────────────┘                                                     │
└──────────────────────────────────────────────────────────────────────┘
```

## 3. Core Source Files — verified responsibilities

| File | Approx. size | Actual responsibility (verified) |
|---|---|---|
| `argus/argus.c` | 2,326 lines | `main()`, CLI option parsing (`getopt`), daemonization, config-file loading, privilege drop coordination, signal handling |
| `argus/ArgusSource.c` | 6,681 lines | libpcap interface open/read (`ArgusOpenInterface`, `ArgusInitSource`), packet-format-specific read loops (`ArgusErfRead`, `ArgusSnoopRead`, etc.), BPF filter compilation (`pcap_compile` at line 1063), the packet capture loop (`ArgusGetPackets`, line 5184, driving `pcap_dispatch`) |
| `argus/ArgusModeler.c` | 5,501 lines | Protocol header dispatch (`ArgusProcessPacketHdrs`, a hardcoded `switch` on ethertype — see §6), flow creation/lookup/update (`ArgusCreateFlow`, `ArgusNewFlow`, `ArgusUpdateFlow`), metric tally (`ArgusTallyStats`), record generation (`ArgusGenerateRecord`) |
| `argus/ArgusOutput.c` | 2,282 lines | Record formatting and dispatch to file/socket clients, connected-client management, `ArgusOutputProcess` main loop |
| `argus/ArgusUtil.c` | 2,799 lines | Time handling, string utilities, queue/list primitives |

*(Previous revisions of this document listed these files as 81K/220K/203K/79K/83K, ostensibly byte counts,
but the figures didn't correspond to actual file sizes and several referenced function names —
`ArgusOpenSource()`, `ArgusReadSource()`, `ArgusFlowAlloc()`, a callable `ArgusModeler()` — do not exist
anywhere in source. The names above were confirmed present via direct grep.)*

### Common libraries (`common/`)

| File | Size | Role |
|---|---|---|
| `argus_filter.c` | 3,554 lines | BPF filter expression code generation (consumed by `pcap_compile`) |
| `argus_util.c` | 2,813 lines | Shared utility functions (separate from, and larger than, `argus/ArgusUtil.c`) |
| `argus_code.c` | 5,549 lines | DSR-aware BPF predicate generation — lets filter expressions reference DSR fields (e.g. correlation/country-code comparisons — see `Argusgen_cmp()` calls against `ARGUS_COR_INDEX`/`ARGUS_COCODE_INDEX`, which is filter-expression *support* for those indices, not sensor production of them) |
| `argus_auth.c` | 586 lines | SASL authentication for remote client connections (`#ifdef ARGUS_SASL`), used together with libwrap (`<tcpd.h>`, included in `ArgusOutput.c`) for TCP-wrapper-style access control on the output socket |
| `grammar.y` / `scanner.l` | 458 / 466 lines | yacc/lex grammar for the BPF-style filter expression language |

## 4. Protocol Handling — confirmed mechanism

**Important correction:** there is no per-protocol source file per parser and no plugin/registration
system. Protocol dispatch in `ArgusProcessPacketHdrs()` (`ArgusModeler.c:758`) is a single hardcoded
`switch (type)` statement keyed on Ethernet type / next-header value:

```c
switch (type) {
   case ETHERTYPE_TRANS_BRIDGE: ...
   case ETHERTYPE_PPP: ...
   case ETHERTYPE_PPPOED:
   case ETHERTYPE_PPPOES: ...
   case ETHERTYPE_UDTOE: ...
   case ETHERTYPE_8021Q: ...
   case ETHERTYPE_MPLS_MULTI:
   case ETHERTYPE_MPLS: ...
   case ETHERTYPE_IP: ...
   case ETHERTYPE_IPV6: ...
   case ETHERTYPE_ARP:
   case ETHERTYPE_REVARP: ...
}
```

Some protocols do have their own source file for their state machine/object handling once dispatched
(`ArgusTcp.c`, `ArgusIcmp.c`, `ArgusArp.c`, `ArgusIsis.c`, `ArgusLcp.c`, `ArgusEsp.c`, `Argus802.11.c`),
but there is no formal extension API — adding a new protocol means adding a `case` to this switch, adding
a member to the `ArgusFlow`/`ArgusNetworkStruct` unions (`include/argus_out.h`), and adding a new DSR type
constant in `include/argus_def.h`, all by directly editing these files.

*(A previous revision of this document described a plugin-style extension point — `argus/ArgusCustom.c`
implementing `ArgusParseCustom()` and "registering in protocol chain." No such file, function, or
registration mechanism exists anywhere in this codebase. That section was invented, not derived from
source, and has been removed.)*

For the full list of protocol-specific source files, see `docs/data-model.md` §4 ("Produced by: Sensor"
column), which maps each protocol handler to the DSR type(s) it emits.

## 5. Flow Classification and the DSR Model

Once a packet is dispatched to `ArgusProcessIpPacket()` (or the equivalent for other protocols), Argus:

1. Extracts a flow key into a `struct ArgusFlow` (the protocol-specific union — IP 5-tuple, MAC pair, ARP,
   ICMP, etc.) — see `docs/data-model.md` §2.
2. Looks up or creates a flow entry (`ArgusCreateFlow`, `ArgusNewFlow`, `ArgusModeler.c:2018`/`2152`).
3. Updates per-flow state and metrics as subsequent packets for the same flow arrive
   (`ArgusUpdateFlow`, `ArgusModeler.c:2698`), populating whichever DSR slots apply
   (`flow->dsrs[ARGUS_x_INDEX] = ...`).
4. Periodically (or on flow termination/timeout) generates and emits an output record
   (`ArgusGenerateRecord`, `ArgusModeler.c:3200`).

**The DSR chain is the actual data model** — see `docs/data-model.md` for the full type table, wire
format (TV vs. TLV encoding), and the confirmed set of DSRs the sensor can populate versus the DSRs that
only exist client-side. Do not treat the simplified `struct ArgusFlow` description in older versions of
this document as accurate; the real struct is a 16-member union of protocol-specific flow-key structs, not
a flat struct with `src`/`dst`/`net`/`app` fields.

## 6. Output — confirmed mechanism

**Important correction:** the sensor does not support JSON or CSV output, and does not compress its
output stream. It writes exactly one binary wire format (`docs/data-model.md`), and only over these
transports, all handled by a single `-w` flag:

```
-w <file>                    write to a file, or '-' for stdout
-w argus-udp://host[:port]   stream to a remote collector (default port 561)
-w udp://host[:port]
-w domain://path/to/socket   Unix domain socket
```

Separately, `-P <portnum>` puts the sensor itself into a listening/server role (default port 561),
allowing remote client programs to connect and pull the live record stream — this is the basis for the
"argus (sensor) → ra/racluster/etc." dataflow, and is protected by the SASL (`argus_auth.c`) and
TCP-wrapper (`<tcpd.h>` in `ArgusOutput.c`) mechanisms in §3.

*(A previous revision claimed `-S 0.0.0.0:5100` for socket output, and listed JSON/CSV format conversion
and gzip/zstd compression as output capabilities. All of these are incorrect: `-S <secs>` actually sets
the flow-status report interval (`setArgusFarReportInterval`, confirmed at `argus.c:150,578`), has nothing
to do with sockets, and no JSON/CSV writer or general-purpose output compression code exists anywhere in
`ArgusOutput.c`. zlib is linked but used only for a specific event-record `compress`/`compress2` postproc
option, not general flow-record output.)*

## 7. Configuration — confirmed precedence

**Important correction:** configuration is simpler, and has a different precedence order, than previously
documented. Verified directly from `main()` (`argus.c:300` onward):

1. `/etc/argus.conf` is loaded **unconditionally**, once, near the start of `main()`, *before* command-line
   argument parsing begins — **if the file exists** (`stat()`-gated). It is not one of several
   "default search paths"; it is the only implicit config file.
2. Command-line arguments are then parsed left-to-right in a single `getopt()` pass. `-F <file>` loads an
   additional config file, at exactly the point it appears in the argument list — so `-F` ordering relative
   to other flags matters, and a later flag on the command line can override a value set by an earlier `-F`
   file or by `/etc/argus.conf`.
3. There is **no environment-variable configuration layer** — confirmed by the complete absence of any
   `getenv()` call anywhere in `argus.c`, `ArgusSource.c`, or `ArgusUtil.c`. Variables named `ARGUS_*` in
   `argus.conf` are config-file keys, not environment variables the shell/OS needs to export.
4. There is no `$ARGUSPATH`/`$ARGUSHOME`/`$HOME` auto-search for a config file in this version — the man
   page (`man/man5/argus.conf.5`) explicitly documents this search as deprecated, and no such search code
   exists in `argus.c`.

*(A previous revision of this document described a 4-tier hierarchy — CLI > `-F` files > env vars >
default config files > compiled defaults — with env vars and multiple auto-searched file paths active.
None of that matches the actual single-pass, no-env-var behavior in source.)*

## 8. Privilege and Access Control — confirmed mechanisms

- **Privilege drop is real**, via `-u <userid>`/`-g <groupid>` and confirmed `setuid()`/`setgid()` calls
  (`ArgusSource.c:1046-1047`, `4712-4796`, `4950-5030`). The general pattern (start as root to bind/open a
  capture interface, then drop) is accurate, though it is *not* automatic — it only happens if `-u`/`-g`
  are supplied; without them the daemon continues running with its starting privileges.
- **SASL authentication** for the output socket is real and gated behind an `ARGUS_SASL` build-time flag
  (`common/argus_auth.c`).
- **TCP-wrapper (libwrap) access control** is real, confirmed via `#include <tcpd.h>` in `ArgusOutput.c`.
- **chroot support** exists via `-c <dir>` (`argus.c`), not previously documented.

## 9. Deployment topology

```
┌──────────────┐     -w argus-udp://collector:561      ┌───────────────────────┐
│  argus (this │ ─────────────────────────────────────▶│  Collector host       │
│  sensor)     │                                        │  running client       │
│              │        or: -P 561 (listen for          │  programs (separate   │
│  Probe host  │◀────────── connecting clients) ────────│  repo/scope)          │
└──────────────┘                                        └───────────────────────┘
```

For SABER, each deployed sensor instance is a single `argus` process bound to one or more interfaces
(`-i <interface>`, repeatable), writing either to local files for later batch pickup or streaming live to
a collector. Multiple sensors can feed one collector; the sensor itself has no concept of other sensors
and does no inter-sensor coordination — any multi-sensor correlation is, again, a client-side capability.

## 10. What's intentionally out of scope here

The following are real Argus capabilities but belong to the **client** side and are documented (if at all)
in the clients repo, not here:
- Record correlation, GeoIP/ASN/DNS labeling, flow clustering/aggregation (`racluster`, `ralabel`, `radns`)
- Long-term storage, database integration, visualization (`ratop`, `ramysql` examples)
- `radium` — the client-side flow-record relay/distribution daemon (name collision alert: this is a
  *client* program despite the "-daemon-sounding" name; it is not part of this sensor codebase)

If SABER's CONOPS requires any of the above, the deployment architecture needs a second tier beyond the
sensor described here — see `docs/data-model.md` §7 for how this affects data-handling/CONOPS language.

---

## Open items / follow-up verification

1. The exact set of supported `-r` input formats beyond pcap/cisco-netflow/MOAT-Tsh/ERF/snoop should be
   enumerated fully (partially covered in `ArgusSource.c`'s per-format read functions, not exhaustively
   catalogued here).
2. Multi-threading behavior under `ARGUS_THREADS` (queue depth, lock contention, thread affinity via
   `ARGUS_TILERA` bind_proc calls seen in `ArgusOutput.c`) was confirmed to exist but not characterized in
   detail — worth a dedicated performance-architecture pass if SABER has specific throughput requirements.
3. This document has not yet been cross-checked against `man/man8/argus.8` for full command-line flag
   coverage — the flags cited above were confirmed present but the list in §6/§7 is not exhaustive.
