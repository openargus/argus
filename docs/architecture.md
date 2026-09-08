# Argus Sensor Architecture

**Scope:** This document covers the Argus sensor only (the `argus` daemon) — the packet-capture,
flow-classification, and record-generation engine. It does not cover the client programs (`ra`,
`racluster`, `radium`, `ralabel`, etc., which live in the separate `argus-clients` repository), except
where a client capability needs to be mentioned to correctly scope what the sensor does *not* do. See
`docs/data-model.md` for why that boundary matters.

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
`ARGUS_THREADS` defined, capture, modeling, and output each run on separate `pthread`s. Without
`ARGUS_THREADS`, the pipeline runs single-threaded, driven by the same event loop.

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

## 3. Core Source Files

| File | Approx. size | Responsibility |
|---|---|---|
| `argus/argus.c` | ~2,300 lines | `main()`, CLI option parsing (`getopt`), daemonization, config-file loading, privilege drop coordination, signal handling |
| `argus/ArgusSource.c` | ~6,700 lines | libpcap interface open/read (`ArgusOpenInterface`, `ArgusInitSource`), packet-format-specific read loops (`ArgusErfRead`, `ArgusSnoopRead`, etc.), BPF filter compilation (`pcap_compile`), the packet capture loop (`ArgusGetPackets`, driving `pcap_dispatch`) |
| `argus/ArgusModeler.c` | ~5,600 lines | Protocol header dispatch (`ArgusProcessPacketHdrs`, a hardcoded `switch` on ethertype — see §4), flow creation/lookup/update (`ArgusCreateFlow`, `ArgusNewFlow`, `ArgusUpdateFlow`), metric tally (`ArgusTallyStats`), record generation (`ArgusGenerateRecord`) |
| `argus/ArgusOutput.c` | ~2,300 lines | Record formatting and dispatch to file/socket clients, connected-client management, `ArgusOutputProcess` main loop |
| `argus/ArgusUtil.c` | ~2,800 lines | Time handling, string utilities, queue/list primitives |

### Common libraries (`common/`)

| File | Size | Role |
|---|---|---|
| `argus_filter.c` | ~3,500 lines | BPF filter expression code generation (consumed by `pcap_compile`) |
| `argus_util.c` | ~2,800 lines | Shared utility functions (separate from, and larger than, `argus/ArgusUtil.c`) |
| `argus_code.c` | ~5,500 lines | DSR-aware BPF predicate generation — lets filter expressions reference DSR fields (e.g. correlation/country-code comparisons via `Argusgen_cmp()` against `ARGUS_COR_INDEX`/`ARGUS_COCODE_INDEX`, which is filter-expression *support* for those indices, not sensor production of them) |
| `argus_auth.c` | ~600 lines | SASL authentication for remote client connections (`#ifdef ARGUS_SASL`), used together with libwrap (`<tcpd.h>`, included in `ArgusOutput.c`) for TCP-wrapper-style access control on the output socket |
| `grammar.y` / `scanner.l` | ~460 / ~470 lines | yacc/lex grammar for the BPF-style filter expression language |

## 4. Protocol Handling

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

For the full list of protocol-specific source files, see `docs/data-model.md` §4 ("Produced by: Sensor"
column), which maps each protocol handler to the DSR type(s) it emits.

## 5. Flow Classification and the DSR Model

Once a packet is dispatched to `ArgusProcessIpPacket()` (or the equivalent for other protocols), Argus:

1. Extracts a flow key into a `struct ArgusFlow` (the protocol-specific union — IP 5-tuple, MAC pair, ARP,
   ICMP, etc.) — see `docs/data-model.md` §2.
2. Looks up or creates a flow entry (`ArgusCreateFlow`, `ArgusNewFlow`).
3. Updates per-flow state and metrics as subsequent packets for the same flow arrive
   (`ArgusUpdateFlow`), populating whichever DSR slots apply (`flow->dsrs[ARGUS_x_INDEX] = ...`).
4. Periodically (or on flow termination/timeout) generates and emits an output record
   (`ArgusGenerateRecord`).

**The DSR chain is the actual data model** — see `docs/data-model.md` for the full type table, wire
format (TV vs. TLV encoding), and the set of DSRs the sensor can populate versus the DSRs that only exist
client-side. The real `struct ArgusFlow` is a multi-member union of protocol-specific flow-key structs,
not a flat struct with `src`/`dst`/`net`/`app` fields.

## 6. Output

The sensor does not support JSON or CSV output, and does not compress its output stream. It writes
exactly one binary wire format (`docs/data-model.md`), and only over these transports, all handled by a
single `-w` flag:

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

## 7. Configuration precedence

Configuration order, from `main()`:

1. `/etc/argus.conf` is loaded unconditionally, once, near the start of `main()`, *before* command-line
   argument parsing begins — if the file exists. It is the only implicit config file; there is no list of
   "default search paths."
2. Command-line arguments are then parsed left-to-right in a single `getopt()` pass. `-F <file>` loads an
   additional config file, at exactly the point it appears in the argument list — so `-F` ordering relative
   to other flags matters, and a later flag on the command line can override a value set by an earlier `-F`
   file or by `/etc/argus.conf`.
3. There is no environment-variable configuration layer. Variables named `ARGUS_*` in `argus.conf` are
   config-file keys, not environment variables the shell/OS needs to export.
4. There is no `$ARGUSPATH`/`$ARGUSHOME`/`$HOME` auto-search for a config file in this version — the man
   page (`man/man5/argus.conf.5`) explicitly documents this search as deprecated.

## 8. Privilege and Access Control

- **Privilege drop** via `-u <userid>`/`-g <groupid>` uses `setuid()`/`setgid()`. The general pattern
  (start as root to bind/open a capture interface, then drop) is *not* automatic — it only happens if
  `-u`/`-g` are supplied; without them the daemon continues running with its starting privileges.
- **SASL authentication** for the output socket is gated behind an `ARGUS_SASL` build-time flag
  (`common/argus_auth.c`).
- **TCP-wrapper (libwrap) access control** is available via `#include <tcpd.h>` in `ArgusOutput.c`.
- **chroot support** exists via `-c <dir>`.

## 9. Deployment topology

```
┌──────────────┐     -w argus-udp://collector:561      ┌───────────────────────┐
│  argus (this │ ─────────────────────────────────────▶│  Collector host       │
│  sensor)     │                                        │  running client       │
│              │        or: -P 561 (listen for          │  programs (separate   │
│  Probe host  │◀────────── connecting clients) ────────│  repo/scope)          │
└──────────────┘                                        └───────────────────────┘
```

Each deployed sensor instance is a single `argus` process bound to one or more interfaces
(`-i <interface>`, repeatable), writing either to local files for later batch pickup or streaming live to
a collector. Multiple sensors can feed one collector; the sensor itself has no concept of other sensors
and does no inter-sensor coordination — any multi-sensor correlation is, again, a client-side capability.

## 10. What's intentionally out of scope here

The following are real Argus capabilities but belong to the **client** side and are documented (if at all)
in the clients repo, not here:
- Record correlation, GeoIP/ASN/DNS labeling, flow clustering/aggregation (`racluster`, `ralabel`, `radns`)
- Long-term storage, database integration, visualization (`ratop`, `ramysql` examples)
- `radium` — the client-side flow-record relay/distribution daemon (this is a *client* program despite
  the daemon-sounding name; it is not part of this sensor codebase)

If any of the above capabilities are required, the deployment architecture needs a second tier beyond the
sensor described here — see `docs/data-model.md` for how this affects data-handling considerations.

---

## Open items / further reading

1. The exact set of supported `-r` input formats beyond pcap/cisco-netflow/MOAT-Tsh/ERF/snoop is covered
   in `ArgusSource.c`'s per-format read functions, not exhaustively catalogued here.
2. Multi-threading behavior under `ARGUS_THREADS` (queue depth, lock contention, thread affinity) exists
   but is not characterized in detail here — worth a dedicated performance-architecture pass if you have
   specific throughput requirements.
3. See `man/man8/argus.8` for the complete, canonical command-line flag reference; the flags cited above
   are illustrative, not exhaustive.
