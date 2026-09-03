# Argus Sensor Configuration Guide

**Scope:** Argus sensor only. Every variable below appears in the sensor's config-variable table
(`ArgusResourceFileStr[]` in `argus/argus.c`) and is cross-checked against `man/man5/argus.conf.5`, which
is the primary authoritative reference for variable semantics.

---

## 1. Configuration file format

See `man/man5/argus.conf.5` and `ArgusParseResourceFile()` in `argus/argus.c`:

```conf
VARIABLE=value
VARIABLE="compound value with spaces"

# Comment on its own line
VARIABLE=value // inline comment (space or tab before // is required)
```

Rules:
- No whitespace around `=`.
- Quotes are optional for simple values, required if the value needs an embedded comment or contains
  spaces.
- A config file is a flat list of `VARIABLE=value` lines — there is no nesting, sectioning, or includes
  beyond the `-F` command-line mechanism described next.

## 2. Configuration precedence

The sensor's configuration model is a simple two-step, single-pass process, from `main()`:

1. **`/etc/argus.conf` loads first, unconditionally, if it exists** — checked with `stat()` before command
   line parsing begins. This is the *only* automatically-searched config file.
2. **Command-line arguments are then parsed once, left to right**, via a single `getopt()` loop. `-F <file>`
   loads an additional config file at exactly the point it appears in the argument list. Any flag appearing
   later on the command line overrides a value set earlier (by `/etc/argus.conf` or an earlier `-F` file).

```bash
# /etc/argus.conf loads first (if present), then this -F file, then -i overrides
# whatever interface either config file set, because it comes last on the command line
argus -F /etc/argus/site.conf -i eth0
```

**There is no environment-variable configuration layer.** The `ARGUS_*` names are config-file variable
names, not shell environment variables — `export ARGUS_MONITOR_ID=...` has no effect.

One variable is easy to confuse with this: **`ARGUS_ENV`** is a real config-file directive, but it does the
opposite of what it sounds like — it calls `putenv()` to set an OS/library-level environment variable
*for other software* (documented use case: PF_RING support in libpcap), and explicitly does **not** affect
any internal Argus variable (`man/man5/argus.conf.5` says so directly: *"you can't set ARGUS_PATH using
this feature"*).

**There is no `$ARGUSPATH`/`$ARGUSHOME`/`$HOME` auto-search** for a config file in this version. The man
page for `argus.conf` documents this search as deprecated from earlier versions.

## 3. Complete list of configuration variables

This is the full set — every one of the following appears in `ArgusResourceFileStr[]`
(`argus/argus.c`), the sensor's exhaustive list of recognized config-file variables. **If a
variable is not in this list, the sensor's config-file parser does not recognize it at all.**

### Identity

| Variable | CLI equiv. | Purpose |
|---|---|---|
| `ARGUS_MONITOR_ID` | `-e <id>` | Source identifier embedded in every output record. v5 supports 128-bit values: unsigned int, IPv4/IPv6 address, 4-byte string, or UUID. Special values `` `hostname` `` and `` `hostuuid` `` resolve at runtime. Syntax: `[type:/]sid[/inf]` where `type` is `int`\|`str`\|`ipv4`\|`ipv6`\|`uuid`. |
| `ARGUS_MONITOR_ID_INCLUDE_INF` | none | If `yes`, folds the monitored interface name into the 160-bit srcid (sid + inf). Default `no`. |

### Daemon / process control

| Variable | CLI equiv. | Purpose |
|---|---|---|
| `ARGUS_DAEMON` | `-d` | Run as background daemon. |
| `ARGUS_SET_PID` | none | Whether to write a pid file (default: yes). |
| `ARGUS_PID_PATH` | none | Directory for the pid file (default `/var/run`). |
| `ARGUS_CHROOT_DIR` | `-c <dir>` | `chroot(2)` after startup — **note: output file paths become relative to this directory afterward.** |
| `ARGUS_SETUSER_ID` | `-u <user>` | `setuid()` after privileged resources are opened. |
| `ARGUS_SETGROUP_ID` | `-g <group>` | `setgid()` after privileged resources are opened. |

### Interfaces / capture

| Variable | CLI equiv. | Purpose |
|---|---|---|
| `ARGUS_INTERFACE` | `-i <interface>` | Interface(s) to capture from. Supports rich syntax: `ind:` (independent tracking per interface), `dup:` (treat 2 interfaces as one half-duplex link), `bond:` (treat multiple interfaces as one source), grouping with `[...]`, and per-interface srcid override — see §4 below. |
| `ARGUS_INTERFACE_SCAN_INTERVAL` | none | Seconds between checks for new/changed interfaces (1–60, default 1). |
| `ARGUS_GO_PROMISCUOUS` | (inverse of `-p`) | Whether to open interfaces in promiscuous mode. |
| `ARGUS_BIND_IP` | `-B` | Restrict the *remote access* listening socket (see `ARGUS_ACCESS_PORT`) to specific local IP(s), comma-separated. |
| `ARGUS_PCAP_BUF_SIZE` | none | libpcap capture buffer size; accepts `K`/`M`/`G` suffixes, e.g. `1G`. |
| `ARGUS_PCAP_DISPATCH_NUM` | none | Packets requested per `pcap_dispatch()` call; `-1` = full buffer. Default `1`. |
| `ARGUS_FILTER` | none | A BPF filter expression, max 2K. |
| `ARGUS_FILTER_OPTIMIZER` | `-O` (inverted) | Whether libpcap's filter optimizer is used. Default yes. |
| `ARGUS_PACKET_CAPTURE_FILE` | none | Write raw captured packets to a file in addition to generating flow records. |
| `ARGUS_PACKET_CAPTURE_ON_PROTO` | none | Limit raw packet capture to specific protocols. |
| `ARGUS_PACKET_CAPTURE_ON_ERROR` | none | Trigger raw packet capture on error conditions. |

`bond`/`dup`/`ind` are Argus's own interface-combination keywords — they are unrelated to OS-level
bonding or VLAN subinterfaces, which Argus treats as ordinary interface names if the OS exposes them
that way.

### Flow model

| Variable | CLI equiv. | Purpose |
|---|---|---|
| `ARGUS_FLOW_TYPE` | none | `Uni` or `Bi` (case-insensitive prefix match — `"Uni..."` / `"Bi..."`), i.e. unidirectional or bidirectional flow tracking. |
| `ARGUS_FLOW_KEY` | none | Space/`+`-separated combination of: `CLASSIC_5_TUPLE`, `LAYER_2`, `LOCAL_MPLS`, `COMPLETE_MPLS`, `VLAN`, `LAYER_2_MATRIX`, `LAYER_3_MATRIX`. Default is `CLASSIC_5_TUPLE` if unset. |
| `ARGUS_IP_TIMEOUT`, `ARGUS_TCP_TIMEOUT`, `ARGUS_ICMP_TIMEOUT`, `ARGUS_IGMP_TIMEOUT`, `ARGUS_FRAG_TIMEOUT`, `ARGUS_ARP_TIMEOUT`, `ARGUS_OTHER_TIMEOUT` | none | Per-protocol flow-cache idle timeout in seconds. Defaults: IP 30, TCP 60, ICMP 5, IGMP 30, Frag 5, ARP 5, Other 30. Max 65534. |
| `ARGUS_TCP_FALLOW_TIMEOUT` | none | Moves an idle TCP flow into an extended "fallow" timeout queue (instead of deleting it) when its last observed state was not LISTEN/CLOSED/CLOSING, to retain syn/synack-direction knowledge for long-lived, otherwise-quiet sessions. `0` (default) disables the feature; valid range when enabled is 1–65533 seconds. |
| `ARGUS_HASHTABLE_SIZE` | none | Flow classification hash table size. Default 4096 (suited to <1M flows/day). For 40–100G sensors, the man page recommends >10M (`0x1000000`). |
| `ARGUS_TRACK_DUPLICATES` / `ARGUS_DEDUP` | none | Duplicate packet detection/handling. |
| `ARGUS_GENERATE_HASH_METRICS` | none | Export the flow hash value as a DSR (`ARGUS_FLOW_HASH_DSR` — see `docs/data-model.md`). |

### Metrics / feature toggles

| Variable | CLI equiv. | Purpose |
|---|---|---|
| `ARGUS_GENERATE_RESPONSE_TIME_DATA` | `-R` | Report data suited to app-response-time / RTT calculation. |
| `ARGUS_GENERATE_PACKET_SIZE` | `-Z` | Generate packet-size data. |
| `ARGUS_PACKET_SIZE_HISTOGRAM` | none | Enable packet-size histogram DSR. |
| `ARGUS_GENERATE_JITTER_DATA` | none | Generate jitter metrics (`ARGUS_JITTER_DSR`). |
| `ARGUS_JITTER_HISTOGRAM` | none | Jitter histogram variant. |
| `ARGUS_GENERATE_MAC_DATA` | none | Include L2 MAC DSR. |
| `ARGUS_GENERATE_APPBYTE_METRIC` | none | Application-byte counting. |
| `ARGUS_GENERATE_TCP_PERF_METRIC` | none | TCP performance metrics. |
| `ARGUS_GENERATE_BIDIRECTIONAL_TIMESTAMPS` | none | Separate src/dst timestamps. |
| `ARGUS_GENERATE_START_RECORDS` | none | Emit an explicit record at flow start (in addition to status/stop). |
| `ARGUS_CAPTURE_DATA_LEN` | `-U <bytes>` | Number of user/application payload bytes to capture (`ARGUS_DATA_DSR` — see `docs/data-model.md` §4). **Data-sensitivity implication: nonzero here means raw payload bytes, not just metadata, are captured.** |
| `ARGUS_ENCAPS_CAPTURE` | none | Capture encapsulation headers for debugging unknown tunnel types. Default `no`. |
| `ARGUS_CAPTURE_FULL_CONTROL_DATA` | `-C` | Full packet capture for specified control-plane protocols (`ARGUS_CONTROLPLANE_PROTO`). Performance-impacting above 100G per the man page. |
| `ARGUS_CONTROLPLANE_PROTO` | none | Protocol list (from `/etc/services` names) treated as control-plane when the above is enabled. |
| `ARGUS_KEYSTROKE` / `ARGUS_KEYSTROKE_CONF` | none | TCP/SSH keystroke-timing detection (`ARGUS_BEHAVIOR_DSR`) and its tunable thresholds (`DC_MIN`, `DC_MAX`, `GS_MAX`, `DS_MIN`, `DS_MAX`, `IC_MIN`, `LCS_MAX`, `GPC_MAX`, `ICR_MIN`, `ICR_MAX`). |
| `ARGUS_OS_FINGERPRINTING` | none | Includes `ARGUS_TCP_INIT` DSR data; **the sensor does not do the fingerprinting itself** — this only tags data that `ra*` clients use for pf.os/nmap-style fingerprinting. Consistent with the sensor/client boundary described in `docs/data-model.md`. |
| `ARGUS_TUNNEL_PARSING` / `ARGUS_TUNNEL_INFORMATION` / `ARGUS_TUNNEL_DISCOVERY` | none | Tunnel (GRE/VXLAN/Geneve/etc.) parsing behavior. |
| `ARGUS_SELF_SYNCHRONIZE` | none | Sensor self-synchronization behavior. |
| `ARGUS_EVENT_DATA` | none | Event-record generation/capture settings. |

Note: the sensor has no alerting concept — it emits flow records; alerting on patterns like SYN floods or
port scans is client/analyst tooling built on top of the record stream, not a sensor feature.

### Output

| Variable | CLI equiv. | Purpose |
|---|---|---|
| `ARGUS_OUTPUT_FILE` | `-w <file>` | Write to file. Supports up to 5 concurrent files, each with its own optional filter: `ARGUS_OUTPUT_FILE=/path/to/file "filter expr"`. |
| `ARGUS_OUTPUT_STREAM` | `-w argus-udp://host:port` | Write to a remote host over UDP (unregistered/unsolicited push), up to 5 concurrent streams, each with its own optional filter: `ARGUS_OUTPUT_STREAM="argus-udp://224.0.20.21:561 'filter'"`. |
| `ARGUS_ACCESS_PORT` | `-P <port>` | Enables a **listening** TCP port (default 561) for remote clients to pull data — this is the "collector connects to sensor" model, distinct from `ARGUS_OUTPUT_STREAM`'s "sensor pushes to collector" model. Disabled by setting to `0`. Man page notes: if `radium.1` (a client-side relay) is also using port 561, use a different port here, e.g. 562, to avoid conflict. |
| `ARGUS_FLOW_STATUS_INTERVAL` | `-S <secs>` | How often a status record is emitted for ongoing flows. |
| `ARGUS_MAR_STATUS_INTERVAL` | none | MAR (management/health) record interval — see `docs/data-model.md` §6 for what's in a MAR. |
| `ARGUS_MAR_INTERFACE_INTERVAL` | none | Interface-specific MAR interval. |

**Note:** file output is `ARGUS_OUTPUT_FILE`, remote output is `ARGUS_OUTPUT_STREAM` — they are not
interchangeable via a single variable. `-S`/`ARGUS_FLOW_STATUS_INTERVAL` sets the flow-status report
interval in seconds; it is unrelated to socket/host configuration.

There is no file-rotation-by-size/time, output buffer-size tuning, or output compression variable in the
sensor's config system. See `docs/architecture.md` §6 for the output-capability description.

### Security / access control

| Variable | CLI equiv. | Purpose |
|---|---|---|
| `ARGUS_BIND_IP` | `-B` | (see Interfaces table above) restricts the `ARGUS_ACCESS_PORT` listener to specific local addresses. |

TCP-wrapper (`hosts.allow`/`hosts.deny`) and SASL authentication are real (see `docs/architecture.md`
§8), but are **not controlled via `argus.conf` variables** — they're compiled-in behavior
(`#include <tcpd.h>`, `#ifdef ARGUS_SASL`) configured through the standard system files
(`/etc/hosts.allow`, `/etc/hosts.deny`) or SASL's own configuration, not through Argus-specific config
variables.

### Debug / logging

| Variable | CLI equiv. | Purpose |
|---|---|---|
| `ARGUS_DEBUG_LEVEL` | `-D <n>` | Debug verbosity (requires debug-enabled build). Default 0. |
| `ARGUS_LOG_DISPLAY_PRIORITY` | none | Controls which syslog priority levels are shown. |

### Miscellaneous

| Variable | CLI equiv. | Purpose |
|---|---|---|
| `ARGUS_ENV` | none | Sets an OS/library-level environment variable via `putenv()` for dependencies like PF_RING — **does not configure Argus itself.** See §2 above. |
| `ARGUS_TIMESTAMP_TYPE` | none | Packet timestamp source/type selection. |
| `ARGUS_MIN_SSF` / `ARGUS_MAX_SSF` | none | Sampling/subsampling-factor bounds. |

## 4. Interface specification syntax (detail)

Since `ARGUS_INTERFACE` syntax is unusually rich and easy to get wrong, quoting the man page's own grammar
directly:

```
-i ind:all
-i ind:any/srcid
-i dup:en0,en1/srcid
-i bond:en0,en1/srcid
-i dup:[bond:en0,en1],en2/srcid
-i en0/srcid -i en1/srcid       (equivalent to '-i ind:en0/srcid,en1/srcid')
-i en0 en1                       (equivalent to '-i bond:en0,en1')
```

- `ind:` — track each listed interface independently (separate flow state per interface).
- `dup:` — treat two interfaces as the two halves of one full-duplex link.
- `bond:` — treat multiple interfaces as a single combined packet source.
- Groups can nest with `[...]`.
- Per-interface `srcid` can override the global `ARGUS_MONITOR_ID`; an empty srcid (`//`) falls back to
  the global `ARGUS_MONITOR_ID`. The `inf` keyword substitutes the actual interface name into the srcid.

## 5. Example: minimal working sensor config

```conf
# /etc/argus.conf

ARGUS_MONITOR_ID=`hostname`
ARGUS_DAEMON=yes
ARGUS_INTERFACE=eth0
ARGUS_OUTPUT_FILE=/var/log/argus/argus.out
ARGUS_FLOW_STATUS_INTERVAL=60
```

For a sensor that also allows a client to pull data live (in addition to writing to a local file):

```conf
ARGUS_MONITOR_ID=`hostname`
ARGUS_DAEMON=yes
ARGUS_INTERFACE=eth0
ARGUS_OUTPUT_FILE=/var/log/argus/argus.out
ARGUS_ACCESS_PORT=561
ARGUS_BIND_IP="127.0.0.1,10.0.0.5"
```

For a sensor pushing directly to a remote collector instead of (or in addition to) writing locally:

```conf
ARGUS_MONITOR_ID=`hostname`
ARGUS_DAEMON=yes
ARGUS_INTERFACE=eth0
ARGUS_OUTPUT_STREAM="argus-udp://collector.example.com:561"
```

## 6. Validating configuration

There is no `-V`/"validate only" flag. Options for checking configuration:

```bash
# Run in foreground with debug output to see what's being parsed/applied
argus -F /etc/argus.conf -D 1 -d

# Short capture test, then inspect with a client program
timeout 60 argus -F /etc/argus.conf -i eth0 -w /tmp/test.argus
# (radump/ra are client-repo tools, not part of this sensor)
```

## 7. Related documentation

- [`man/man5/argus.conf.5`](../man/man5/argus.conf.5) — the primary authoritative reference; this document
  is a curated/cross-referenced summary of it, not a replacement.
- [`docs/architecture.md`](architecture.md) — sensor process/component architecture.
- [`docs/data-model.md`](data-model.md) — wire format and DSR reference; several config variables above
  directly control which DSRs get populated (jitter, packet-size histogram, MAC, hash metrics, keystroke,
  data-capture length).

---

## Known gaps

1. `ARGUS_COLLECTOR` appears in `ArgusResourceFileStr[]` and is parsed, but its `case` body is a no-op
   (`break;` with no action) — likely a legacy or reserved variable. Its intended behavior (if any) is
   undocumented.
2. A handful of default values above (`ARGUS_HASHTABLE_SIZE=4096`, `ARGUS_MIN_SSF`/`ARGUS_MAX_SSF`
   bounds) are transcribed from the man page rather than independently re-derived from source; treat as
   generally reliable but not exhaustively cross-checked.
