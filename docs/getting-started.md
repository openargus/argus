# Getting Started with the Argus Sensor

**Status:** Verified against source.
**Scope:** Argus sensor only (`~/Saber/argus/argus`) — installation, running, and basic operation of the
`argus` daemon itself. Reading/analyzing the output it produces requires client programs from the separate
`~/Saber/argus/clients` repo (`ra`, `radump`, etc.) — see the note in §5 about what is and isn't verified
about those tools here.
**Supersedes:** the previous version of this document, which contained numerous incorrect CLI flags,
a fabricated "Understanding Argus Output" section with an invented tabular format, non-existent output
formats (JSON/CSV directly from the sensor), and a security-monitoring example built on non-existent
`raaggregate`/`rahistogram`/`rahigh` pipelines. Every specific correction is called out inline below.

---

## 1. What the sensor does (and doesn't do)

Argus's job: capture packets, classify them into flows, track flow state and metrics, and periodically
emit binary flow records. That's it. Analysis, visualization, CSV/JSON export, alerting, and correlation
are all client-side capabilities in the separate `argus-clients` distribution, not part of this sensor.
See `docs/architecture.md` §10 and `docs/data-model.md` for the full sensor/client boundary.

## 2. Prerequisites

- A Unix-like system — build support confirmed in `configure.ac` for Linux, macOS, FreeBSD/OpenBSD/NetBSD,
  Solaris, AIX, HP-UX, Cygwin (see root `ARCHITECTURE.md`).
- Root/sudo access, or appropriate packet-capture capabilities, to open interfaces for live capture.
- `libpcap`, `flex`, `bison`, a C compiler, and `zlib` development headers to build from source.

## 3. Installation (build from source)

This repo does not ship prebuilt packages as part of what's cloned into `~/Saber/argus/argus` — the
commands below build directly from this checkout.

```bash
# From the sensor repo root
./configure --prefix=/usr/local
make
sudo make install
```

*(Corrected: the previous doc suggested `apt-get install argus argus-clients`, `dnf install argus`, and
`brew install argus` as primary installation paths, and a `git clone https://github.com/openargus/argus.git`
step. Since you already have this cloned locally as part of the SABER project, the relevant path is
building from this checkout directly — package-manager availability/versions for `argus` were not
verified as part of this review and should not be assumed current or appropriate for a SABER deployment
without separate verification.)*

**Verify the build:**

```bash
argus -h
```

*(Corrected: the previous doc used `argus -V` and claimed it prints something like `argus-5.0.x` and exits.
**`-V` is not a recognized flag** — confirmed against the real `getopt()` option string in `argus/argus.c:451`,
`"AbB:c:CdD:e:E:fF:g:H:i:Jk:lmM:N:OP:pRr:S:s:tT:u:U:w:XZh"`, which contains no `V`. Passing an unrecognized
flag falls through to `default: usage();` (`argus.c:629`), which prints full usage text — starting with a
line of the form `Argus Version <ver>` — and then **exits with a nonzero status**, which is different from a
dedicated "print version and exit cleanly" command. The version string itself is generated directly from
the repo's `VERSION` file — currently `5.0.3`, not `argus-5.0.x`.)*

## 4. Running the sensor

### Capture live from an interface, write to a file

```bash
sudo argus -i eth0 -w /var/log/argus/data.argus
```

This part of the previous doc's Quick Start was correct — `-i <interface>` and `-w <file>` are both real,
confirmed flags.

### Stop the sensor

```bash
# Ctrl+C if running in the foreground, or:
sudo killall argus
```

Confirmed: `SIGINT`, `SIGTERM`, and `SIGHUP` are all wired to a graceful shutdown handler
(`ArgusScheduleShutDown`, `argus/argus.c:787-789`), so both methods work as described.

### Run as a daemon

```bash
sudo argus -d -i eth0 -w /var/log/argus/data.argus
```

`-d` toggles daemon mode (`argus.c:466`). *(Corrected: the previous doc implied this was only reachable via
a config-file `ARGUS_DAEMON=yes` setting combined with a systemd unit; `-d` on the command line is the
direct equivalent and is the simplest way to test daemon mode manually.)*

**Systemd / LaunchDaemons packaging**: this repo does include packaging assets (`pkg/systemd/`, `pkg/osx/`,
`debian/`), but their exact contents/paths were not individually verified for this document — check
`pkg/systemd/` directly for the actual unit file name and paths rather than assuming
`/usr/local/share/argus/argus.service` as the previous doc did (that specific path was not confirmed to
exist).

### Minimal configuration file

```conf
# /etc/argus.conf
ARGUS_MONITOR_ID=`hostname`
ARGUS_FLOW_TYPE=Bi
ARGUS_FLOW_KEY=CLASSIC_5_TUPLE
ARGUS_INTERFACE=eth0
ARGUS_OUTPUT_FILE=/var/log/argus/data.argus
ARGUS_DAEMON=yes
```

*(Corrected: previous doc used `ARGUS_FLOW_TYPE="Bidirectional"` — the parser only checks a
case-insensitive prefix, `"Uni"` or `"Bi"` (`argus.c:1705-1709`), so `"Bidirectional"` does work, but `Bi`
is the minimal accurate form. It also used a bare `ARGUS_OUTPUT` variable, which doesn't exist — the real
variable is `ARGUS_OUTPUT_FILE`, and multiple `ARGUS_INTERFACE=` lines for multiple interfaces is correct
and was retained. See `docs/configuration.md` for the complete, verified variable reference.)*

## 5. Filter expressions

```bash
sudo argus -i eth0 'tcp port 80'
```

Filter expressions use BPF syntax (same as `tcpdump`), compiled via `pcap_compile()`
(`ArgusSource.c:1063`). Quoting matters if the expression contains shell metacharacters or spaces — this
part of the previous doc's guidance was accurate.

To see the compiled filter for debugging (this is a real flag, previously undocumented):

```bash
sudo argus -i eth0 -b 'tcp port 80'
```

`-b` dumps filter compiler output (`argus.c:114`, `Argusbpf_dump`, `ArgusSource.c:5549`).

## 6. Inspecting output — scope note

The sensor writes exactly one binary wire format (see `docs/data-model.md`) — there is no built-in way for
the sensor itself to print human-readable flow records, CSV, or JSON. Reading the output requires a client
program (`ra`, `radump`, etc.) from the **separate** `~/Saber/argus/clients` repository.

**This document does not verify client-program usage** — that repo is out of scope for the sensor
documentation effort per the working agreement for this pass. If you need to confirm a specific `ra`
invocation, output field name, or output-format flag (e.g. whether `-M csv`/`-M json` are real `ra` flags,
which was not confirmed here), that should be checked directly against the clients repo source, not
assumed from this document or its predecessor.

*(Corrected: the previous doc's entire "Understanding Argus Output" section — the tabular field-order
diagram, the specific example output line, `ra -M csv`, `ra -M json`, and the four "Common Use Cases"
pipelines using `raaggregate`, `rahistogram`, `rahigh`, `rasort -k 5 -rn` — was not verified against the
clients source and should be treated as unconfirmed, not as documentation of actual sensor or client
behavior. None of it originates from the sensor repo this document covers.)*

## 7. Basic troubleshooting

**Sensor won't start / permission errors:**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which argus)
# or simply run with sudo
```
This is a standard Linux capabilities mechanism for libpcap-based tools and is accurate as general
guidance; it was not independently re-verified as Argus-specific in this pass.

**No packets captured:**
```bash
ip link show eth0        # confirm interface is up
sudo tcpdump -i eth0 -c 10   # confirm traffic is actually reaching the interface
```

**Check filter compilation:**
```bash
sudo argus -i eth0 -b 'tcp port 80'
```

See `docs/troubleshooting.md` for a more complete, source-verified troubleshooting reference.

## 8. Next steps

- [`docs/configuration.md`](configuration.md) — full, verified configuration variable reference.
- [`docs/architecture.md`](architecture.md) — how the sensor is structured internally.
- [`docs/data-model.md`](data-model.md) — the wire format the sensor produces.
- [`docs/troubleshooting.md`](troubleshooting.md) — verified troubleshooting reference.

---

## Open items / follow-up verification

1. Exact systemd/launchd packaging file names and install paths (`pkg/systemd/`, `pkg/osx/`) were not
   individually confirmed in this pass — verify directly before publishing a specific
   `systemctl enable <name>` instruction.
2. Client-side output/analysis commands (`ra`, `radump`, and any aggregation/histogram tools) are entirely
   out of scope for sensor documentation and were deliberately not verified or included here — a
   client-focused pass against the `~/Saber/argus/clients` repo would be needed before publishing
   equivalent "getting started with output analysis" content.
3. Packet-capture capability/permission guidance (`setcap`, AppArmor/SELinux considerations) is generic
   Linux/libpcap guidance, not confirmed against this specific codebase — retained as reasonable general
   advice, flagged as such.
