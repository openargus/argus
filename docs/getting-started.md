# Getting Started with the Argus Sensor

**Scope:** The Argus sensor only — installation, running, and basic operation of the `argus` daemon
itself. Reading and analyzing the flow records it produces requires client programs (`ra`, `radump`,
etc.) from the separate [`argus-clients`](https://github.com/openargus/clients) repository; those tools
are out of scope for this document.

---

## 1. What the sensor does (and doesn't do)

Argus's job: capture packets, classify them into flows, track flow state and metrics, and periodically
emit binary flow records. That's it. Analysis, visualization, CSV/JSON export, alerting, and correlation
are all client-side capabilities in the separate `argus-clients` distribution, not part of this sensor.
See [`docs/architecture.md`](architecture.md) and [`docs/data-model.md`](data-model.md) for the full
sensor/client boundary.

## 2. Prerequisites

- A Unix-like system — build support exists in `configure.ac` for Linux, macOS, FreeBSD/OpenBSD/NetBSD,
  Solaris, AIX, HP-UX, and Cygwin (see [`ARCHITECTURE.md`](../ARCHITECTURE.md)).
- Root/sudo access, or appropriate packet-capture capabilities, to open interfaces for live capture.
- `libpcap`, `flex`, `bison`, a C compiler, and `zlib` development headers to build from source.

## 3. Installation (build from source)

```bash
git clone https://github.com/openargus/argus.git
cd argus
./configure --prefix=/usr/local
make
sudo make install
```

**Verify the build:**

```bash
argus -h
```

This prints the version banner (`Argus Version <ver>`, taken from the repo's `VERSION` file) followed by
full usage text. Note: `argus` has no dedicated `-V`/`--version` flag; `-h` (or any unrecognized flag)
falls through to the usage/version banner.

## 4. Running the sensor

### Capture live from an interface, write to a file

```bash
sudo argus -i eth0 -w /var/log/argus/data.argus
```

### Stop the sensor

```bash
# Ctrl+C if running in the foreground, or:
sudo killall argus
```

`SIGINT`, `SIGTERM`, and `SIGHUP` are all wired to a graceful shutdown handler, so either method works.

### Run as a daemon

```bash
sudo argus -d -i eth0 -w /var/log/argus/data.argus
```

`-d` toggles daemon mode directly from the command line; you don't need a config file to test it.

**Systemd / launchd packaging**: this repo includes packaging assets under `pkg/systemd/`, `pkg/osx/`,
and `debian/` — check those directories directly for the unit/service file names and install paths for
your platform.

### Minimal configuration file

```conf
# /etc/argus.conf
ARGUS_MONITOR_ID=`hostname`
ARGUS_FLOW_TYPE=Bidirectional
ARGUS_FLOW_KEY=CLASSIC_5_TUPLE
ARGUS_INTERFACE=eth0
ARGUS_OUTPUT_FILE=/var/log/argus/data.argus
ARGUS_DAEMON=yes
```

See [`docs/configuration.md`](configuration.md) for the complete configuration variable reference.

## 5. Filter expressions

```bash
sudo argus -i eth0 'tcp port 80'
```

Filter expressions use BPF syntax (same as `tcpdump`). Quote the expression if it contains shell
metacharacters or spaces.

To see the compiled filter for debugging:

```bash
sudo argus -i eth0 -b 'tcp port 80'
```

`-b` dumps the filter compiler output and exits.

## 6. Inspecting output

The sensor writes exactly one binary wire format (see [`docs/data-model.md`](data-model.md)) — there is
no built-in way for the sensor itself to print human-readable flow records, CSV, or JSON. Reading the
output requires a client program (`ra`, `radump`, etc.) from the separate
[`argus-clients`](https://github.com/openargus/clients) repository; see that project's documentation for
usage.

## 7. Basic troubleshooting

**Sensor won't start / permission errors:**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which argus)
# or simply run with sudo
```

**No packets captured:**
```bash
ip link show eth0            # confirm interface is up
sudo tcpdump -i eth0 -c 10   # confirm traffic is actually reaching the interface
```

**Check filter compilation:**
```bash
sudo argus -i eth0 -b 'tcp port 80'
```

See [`docs/troubleshooting.md`](troubleshooting.md) for a more complete troubleshooting reference.

## 8. Next steps

- [`docs/configuration.md`](configuration.md) — full configuration variable reference.
- [`docs/architecture.md`](architecture.md) — how the sensor is structured internally.
- [`docs/data-model.md`](data-model.md) — the wire format the sensor produces.
- [`docs/troubleshooting.md`](troubleshooting.md) — troubleshooting reference.
