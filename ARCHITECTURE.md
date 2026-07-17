# Argus Daemon Architecture

This document describes the architecture of the Argus daemon - the core network flow monitoring engine that captures packets and generates comprehensive flow records.

---

## System Overview

Argus is a comprehensive network transaction auditing system that generates flow data from raw packet captures.

```
┌────────────────────────────────────────────────────────────────────────┐
│                     Argus Daemon (C)                                   │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Processing Pipeline                          │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                        │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐ │
│  │  Capture    │──►│   Filter    │──►│  Protocol   │──►│   Flow      │ │
│  │  Layer      │   │   Engine    │   │   Parsers   │   │  Aggregator │ │
│  └─────────────┘   └─────────────┘   └─────────────┘   └──────┬──────┘ │
│         │                                                     │        │
│         ▼                                                     ▼        │
│  ┌─────────────┐                                      ┌──────────────┐ │
│  │  libpcap    │                                      │    Output    │ │
│  │  Interfaces │                                      │    Writer    │ │
│  └─────────────┘                                      └──────────────┘ │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### Core Source Files

| File               | Lines | Responsibility       | Key Functions          |
|--------------------|-------|----------------------|------------------------|
| **argus.c**        | 81K   | Main daemon control  | Daemonization, config, |
|                    |       |                      | signal handling        |
| **ArgusSource.c**  | 220K  | Packet capture and   | `ArgusOpenSource()`,   |
|                    |       | interface management | `ArgusReadSource()`    |
| **ArgusModeler.c** | 203K  | Flow aggregation &   | `ArgusFlowAlloc()`,    |
|                    |       | state tracking       | `ArgusModeler()`       |
| **ArgusOutput.c**  | 79K   | Flow record output   | `ArgusOutput()`,       |
|                    |       |                      | `ArgusWriteRecord()`   |
| **ArgusUtil.c**    | 83K   | Utility functions    | Time handling, string  |
|                    |       |                      |  utils, memory         |

### Protocol Parsers

| Parser              | File             | Responsibility                |
|---------------------|------------------|-------------------------------|
| **Ethernet/802.11** | `Argus802.11.c`  | Wireless frame parsing        |
| **Application**     | `ArgusApp.c`     | Application layer detection   |
| **ARP**             | `ArgusArp.c`     | ARP request/response tracking |
| **Authentication**  | `ArgusAuth.c`    | Auth protocol parsing         |
| **ESP/IPSec**       | `ArgusEsp.c`     | Encrypted payload handling    |
| **Events**          | `ArgusEvents.c`  | System event generation       |
| **Fragmentation**   | `ArgusFrag.c`    | IP fragment reassembly        |
| **Geneve**          | `ArgusGeneve.c`  | Network virtualization        |
| **GRE**             | `ArgusGre.c`     | Generic routing encapsulation |
| **ICMP**            | `ArgusIcmp.c`    | ICMP message parsing          |
| **Interface Names** | `ArgusIfnam.c`   | Interface name resolution     |
| **IGMP**            | `ArgusIgmp.c`    | Multicast group management    |
| **ISIS**            | `ArgusIsis.c`    | IS-IS routing protocol        |
| **L2TP**            | `ArgusL2TP.c`    | Layer 2 tunneling             |
| **LCP**             | `ArgusLcp.c`     | PPP link control              |
| **MAC**             | `ArgusMac.c`     | MAC address handling          |
| **NetFlow**         | `ArgusNetflow.c` | NetFlow import/processing     |
| **SFlow**           | `ArgusSflow.c`   | sFlow import/processing       |
| **TCP**             | `ArgusTcp.c`     | TCP state machine, metrics    |
| **UDP**             | `ArgusUdp.c`     | UDP flow tracking             |
| **UDT**             | `ArgusUdt.c`     | UDP-based Data Transfer       |
| **VXLAN**           | `ArgusVxLan.c`   | Virtual eXtensible LAN        |

### Common Libraries

| Component           | File             | Responsibility                    |
|---------------------|------------------|-----------------------------------|
| **Authentication**  | `argus_auth.c`   | SASL, TCP wrappers                |
| **Code Conversion** | `argus_code.c`   | Data encoding/decoding            |
| **Filter Engine**   | `argus_filter.c` | BPF filter compilation/evaluation |
| **Utilities**       | `argus_util.c`   | Common utilities                  |
| **Parser Grammar**  | `grammar.y`      | Filter expression grammar         |
| **Scanner**         | `scanner.l`      | Filter expression lexer           |
| **Version**         | `version.c`      | Build version info                |

---

## Data Flow Architecture

### Packet Processing Pipeline

```
┌──────────────────────────────────────────────────────────────────────┐
│                       Packet Processing Flow                         │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. PACKET ARRIVAL                                                   │
│     ┌──────────────────────────────────────────────────────────┐     │
│     │ • Network interface (eth0, en0, etc.)                    │     │
│     │ • Packet capture file (tcpdump, snoop, ERF)              │     │
│     │ • Remote source (sflow, netflow)                         │     │
│     └───────────────────────┬──────────────────────────────────┘     │
│                             ▼                                        │
│  2. INTERFACE PROCESSING (ArgusSource.c)                             │
│     ┌──────────────────────────────────────────────────────────┐     │
│     │ • Timestamp assignment                                   │     │
│     │ • Interface identification                               │     │
│     │ • Link layer parsing                                     │     │
│     │ • Packet validation                                      │     │
│     └───────────────────────┬──────────────────────────────────┘     │
│                             ▼                                        │
│  3. FILTER EVALUATION (argus_filter.c)                               │
│     ┌──────────────────────────────────────────────────────────┐     │
│     │ • BPF filter compilation                                 │     │
│     │ • Expression evaluation                                  │     │
│     │ • Packet matching                                        │     │
│     └───────────────────────┬──────────────────────────────────┘     │
│                             ▼                                        │
│  4. PROTOCOL PARSING (Argus*.c)                                      │
│     ┌──────────────────────────────────────────────────────────┐     │
│     │ • Layer 2: Ethernet, VLAN, 802.11, MPLS                  │     │
│     │ • Layer 3: IPv4, IPv6                                    │     │
│     │ • Layer 4: TCP, UDP, ICMP, IGMP                          │     │
│     │ • Encapsulation: VXLAN, GRE, Geneve, L2TP                │     │
│     │ • Routing: ISIS, OSPF                                    │     │
│     └───────────────────────┬──────────────────────────────────┘     │
│                             ▼                                        │
│  5. FLOW AGGREGATION (ArgusModeler.c)                                │
│     ┌──────────────────────────────────────────────────────────┐     │
│     │ • Flow key extraction (5-tuple, L2, custom)              │     │
│     │ • Hash table lookup/insertion                            │     │
│     │ • State machine updates (TCP handshake, etc.)            │     │
│     │ • Metric calculation (bytes, packets, jitter, RTT)       │     │
│     └───────────────────────┬──────────────────────────────────┘     │
│                             ▼                                        │
│  6. METRICS CALCULATION (ArgusUtil.c)                                │
│     ┌──────────────────────────────────────────────────────────┐     │
│     │ • Byte/packet counts                                     │     │
│     │ • Timing metrics (duration, inter-arrival)               │     │
│     │ • Behavioral analysis (jitter, retransmission)           │     │
│     │ • Application layer metrics                              │     │
│     └───────────────────────┬──────────────────────────────────┘     │
│                             ▼                                        │
│  7. OUTPUT GENERATION (ArgusOutput.c)                                │
│     ┌──────────────────────────────────────────────────────────┐     │
│     │ • Record formatting (binary, DSR blocks)                 │     │
│     │ • File writing with rotation                             │     │
│     │ • Socket transmission to collectors                      │     │
│     │ • Compression (gzip, zstd)                               │     │
│     └──────────────────────────────────────────────────────────┘     │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Key Data Structures

### Flow Record Structure

```c
struct ArgusFlow {
    struct ArgusCommon      common;      /* Header, timestamps */
    struct ArgusSourceStruct *src;       /* Source information */
    struct ArgusDestinationStruct *dst;  /* Destination information */
    
    /* Network layer */
    struct ArgusNetworkStruct net;
    
    /* Transport layer */
    struct ArgusTransportStruct tran;
    
    /* Application layer */
    struct ArgusApplicationStruct app;
    
    /* Metrics */
    struct ArgusMetricStruct metric;
    
    /* Flow state */
    u_int flow_state;
    u_int flow_status;
};
```

### DSR (Destination Specific Record) System

| DSR Type | Code | Description                     |
|----------|------|---------------------------------|
| SOURCE   |  1   | Source address information      |
| DEST     |  2   | Destination address information |
| FLOW     |  3   | Flow identification             |
| TCP      |  4   | TCP state and flags             |
| ICMP     |  5   | ICMP type/code                  |
| JITTER   |  6   | Performance metrics             |
| APP      |  7   | Application layer data          |
| EVENT    |  8   | System events                   |

---

## Configuration Architecture

### Configuration Hierarchy

```
┌─────────────────────────────────────┐
│ 1. Command-Line Options             │  ← Highest Priority
├─────────────────────────────────────┤
│ 2. Explicit Config Files (-F)       │
├─────────────────────────────────────┤
│ 3. Environment Variables            │
├─────────────────────────────────────┤
│ 4. Default Config Files             │
│    /etc/argus.conf                  │
│    $ARGUSPATH/argus.conf            │
│    $HOME/argus.conf                 │
├─────────────────────────────────────┤
│ 5. Compiled-in Defaults             │  ← Lowest Priority
└─────────────────────────────────────┘
```

### Key Configuration Variables

| Variable           | Scope  | Description                   |
|--------------------|--------|-------------------------------|
| `ARGUS_MONITOR_ID` | Daemon | Unique probe identifier       |
| `ARGUS_FLOW_TYPE`  | Daemon | Bidirectional/Unidirecti onal |
| `ARGUS_FLOW_KEY`   | Daemon | Flow aggregation strategy     |
| `ARGUS_INTERFACE`  | Daemon | Network interface(s)          |
| `ARGUS_OUTPUT`     | Daemon | Output destination            |
| `ARGUS_DAEMON`     | Daemon | Run as background process     |

---

## Performance Architecture

### Scalability Features

1. **Multi-threading Support** (`ARGUS_THREADS`)
   - Separate threads for capture, processing, output
   - Thread-local flow tables
   - Lock-free data structures where possible

2. **Memory Management**
   - Pre-allocated flow cache
   - Efficient hash tables
   - Automatic flow expiration

3. **I/O Optimization**
   - Ring buffer for packet capture
   - Buffered output writes
   - Async socket operations

### Performance Metrics

| Metric             | Target    | Notes                |
|--------------------|-----------|----------------------|
| Packet Processing  | 1M+ pps   | Line rate on 100Gbps |
| Flow Creation      | 100K+ f/s | Depends on flow key  |
| Memory Usage       | 50-500MB  | Configurable         |
| CPU Usage          | 10-80%    | Depends on traffic   |
| Latency            | <1ms      | Packet to record     |

---

## Security Architecture

### Access Control

1. **TCP Wrappers** (`/etc/hosts.allow`, `/etc/hosts.deny`)
   - Socket connection filtering
   - Client IP whitelisting

2. **SASL Authentication**
   - Strong authentication for remote access
   - Encryption support
   - Integration with system auth

### Privilege Separation

```c
/* Argus drops privileges after binding */
1. Start as root
2. Bind to privileged ports/interfaces
3. Drop to unprivileged user
4. Continue processing
```

---

## Build System

### Directory Structure

```
argus/
├── argus/           # Core daemon source
├── common/          # Shared libraries
│   ├── grammar.y    # Filter parser grammar
│   ├── scanner.l    # Filter lexer
│   └── *.c          # Common utilities
├── include/         # Header files
│   ├── argus/       # Argus-specific headers
│   └── net/         # Network protocol headers
├── bin/             # Compiled binaries
├── man/             # Manual pages
│   ├── man5/        # argus.conf.5
│   └── man8/        # argus.8
└── pkg/             # Package files
    ├── systemd/     # Systemd service files
    ├── init.d/      # SysV init scripts
    └── argus.conf   # Example configuration
```

### Build Process

```bash
./configure              # Detect system capabilities
make                     # Build all components
make check               # Run tests (if available)
sudo make install        # Install to system
```

---

## Deployment Architectures

### Single-Node Deployment

```
┌─────────────────────────────────────┐
│   Server                            │
│  ┌──────────────┐  ┌─────────────┐  │
│  │    argus     │─►│  /var/log/  │  │
│  │     (C)      │  │   argus/    │  │
│  │              │─►│  *.argus    │  │
│  └──────────────┘  └─────────────┘  │
│         │                 │         │
│         ▼                 ▼         │
│   ┌────────────┐  ┌──────────────┐  │
│   │     ra     │◄─│   racluster  │  │
│   │  (Clients) │  │   (Clients)  │  │
│   └────────────┘  └──────────────┘  │
└─────────────────────────────────────┘
```

### Distributed Deployment

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Probe 1   │    │   Probe 2   │    │   Probe N   │
│  (argus C)  │    │  (argus C)  │    │  (argus C)  │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │
       └──────────────────┼──────────────────┘
                          ▼
              ┌───────────────────────┐
              │   Collector           │
              │    (raapi/clients)    │
              │                       │
              │   ┌───────────────┐   │
              │   │ Flow Store    │   │
              │   │ (Database)    │   │
              │   └───────────────┘   │
              └───────────────────────┘
```

---

## Extension Points

### Adding New Protocol Parsers

```c
/* argus/ArgusCustom.c */
int ArgusParseCustom(u_char *data, int len, struct ArgusFlow *flow)
{
    /* Extract protocol fields */
    /* Update flow structure */
    return bytes_consumed;
}
```

### Adding New DSR Types

```c
/* include/argus_def.h */
#define ARGUS_DSR_TYPE_CUSTOM  99

struct ArgusCustomDSR {
    /* Custom data structure */
};
```

---

## Platform Support

Argus has been ported to numerous platforms:

| Platform | Status | Notes            |
|----------|--------|------------------|
| Linux    |   ✅   | Primary platform |
| macOS    |   ✅   | Full support     |
| FreeBSD  |   ✅   | Full support     |
| OpenBSD  |   ✅   | Full support     |
| NetBSD   |   ✅   | Full support     |
| VxWorks  |   ✅   | Full support     |
| Solaris  |   ✅   | Legacy support   |
| AIX      |   ✅   | Legacy support   |
| HPUX     |   ✅   | Legacy support   |
| Windows  |   ⚠️    | Cygwin/MinGW     |
| Embedded |   ✅   | OpenWRT, etc.    |

---

## Related Documentation

- [argus.conf.5](man/man5/argus.conf.5) - Configuration reference
- [argus.8](man/man8/argus.8) - Command reference
- [INSTALL](INSTALL) - Build instructions
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development guidelines
- [../clients/ARCHITECTURE.md](../clients/ARCHITECTURE.md) - Clients architecture

---

*Last updated: 2026-07-02*
*Argus Version: 5.0.x*
