# Argus Architecture

This document provides an overview of the Argus system architecture, design principles, and component interactions.

## System Overview

Argus is designed as a modular, extensible network flow monitoring system. The architecture follows a pipeline model where packets flow through various processing stages to generate comprehensive flow records.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Argus Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐   ┌────────────┐   ┌─────────────┐   ┌─────────┐ │
│  │  Packet  │──▶│  Filter    │──▶│   Protocol  │──▶│  Flow   │ │
│  │ Capture  │   │  Engine    │   │   Parser    │   │  Agg.   │ │
│  └──────────┘   └────────────┘   └─────────────┘   └────┬────┘ │
│         │                                                 │     │
│         ▼                                                 ▼     │
│  ┌──────────┐                                      ┌──────────┐ │
│  │  libpcap │                                      │  Output  │ │
│  └──────────┘                                      └──────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Packet Capture Layer

**Location:** `argus/argus.c`, `argus/ArgusSource.c`

The capture layer interfaces with libpcap to:
- Open network interfaces
- Configure packet filters
- Read packets from interfaces or files
- Handle packet timestamps

**Key Features:**
```c
// Supports multiple capture sources
- Network interfaces (eth0, en0, etc.)
- Packet capture files (tcpdump, snoop, ERF)
- Remote packet sources (sflow, netflow)
```

### 2. Filter Engine

**Location:** `common/scanner.l`, `common/grammar.y`, `common/argus_filter.c`

The filter engine uses a BPF-compatible parser to:
- Compile filter expressions
- Match packets against criteria
- Route packets to appropriate processors

**Filter Syntax:**
```
argus -i eth0 'tcp port 80 and host 192.168.1.0/24'
```

### 3. Protocol Parsers

**Location:** `argus/Argus*.c` files

Argus includes specialized parsers for each protocol:

| Parser | File | Function |
|--------|------|----------|
| Ethernet | `ArgusEth.c` | Layer 2 parsing |
| IP | `ArgusIp.c` | IPv4/IPv6 header parsing |
| TCP | `ArgusTcp.c` | TCP state tracking |
| UDP | `ArgusUdp.c` | UDP flow tracking |
| ICMP | `ArgusIcmp.c` | ICMP message parsing |
| ARP | `ArgusArp.c` | ARP request/response |
| ISIS | `ArgusIsis.c` | Routing protocol |
| VXLAN | `ArgusVxLan.c` | Overlay networks |
| GRE | `ArgusGre.c` | Tunneling protocol |
| Geneve | `ArgusGeneve.c` | Network virtualization |

**Parser Responsibilities:**
- Extract protocol-specific fields
- Track protocol state (TCP handshake, etc.)
- Calculate protocol metrics (jitter, RTT)
- Handle encapsulation/nesting

### 4. Flow Aggregation

**Location:** `argus/ArgusModeler.c`

The flow aggregation engine:
- Groups packets into flows based on keys
- Maintains flow state tables
- Calculates aggregate metrics
- Handles flow timeout and expiration

**Flow Key Strategies:**
```c
// Configurable aggregation strategies
- CLASSIC_5_TUPLE: src_ip, dst_ip, src_port, dst_port, proto
- LAYER_2_MATRIX: Include MAC addresses
- MPLS: Include MPLS labels
- VLAN: Include VLAN tags
- Custom: User-defined key combinations
```

### 5. Output System

**Location:** `argus/ArgusOutput.c`

The output system handles:
- Writing flow records to files
- Socket transmission to clients
- Format conversion (binary, JSON, CSV)
- Compression and archiving

**Output Modes:**
```c
// File output
argus -w /var/log/argus/data.argus

// Socket output
argus -S 0.0.0.0:5100

// Stdout
argus -W -
```

## Data Structures

### Flow Record Structure

```c
struct ArgusFlow {
    struct ArgusCommon      common;      // Header, timestamps
    struct ArgusSourceStruct *src;       // Source information
    struct ArgusDestinationStruct *dst;  // Destination information
    
    // Network layer
    struct ArgusNetworkStruct net;
    
    // Transport layer
    struct ArgusTransportStruct tran;
    
    // Application layer
    struct ArgusApplicationStruct app;
    
    // Metrics
    struct ArgusMetricStruct metric;
    
    // Flow state
    u_int flow_state;
    u_int flow_status;
};
```

### DSR (Destination Specific Record) System

Argus uses extensible DSR records for protocol-specific data:

```c
// DSR Types
- ARGUS_DSR_TYPE_SOURCE    : Source address info
- ARGUS_DSR_TYPE_DEST      : Destination address info
- ARGUS_DSR_TYPE_FLOW      : Flow identification
- ARGUS_DSR_TYPE_TCP       : TCP state and metrics
- ARGUS_DSR_TYPE_ICMP      : ICMP type/code
- ARGUS_DSR_TYPE_JITTER    : Performance metrics
- ARGUS_DSR_TYPE_APP       : Application layer data
```

## Processing Pipeline

### Packet Processing Flow

```
1. Packet Arrival
   │
   ▼
2. Interface Processing (ArgusSource.c)
   - Timestamp assignment
   - Interface identification
   - Link layer parsing
   │
   ▼
3. Filter Evaluation (argus_filter.c)
   - BPF filter matching
   - Expression evaluation
   │
   ▼
4. Protocol Parsing (Argus*.c)
   - Layer 2 (Ethernet, VLAN, etc.)
   - Layer 3 (IP, IPv6)
   - Layer 4 (TCP, UDP, ICMP)
   - Layer 7 (Application)
   │
   ▼
5. Flow Matching (ArgusModeler.c)
   - Hash lookup
   - Flow creation/update
   - State machine processing
   │
   ▼
6. Metrics Calculation (ArgusUtil.c)
   - Byte/packet counts
   - Timing metrics
   - Behavioral analysis
   │
   ▼
7. Output Generation (ArgusOutput.c)
   - Record formatting
   - File/socket writing
   - Compression
```

## Configuration System

### Configuration Hierarchy

```
1. Command-line options (highest priority)
2. Configuration files (-F option)
3. Environment variables
4. Default values (lowest priority)
```

### Configuration File Format

```conf
# Variable assignment
VARIABLE=value

# Comments with #
# Embedded comments with //
VARIABLE=value // comment

# Multiple values
ARGUS_INTERFACE=eth0
ARGUS_INTERFACE=eth1
```

### Key Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ARGUS_MONITOR_ID` | Unique probe identifier | hostname |
| `ARGUS_FLOW_TYPE` | Uni/Bidirectional flows | Bidirectional |
| `ARGUS_FLOW_KEY` | Flow aggregation strategy | CLASSIC_5_TUPLE |
| `ARGUS_INTERFACE` | Interface to monitor | first up |
| `ARGUS_OUTPUT` | Output file path | stdout |
| `ARGUS_DAEMON` | Run as daemon | no |

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

Argus tracks its own performance:
```c
- Packets processed per second
- Flows created per second
- Memory usage
- CPU utilization
- Output buffer saturation
```

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
// Argus drops privileges after binding
1. Start as root
2. Bind to privileged ports/interfaces
3. Drop to unprivileged user
4. Continue processing
```

## Extension Points

### Developing Custom Parsers

1. Create parser file: `ArgusCustom.c`
2. Implement parse function:
```c
int ArgusParseCustom(u_char *data, int len, struct ArgusFlow *flow)
{
    // Extract custom protocol fields
    // Update flow structure
    return bytes_consumed;
}
```

3. Register in protocol chain

### Custom Metrics

Add metrics to `ArgusMetricStruct`:
```c
struct ArgusMetricStruct {
    // Existing metrics
    double srate, drate;
    
    // Custom metrics
    double custom_metric_1;
    double custom_metric_2;
};
```

## File Formats

### Argus Data File Format

```
┌─────────────────────────────────────┐
│ File Header (64 bytes)              │
│ - Magic number                      │
│ - Version                           │
│ - Header size                       │
├─────────────────────────────────────┤
│ Record 1                            │
│ - Record length                     │
│ - Record type                       │
│ - DSR blocks...                     │
├─────────────────────────────────────┤
│ Record 2                            │
│ ...                                 │
└─────────────────────────────────────┘
```

### Record Types

- `ARGUS_RECORD_FLOW` : Standard flow record
- `ARGUS_RECORD_EVENT` : System event
- `ARGUS_RECORD_ALERT` : Security alert
- `ARGUS_RECORD_STATUS` : Status update

## Integration Points

### With argus-clients

```
argus (sensor) ──┐
                 ├──▶ ra (viewer)
                 ├──▶ racluster (aggregate)
                 ├──▶ rasum (summary)
                 └──▶ radump (file inspection)
```

### With External Systems

- **SIEM**: Syslog, CEF, LEEF output
- **Storage**: File, database, message queue
- **Visualization**: Grafana, Kibana plugins
- **Analytics**: Python/R data export

## Design Principles

1. **Comprehensive**: Capture all network activity, not just IP
2. **Extensible**: Easy to add new protocols and metrics
3. **Efficient**: Minimize memory and CPU overhead
4. **Portable**: Run on diverse platforms
5. **Accurate**: Precise timestamps and measurements
6. **Secure**: Defense in depth approach

## Future Directions

- Enhanced ML/ML integration points
- Real-time anomaly detection
- Distributed flow correlation
- Enhanced encryption support
- Cloud-native deployment options

## References

- [RFC 7011](https://tools.ietf.org/html/rfc7011) - IPFIX
- [RFC 3954](https://tools.ietf.org/html/rfc3954) - NetFlow v9
- [IPDR/SP](https://www.ipdr.org/) - IP Storage Protocol

---

For implementation details, see the source code comments in each module.
