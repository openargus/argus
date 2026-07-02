# Argus Configuration Guide

This guide provides a comprehensive overview of Argus configuration options and best practices.

## Table of Contents

- [Configuration File Format](#configuration-file-format)
- [Configuration Hierarchy](#configuration-hierarchy)
- [Core Configuration Variables](#core-configuration-variables)
- [Interface Configuration](#interface-configuration)
- [Flow Configuration](#flow-configuration)
- [Output Configuration](#output-configuration)
- [Security Configuration](#security-configuration)
- [Performance Tuning](#performance-tuning)
- [Example Configurations](#example-configurations)

---

## Configuration File Format

### Syntax

Configuration files use a simple key=value format:

```conf
# Comments start with #
VARIABLE=value

# Embedded comments use //
VARIABLE=value // inline comment

# Quoted values for strings with spaces
VARIABLE="value with spaces"
```

### Rules

1. No spaces around the `=` sign
2. Comments must be on their own line or after a space/tab
3. Values can be:
   - Numbers: `12345`
   - Strings: `"mystring"` or `mystring`
   - IP addresses: `192.168.1.1`
   - Booleans: `yes`/`no` or `true`/`false`

---

## Configuration Hierarchy

Argus reads configuration in this order (later overrides earlier):

1. **Compiled-in defaults**
2. **Environment variables** (`ARGUS_*`)
3. **Default config files** searched in order:
   - `/etc/argus.conf`
   - `$ARGUSPATH/argus.conf`
   - `$ARGUSHOME/argus.conf`
   - `$HOME/argus.conf`
4. **Explicit config files** (`-F` option, in order specified)
5. **Command-line options** (highest priority)

### Example Priority

```bash
# Command line overrides file
argus -F /etc/argus.conf -i eth0

# If eth0 is also in /etc/argus.conf, command line wins
```

---

## Core Configuration Variables

### ARGUS_MONITOR_ID

**Purpose:** Unique identifier for this Argus probe

**Values:**
- Integer: `12345`
- IPv4 address: `192.168.1.1`
- IPv6 address: `fe80::1`
- String (4 chars): `"probe1"`
- UUID: `5E487EDE-B311-5E80-B69F-967E5E6C7A9F`
- Special: `hostname` or `hostuuid`

**Format:** `[type:/]sid[/inf]`

**Examples:**
```conf
# Simple hostname
ARGUS_MONITOR_ID=hostname

# UUID with interface
ARGUS_MONITOR_ID=uuid:/5E487EDE-B311-5E80-B69F-967E5E6C7A9F/en0

# Static IP
ARGUS_MONITOR_ID=192.168.1.100

# Custom name
ARGUS_MONITOR_ID="prod-core-01"
```

**Command-line:** `-e <id>`

---

### ARGUS_DAEMON

**Purpose:** Run Argus as a daemon process

**Values:** `yes` | `no`

**Examples:**
```conf
# Run as daemon (for init scripts)
ARGUS_DAEMON=yes

# Run in foreground (for debugging)
ARGUS_DAEMON=no
```

**Command-line:** `-d` (enables daemon mode)

---

### ARGUS_FLOW_TYPE

**Purpose:** Directionality of flow tracking

**Values:**
- `Bidirectional`: Combine src→dst and dst→src (default)
- `Unidirectional`: Track each direction separately

**Examples:**
```conf
# Default - bidirectional flows
ARGUS_FLOW_TYPE=Bidirectional

# Unidirectional for specific analysis
ARGUS_FLOW_TYPE=Unidirectional
```

**Impact:** 
- Bidirectional: Half the flow records, combined metrics
- Unidirectional: More records, separate direction metrics

---

### ARGUS_FLOW_KEY

**Purpose:** Strategy for aggregating packets into flows

**Values:**
- `CLASSIC_5_TUPLE`: src_ip, dst_ip, src_port, dst_port, proto
- `LAYER_2_MATRIX`: Include MAC addresses
- `LAYER_3_MATRIX`: Include IP + ports
- `MPLS`: Include MPLS labels
- `VLAN`: Include VLAN tags
- Custom combinations

**Examples:**
```conf
# Standard 5-tuple (default)
ARGUS_FLOW_KEY=CLASSIC_5_TUPLE

# Include Layer 2 information
ARGUS_FLOW_KEY=CLASSIC_5_TUPLE+LAYER_2

# VLAN-aware flows
ARGUS_FLOW_KEY=CLASSIC_5_TUPLE+VLAN
```

---

## Interface Configuration

### ARGUS_INTERFACE

**Purpose:** Specify network interfaces to monitor

**Syntax:** `interface[/srcid]`

**Examples:**
```conf
# Single interface
ARGUS_INTERFACE=eth0

# Multiple interfaces
ARGUS_INTERFACE=eth0
ARGUS_INTERFACE=eth1
ARGUS_INTERFACE=eth2

# Interface with custom source ID
ARGUS_INTERFACE=eth0/monitor1

# All interfaces
ARGUS_INTERFACE=all

# Interface pairs (ingress/egress)
ARGUS_INTERFACE=dup:en0,en1/"ap01"
```

**Command-line:** `-i <interface>`

---

### Interface Selection Tips

**For SPAN/Mirror Ports:**
```conf
# Single interface receiving mirrored traffic
ARGUS_INTERFACE=span0
```

**For Multi-Homed Systems:**
```conf
# Monitor multiple interfaces separately
ARGUS_INTERFACE=eth0
ARGUS_INTERFACE=eth1
ARGUS_INTERFACE=eth2
```

**For Bonded/Aggregated Interfaces:**
```conf
# Monitor the bond interface
ARGUS_INTERFACE=bond0
```

**For VLAN Tagged Traffic:**
```conf
# Monitor VLAN subinterface
ARGUS_INTERFACE=eth0.100
```

---

## Output Configuration

### ARGUS_OUTPUT

**Purpose:** Output destination for flow records

**Values:**
- File path: `/var/log/argus/data.argus`
- Socket: `host:port`
- Stdout: `-`

**Examples:**
```conf
# Write to file
ARGUS_OUTPUT=/var/log/argus/data.argus

# Write to socket (for remote collection)
ARGUS_OUTPUT=collector.example.com:5100

# Write to stdout (for piping)
ARGUS_OUTPUT=-
```

**Command-line:** `-w <file>` or `-S <host:port>`

---

### Output Options

**File Rotation:**
```conf
# Rotate files based on size
ARGUS_OUTPUT_MAX_SIZE=104857600  # 100MB

# Rotate files based on time
ARGUS_OUTPUT_MAX_TIME=86400      # 24 hours
```

**Compression:**
```conf
# Enable gzip compression
ARGUS_COMPRESS=yes

# Compression level (1-9)
ARGUS_COMPRESS_LEVEL=6
```

**Buffer Size:**
```conf
# Output buffer size in bytes
ARGUS_OUTPUT_BUFFER=1048576  # 1MB
```

---

## Security Configuration

### Authentication

**TCP Wrappers:**
```conf
# Edit /etc/hosts.allow and /etc/hosts.deny
# Allow specific hosts
echo "argus: 192.168.1.0/24" >> /etc/hosts.allow

# Deny all others
echo "argus: ALL" >> /etc/hosts.deny
```

**SASL Authentication:**
```conf
# Enable SASL
ARGUS_SASL=yes

# SASL mechanism
ARGUS_SASL_MECH=PLAIN
```

### Privilege Separation

```conf
# Drop to user after startup
ARGUS_USER=argus

# Drop to group
ARGUS_GROUP=argus

# Chroot after startup
ARGUS_CHROOT=/var/argus
```

---

## Performance Tuning

### Flow Table Management

```conf
# Maximum number of concurrent flows
ARGUS_MAX_FLOWS=1000000

# Flow timeout (active flows)
ARGUS_FLOW_TIMEOUT=300

# Flow timeout (inactive flows)
ARGUS_FLOW_TIMEOUT_INACTIVE=60

# Flow expiration check interval
ARGUS_FLOW_EXPIRE_INTERVAL=30
```

### Memory Management

```conf
# Pre-allocate flow cache
ARGUS_FLOW_CACHE_SIZE=2097152

# Memory pool size
ARGUS_MEMORY_POOL_SIZE=134217728
```

### CPU Optimization

```conf
# Limit to specific CPU cores (Linux)
ARGUS_CPU_AFFINITY=0,1

# Thread count (if threaded build)
ARGUS_THREAD_COUNT=4
```

### Packet Capture Tuning

```conf
# Packet buffer size
ARGUS_PACKET_BUFFER_SIZE=262144

# Packet snapshot length
ARGUS_SNAPLEN=65535

# Promiscuous mode
ARGUS_PROMISC=yes
```

---

## Example Configurations

### Basic Production Setup

```conf
# /etc/argus.conf - Basic Production Configuration

# Identify this probe
ARGUS_MONITOR_ID=hostname

# Flow settings
ARGUS_FLOW_TYPE=Bidirectional
ARGUS_FLOW_KEY=CLASSIC_5_TUPLE

# Interfaces
ARGUS_INTERFACE=eth0
ARGUS_INTERFACE=eth1

# Output
ARGUS_OUTPUT=/var/log/argus/data.argus
ARGUS_OUTPUT_MAX_SIZE=536870912  # 512MB

# Daemon mode
ARGUS_DAEMON=yes

# Logging
ARGUS_LOG_SYSLOG=yes
```

### High-Performance Core Network

```conf
# /etc/argus.conf - High Performance Core Network

# Unique identifier
ARGUS_MONITOR_ID=uuid:/$(cat /etc/machine-id)/core01

# Aggressive flow settings
ARGUS_FLOW_TYPE=Bidirectional
ARGUS_FLOW_KEY=CLASSIC_5_TUPLE
ARGUS_MAX_FLOWS=10000000
ARGUS_FLOW_TIMEOUT=600
ARGUS_FLOW_TIMEOUT_INACTIVE=120

# Multiple interfaces
ARGUS_INTERFACE=eth0
ARGUS_INTERFACE=eth1
ARGUS_INTERFACE=eth2
ARGUS_INTERFACE=eth3

# High-performance output
ARGUS_OUTPUT=/mnt/raid/argus/data.argus
ARGUS_OUTPUT_BUFFER=4194304  # 4MB buffer
ARGUS_COMPRESS=yes
ARGUS_COMPRESS_LEVEL=1

# CPU optimization
ARGUS_CPU_AFFINITY=0,1,2,3

# Daemon mode
ARGUS_DAEMON=yes

# Resource limits
ARGUS_FLOW_CACHE_SIZE=16777216
```

### Security Monitoring (NIDS Integration)

```conf
# /etc/argus.conf - Security Monitoring

# Identify probe
ARGUS_MONITOR_ID=security-probe-01

# Detailed flow tracking
ARGUS_FLOW_TYPE=Unidirectional
ARGUS_FLOW_KEY=CLASSIC_5_TUPLE+LAYER_2

# SPAN port for traffic mirror
ARGUS_INTERFACE=span0

# Enable detailed metrics
ARGUS_ENABLE_JITTER_METRICS=yes
ARGUS_ENABLE_APP_METRICS=yes

# Output to SIEM
ARGUS_OUTPUT=siem.example.com:5100

# Alert on suspicious activity
ARGUS_ALERT_ON_SYN_FLOOD=yes
ARGUS_ALERT_ON_PORT_SCAN=yes

# Daemon mode
ARGUS_DAEMON=yes
```

### Development/Testing

```conf
# /etc/argus.conf - Development Configuration

# Debug settings
ARGUS_MONITOR_ID="dev-probe"

# Simple flow tracking
ARGUS_FLOW_TYPE=Bidirectional
ARGUS_FLOW_KEY=CLASSIC_5_TUPLE

# Test interface
ARGUS_INTERFACE=eth0

# Output to file for analysis
ARGUS_OUTPUT=/tmp/argus-test.argus

# No daemon (foreground for debugging)
ARGUS_DAEMON=no

# Verbose logging
ARGUS_LOG_LEVEL=debug
```

### Container Deployment

```conf
# /etc/argus.conf - Docker/Kubernetes

# Use environment variable for ID
ARGUS_MONITOR_ID=${POD_IP}

# Single interface
ARGUS_INTERFACE=eth0

# Output to stdout for logging
ARGUS_OUTPUT=-

# Non-daemon mode for container
ARGUS_DAEMON=no

# Minimal flow tracking
ARGUS_FLOW_TYPE=Bidirectional
ARGUS_FLOW_KEY=CLASSIC_5_TUPLE
ARGUS_MAX_FLOWS=100000
```

---

## Environment Variables

Argus can be configured via environment variables:

```bash
# Set before running argus
export ARGUS_MONITOR_ID="my-probe"
export ARGUS_INTERFACE=eth0
export ARGUS_OUTPUT=/var/log/argus/data.argus

# Or in /etc/default/argus (systemd)
# /etc/systemd/system/argus.service.d/env.conf
Environment="ARGUS_MONITOR_ID=prod-01"
Environment="ARGUS_INTERFACE=eth0,eth1"
```

---

## Configuration Validation

### Check Configuration Syntax

```bash
# Validate config file
argus -F /etc/argus.conf -V

# Test with debug output
argus -F /etc/argus.conf -D 1 -d
```

### Test Configuration

```bash
# Run in foreground with test config
argus -F /test.conf -i eth0 -w /tmp/test.argus

# Capture for 60 seconds then stop
timeout 60 argus -F /test.conf -i eth0 -w /tmp/test.argus

# Verify output
radump -r /tmp/test.argus | head
```

---

## Best Practices

### 1. Use Consistent Monitor IDs
```conf
# In production, use stable identifiers
ARGUS_MONITOR_ID=uuid:/$(cat /etc/machine-id)
```

### 2. Plan Output Storage
```conf
# Calculate storage needs
# 1 Gbps ≈ 1.5GB/hour at full packet rate
# Set appropriate rotation
ARGUS_OUTPUT_MAX_SIZE=1073741824  # 1GB
```

### 3. Secure Configuration Files
```bash
# Restrict config file access
sudo chmod 600 /etc/argus.conf
sudo chown root:argus /etc/argus.conf
```

### 4. Monitor Resource Usage
```conf
# Set reasonable limits
ARGUS_MAX_FLOWS=1000000
ARGUS_FLOW_TIMEOUT=300
```

### 5. Document Custom Configurations
```conf
# Add comments to explain custom settings
ARGUS_FLOW_KEY=CLASSIC_5_TUPLE+LAYER_2  # Required for MAC-based analysis
```

---

## Troubleshooting Configuration

### Config Not Being Read

```bash
# Check which config files exist
ls -la /etc/argus.conf
ls -la $HOME/argus.conf

# See what Argus is using
argus -V -F /path/to/config.conf
```

### Variable Not Applied

```bash
# Verify variable name
grep -i "variable_name" /usr/local/share/doc/argus.conf

# Check for typos in config
cat /etc/argus.conf | grep VARIABLE
```

### Multiple Config Files

```bash
# List all config files being read
argus -F /etc/argus.conf -F /etc/argus-custom.conf -D 2
```

---

## Related Documentation

- [argus.conf.5](../man/man5/argus.conf.5) - Complete configuration reference
- [Getting Started](getting-started.md) - Basic setup guide
- [Architecture](architecture.md) - System design overview
- [Troubleshooting](troubleshooting.md) - Common issues

---

For the complete list of configuration options, see the `argus.conf.5` man page.
