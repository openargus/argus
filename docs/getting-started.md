# Getting Started with Argus

This guide will help you get Argus up and running quickly for network flow monitoring.

## What is Argus?

Argus (Audit Record Generation and Utilization System) is a comprehensive network flow monitoring system that:
- Captures raw network packets
- Generates detailed flow records with extensive metrics
- Supports real-time and historical analysis
- Monitors all network protocols (Layer 2-7)

## Prerequisites

Before installing Argus, ensure you have:

- A Unix-like system (Linux, macOS, BSD, Solaris)
- Root/sudo access for installation
- Network interface with packet capture permissions
- Basic command-line knowledge

## Installation

### Option 1: Package Manager (Recommended for Production)

**Debian/Ubuntu:**
```bash
# Add repository (if available)
sudo apt-get update
sudo apt-get install argus argus-clients
```

**Fedora/RHEL:**
```bash
sudo dnf install argus argus-clients
```

**macOS (Homebrew):**
```bash
brew install argus
```

### Option 2: Build from Source

**Install Dependencies:**

Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libpcap-dev \
    flex \
    bison \
    zlib1g-dev \
    libssl-dev
```

Fedora/RHEL:
```bash
sudo dnf groupinstall "Development Tools"
sudo dnf install libpcap-devel flex bison zlib-devel openssl-devel
```

macOS:
```bash
brew install libpcap flex bison zlib openssl
```

**Build Argus:**
```bash
# Get the source
git clone https://github.com/openargus/argus.git
cd argus

# Configure
./configure --prefix=/usr/local

# Build
make

# Install (requires sudo)
sudo make install
```

**Verify Installation:**
```bash
argus -V
# Should output: argus-5.0.x
```

## Quick Start

### Basic Network Monitoring

1. **Start monitoring an interface:**
```bash
sudo argus -i eth0 -w /var/log/argus/data.argus
```

2. **View flow data in real-time:**
```bash
# In another terminal
ra -r /var/log/argus/data.argus | head -20
```

3. **Stop Argus:**
```bash
# Send SIGINT to the argus process
sudo killall argus
# Or use Ctrl+C if running in foreground
```

### Basic Configuration

Create `/etc/argus.conf`:

```conf
# /etc/argus.conf - Argus Configuration File

# Identify this probe
ARGUS_MONITOR_ID="prod-switch-monitor-01"

# Flow configuration
ARGUS_FLOW_TYPE="Bidirectional"
ARGUS_FLOW_KEY="CLASSIC_5_TUPLE"

# Interfaces to monitor
ARGUS_INTERFACE="eth0"
ARGUS_INTERFACE="eth1"

# Output file
ARGUS_OUTPUT="/var/log/argus/data.argus"

# Run as daemon
ARGUS_DAEMON=yes
```

### Start as a Service

**Systemd (Linux):**
```bash
# Create service file (if not provided by package)
sudo cp /usr/local/share/argus/argus.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable argus
sudo systemctl start argus

# Check status
sudo systemctl status argus
```

**LaunchDaemons (macOS):**
```bash
sudo cp /usr/local/share/argus/com.qosient.argus.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.qosient.argus.plist
```

## Understanding Argus Output

### Flow Record Format

Argus generates flow records with these key fields:

```
start time | end time | src addr | dst addr | proto | bytes | packets | flags
```

Example output:
```
2024-01-15 10:30:00.123 2024-01-15 10:30:05.456 192.168.1.100 10.0.0.1 TCP 15000 120 S
```

### Common Output Formats

**Tabular (default):**
```bash
ra -r data.argus
```

**CSV for Excel/Spreadsheets:**
```bash
ra -M csv -r data.argus > output.csv
```

**JSON:**
```bash
ra -M json -r data.argus > output.json
```

**Summary Statistics:**
```bash
rasum -r data.argus
```

## Common Use Cases

### 1. Network Traffic Analysis

Monitor total bandwidth usage:
```bash
ra -r data.argus -o st,et,saddr,daddr,ip.proto,sbytes,dbytes | \
    raaggregate -n 1m | \
    rasort -k 5 -rn | head -20
```

### 2. Security Monitoring

Detect port scans:
```bash
ra -r data.argus proto tcp -o st,saddr,daddr,dport,flags | \
    raaggregate -n 5m -k saddr,daddr | \
    rahistogram -k dport | \
    rahigh -n 100
```

### 3. Performance Monitoring

Monitor TCP retransmissions:
```bash
ra -r data.argus proto tcp -o st,saddr,daddr,tcp.sport,tcp.dport,tcp.retrans | \
    rahigh -k tcp.retrans -v
```

### 4. Protocol Distribution

Analyze protocol mix:
```bash
ra -r data.argus -o ip.proto | \
    rahistogram -k ip.proto
```

## Next Steps

Once you're comfortable with the basics:

1. **Read the Configuration Guide** - Learn advanced configuration options
2. **Explore Client Tools** - Discover all the ra* utilities
3. **Set Up Archiving** - Configure log rotation and storage
4. **Integrate with SIEM** - Connect to security information systems
5. **Monitor Multiple Interfaces** - Scale to enterprise deployments

## Troubleshooting

### Argus won't start

**Check permissions:**
```bash
# Ensure you have packet capture permissions
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/sbin/argus
```

**Check for conflicts:**
```bash
# Make sure no other process is using the interface
sudo lsof -i :argus_port
```

### No data being captured

**Verify interface:**
```bash
# Check interface name
ip link show
# or
ifconfig -a

# Test with tcpdump
sudo tcpdump -i eth0 -c 10
```

**Check filter syntax:**
```bash
# Test your filter expression
argus -i eth0 -b 'tcp port 80'
```

### Can't read output files

**Verify file format:**
```bash
file /var/log/argus/data.argus
# Should show: Argus data file
```

**Check ra version compatibility:**
```bash
ra -V
argus -V
# Versions should match
```

## Getting Help

- **Documentation**: See [Configuration Guide](configuration.md)
- **Man Pages**: `man argus`, `man argus.conf`
- **Mailing List**: argus-info@lists.andrew.cmu.edu
- **Bug Reports**: Use `./bin/argusbug`

## Resources

- [Argus Website](https://openargus.com)
- [Client Tools Documentation](https://github.com/openargus/clients)
- [Network Flow Monitoring Best Practices](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171.pdf)

## Summary

You should now be able to:
- Install Argus on your system
- Start basic network monitoring
- View and analyze flow data
- Configure common use cases

For more advanced topics, continue with the [Configuration Guide](configuration.md).
