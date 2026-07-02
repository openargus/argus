# Argus - Network Flow Monitoring System

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Version](https://img.shields.io/badge/version-5.0.0-green.svg)](https://github.com/openargus/argus/releases)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20BSD%20%7C%20Solaris-lightgrey.svg)](https://openargus.com)

**Argus** (Audit Record Generation and Utilization System) is the original network flow monitoring technology, developed since 1984. It generates comprehensive network flow data from raw packet captures for network operations, security analysis, performance monitoring, and forensics.

![Argus Logo](logo/argus_logo_medium-6aac34a9.png)

## Overview

Argus is a comprehensive network transaction auditing tool that:
- Processes raw packet data from network interfaces or capture files
- Generates detailed network flow records with extensive metrics
- Supports bi-directional and uni-directional flow tracking
- Accounts for all network activity (not just IP traffic)
- Provides data suitable for real-time analysis and historical forensics
- Enables AI/ML-based network analysis with rich feature sets

### Key Features

- **Comprehensive Protocol Support**: Layer 2-7 protocol analysis including IPv4/IPv6, TCP, UDP, ICMP, ARP, routing protocols (ISIS), and encapsulation protocols (VXLAN, GRE, Geneve, MPLS, VLAN)
- **Advanced Metrics**: Packet dynamics, jitter, throughput, application byte metrics, keystroke detection
- **Flexible Flow Keys**: Configurable flow aggregation strategies (5-tuple, Layer 2 matrix, custom keys)
- **Scalable Deployment**: Proven at scale from 1G to 100G+ networks
- **Cross-Platform**: Ported to Linux, macOS, BSD, Solaris, AIX, HPUX, VxWorks, and more
- **Secure**: Supports SASL authentication and TCP wrappers for access control

## Quick Start

### Installation

**Prerequisites:**
- libpcap (packet capture library)
- flex and bison (parser generators)
- C compiler (gcc/clang)
- zlib development libraries

**Build from source:**

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install build-essential libpcap-dev flex bison zlib1g-dev

# Install dependencies (Fedora/RHEL)
sudo dnf install gcc make libpcap-devel flex bison zlib-devel

# Build Argus
./configure
make
sudo make install
```

See [INSTALL](INSTALL) for detailed installation instructions.

### Basic Usage

```bash
# Monitor a network interface
sudo argus -i eth0 -w /var/log/argus/data.argus

# Read from pcap file
argus -r capture.pcap -w output.argus

# View flow data with ra (from argus-clients package)
ra -r /var/log/argus/data.argus | head

# Filter specific traffic
argus -i eth0 proto tcp -w tcp.flow.argus
```

### Configuration

Create `/etc/argus.conf`:

```conf
# Basic configuration
ARGUS_MONITOR_ID="argus-probe-01"
ARGUS_FLOW_TYPE="Bidirectional"
ARGUS_FLOW_KEY="CLASSIC_5_TUPLE"

# Interface monitoring
ARGUS_INTERFACE="eth0"
ARGUS_INTERFACE="eth1"

# Output configuration
ARGUS_OUTPUT="/var/log/argus/data.argus"
```

See [argus.conf.5](man/man5/argus.conf.5) for complete configuration options.

## Documentation

- [Getting Started Guide](docs/getting-started.md) - First-time setup and basic usage
- [Installation Guide](docs/installation.md) - Detailed build and deployment instructions
- [Architecture Overview](docs/architecture.md) - System design and components
- [Configuration Reference](docs/configuration.md) - Complete configuration guide
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions
- [Man Pages](man/) - Detailed command reference

## History

Argus was developed by Carter Bullard in 1984 at Georgia Tech and became a critical tool during:
- 1985: NSFnet backbone monitoring
- 1986-1987: Detection of Legion of Doom break-ins
- 1988: Morris Worm analysis at ArpaNet/NSFnet
- 1989-1991: Cyber security operations at CERT/SEI
- 1994: Open source release

Argus pioneered many flow monitoring concepts and continues to be the most comprehensive network flow system available.

## Related Projects

- **[argus-clients](https://github.com/openargus/clients)** - Client tools for processing and analyzing Argus data
  - `ra` - Print and filter Argus flow records
  - `rasum` - Summarize Argus data
  - `racluster` - Cluster and aggregate flows
  - `radump` - Dump Argus file format
  - `raprofiler` - Profile network behavior

## Support

### Mailing Lists

- **argus-info@lists.andrew.cmu.edu** - General discussion and support
- **argus-dev@lists.andrew.cmu.edu** - Development discussions

### Bug Reports

Please use the `./bin/argusbug` script to report issues:

```bash
./bin/argusbug
```

This collects system information and formats your report properly.

**Important**: Bug reports not generated with `argusbug` may be silently ignored. Please provide detailed information about your environment and the problem.

### Community

- [OpenArgus Website](https://openargus.com)
- [QoSient](http://qosient.com/argus) - Project homepage

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Argus is released under the **GNU General Public License v3.0** (GPL-3.0).

- See [COPYING](COPYING) for the complete license text
- Other licensing options available through QoSient, LLC

## Acknowledgments

Argus has been supported and used by:
- US Department of Defense
- National Science Foundation (GLORIAD network)
- Carnegie Mellon University CERT
- Government and enterprise networks worldwide

## Authors

- **Carter Bullard** - Original creator and lead developer
- **QoSient, LLC** - Current development and maintenance

For questions: argus@qosient.com

---

*Comprehensive network transaction auditing - 40 years of innovation*
