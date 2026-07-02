# Troubleshooting Guide

This guide covers common issues encountered when using Argus and their solutions.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Capture Problems](#capture-problems)
- [Configuration Issues](#configuration-issues)
- [Performance Problems](#performance-problems)
- [Output/Data Issues](#outputdata-issues)
- [Platform-Specific Issues](#platform-specific-issues)
- [Debugging Tools](#debugging-tools)

---

## Installation Issues

### Problem: `./configure` fails

**Symptoms:**
```
checking for pcap_create... no
configure: error: libpcap not found
```

**Solutions:**

1. **Install libpcap development files:**
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# Fedora/RHEL
sudo dnf install libpcap-devel

# macOS
brew install libpcap
```

2. **Specify libpcap location:**
```bash
./configure --with-pcap=/usr/local
```

3. **Check for conflicting installations:**
```bash
ldconfig -p | grep pcap
locate libpcap.so
```

### Problem: `make` fails with compilation errors

**Symptoms:**
```
argus.c:42:10: fatal error: 'argus_config.h' file not found
```

**Solutions:**

1. **Run configure first:**
```bash
./configure
make
```

2. **Clean and rebuild:**
```bash
make clean
./configure
make
```

3. **Check compiler compatibility:**
```bash
gcc --version
# Argus requires C99 or later
```

### Problem: `make install` permission denied

**Symptoms:**
```
install: cannot create regular file '/usr/local/bin/argus': Permission denied
```

**Solutions:**

```bash
# Use sudo
sudo make install

# Or install to user directory
./configure --prefix=$HOME/.local
make
make install
```

---

## Capture Problems

### Problem: No packets captured

**Symptoms:**
- Argus runs but generates no flow data
- `argus -i eth0` shows no activity

**Solutions:**

1. **Verify interface exists and is up:**
```bash
ip link show eth0
# Should show: state UP

ifconfig eth0
# Check for packets in/out counters
```

2. **Check for packet capture permissions:**
```bash
# Modern systems require capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/sbin/argus

# Or run as root
sudo argus -i eth0
```

3. **Test with tcpdump:**
```bash
sudo tcpdump -i eth0 -c 10
# If tcpdump sees nothing, the interface may not have traffic
```

4. **Check interface statistics:**
```bash
cat /proc/net/dev
# Look for packet counters increasing
```

### Problem: Packet capture errors

**Symptoms:**
```
argus: can't create capture handle: Permission denied
argus: pcap_activate failed: Operation not permitted
```

**Solutions:**

1. **Run with elevated privileges:**
```bash
sudo argus -i eth0
```

2. **Use capabilities (Linux):**
```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which argus)
```

3. **Check AppArmor/SELinux:**
```bash
# AppArmor
sudo aa-status

# SELinux
sudo getenforce
sudo ausearch -m avc -ts recent
```

### Problem: Filter doesn't work as expected

**Symptoms:**
- Filter expression seems to match nothing
- Unexpected packets captured

**Solutions:**

1. **Test filter syntax:**
```bash
# Use -b to dump compiled filter
argus -i eth0 -b 'tcp port 80'
```

2. **Verify filter with tcpdump:**
```bash
tcpdump -i eth0 'tcp port 80' -c 10
```

3. **Check filter complexity:**
```bash
# Complex filters may exceed BPF limits
# Simplify or break into multiple filters
```

4. **Common filter mistakes:**
```bash
# Wrong: Missing quotes
argus -i eth0 tcp port 80

# Correct: Use quotes
argus -i eth0 'tcp port 80'

# Wrong: Wrong operator
argus -i eth0 'tcp and port 80'

# Correct
argus -i eth0 'tcp port 80'
```

### Problem: High packet loss

**Symptoms:**
```
argus: packet drop count: 1500
```

**Solutions:**

1. **Increase ring buffer size:**
```bash
# Edit /etc/sysctl.conf
net.core.rmem_max=134217728
net.core.rmem_default=134217728
net.core.netdev_max_backlog=5000

# Apply
sudo sysctl -p
```

2. **Use dedicated CPU core:**
```bash
# Pin argus to a CPU core
taskset -c 0 argus -i eth0
```

3. **Check system load:**
```bash
top
# Look for high CPU or I/O wait
```

4. **Reduce filter complexity:**
```bash
# Simpler filters process faster
argus -i eth0 'not arp'  # Instead of complex expression
```

---

## Configuration Issues

### Problem: Configuration file not read

**Symptoms:**
- Expected settings not applied
- Default values used instead

**Solutions:**

1. **Verify file location:**
```bash
# Argus searches these locations
ls /etc/argus.conf
ls $ARGUSPATH/argus.conf
ls $HOME/argus.conf
```

2. **Specify configuration explicitly:**
```bash
argus -F /path/to/argus.conf
```

3. **Check file syntax:**
```bash
# Look for syntax errors
cat argus.conf | grep -v '^#' | grep -v '^$'

# Ensure no spaces around =
ARGUS_DAEMON=yes   # Correct
ARGUS_DAEMON = yes # Wrong - spaces around =
```

4. **Verify variable names:**
```bash
# Check for typos
grep ARGUS argus.conf
# Should match documented variable names
```

### Problem: Interface not found

**Symptoms:**
```
argus: interface eth0 not found
```

**Solutions:**

1. **List available interfaces:**
```bash
ip link show
# or
ifconfig -a
```

2. **Check interface name changes:**
```bash
# Modern Linux uses predictable names
# eth0 might be enp0s3
ip link
```

3. **Use 'all' for all interfaces:**
```bash
argus -i all
```

### Problem: Output file not created

**Symptoms:**
- `-w` option specified but no file created
- File created but empty

**Solutions:**

1. **Check directory permissions:**
```bash
ls -ld /var/log/argus/
# Should be writable by argus user
```

2. **Verify output path:**
```bash
# Use absolute path
argus -w /var/log/argus/data.argus

# Not relative
argus -w data.argus
```

3. **Check disk space:**
```bash
df -h /var/log/
```

4. **Test output:**
```bash
# Write to stdout first
argus -i eth0 -W - | head
```

---

## Performance Problems

### Problem: High CPU usage

**Symptoms:**
- argus process consuming excessive CPU
- System slowdown during capture

**Solutions:**

1. **Check packet rate:**
```bash
# Use argus to monitor itself
argus -i eth0 -M cpu
```

2. **Reduce captured traffic:**
```bash
# Filter to only needed traffic
argus -i eth0 'tcp or udp'
```

3. **Optimize flow aggregation:**
```bash
# Use simpler flow keys
ARGUS_FLOW_KEY="CLASSIC_5_TUPLE"
```

4. **Increase sampling:**
```bash
# Sample every Nth packet
argus -i eth0 -S 10
```

### Problem: Memory exhaustion

**Symptoms:**
```
argus: out of memory
```

**Solutions:**

1. **Set flow limits:**
```bash
# Limit maximum flows
ARGUS_MAX_FLOWS=1000000
```

2. **Reduce flow timeout:**
```bash
# Expire flows faster
ARGUS_FLOW_TIMEOUT=300
```

3. **Check for memory leaks:**
```bash
# Use valgrind
valgrind --leak-check=full argus -i eth0 -r test.pcap
```

4. **Monitor memory usage:**
```bash
watch -n 1 'ps -o rss= -C argus'
```

### Problem: Slow output writing

**Symptoms:**
- Argus buffers growing
- Packet loss due to slow I/O

**Solutions:**

1. **Use asynchronous output:**
```bash
# Write to socket instead of file
argus -i eth0 -S localhost:5100
```

2. **Increase buffer size:**
```bash
ARGUS_OUTPUT_BUFFER=1048576
```

3. **Compress output:**
```bash
# Use gzip compression
argus -i eth0 -w - | gzip > data.argus.gz
```

4. **Use faster storage:**
```bash
# Write to SSD/RAM disk
mount -t tmpfs -o size=4G tmpfs /mnt/argus
argus -i eth0 -w /mnt/argus/data.argus
```

---

## Output/Data Issues

### Problem: Flow records look incorrect

**Symptoms:**
- Wrong byte counts
- Missing timestamps
- Incorrect protocol detection

**Solutions:**

1. **Verify source data:**
```bash
# Check if packets are being captured
tcpdump -i eth0 -c 100 -w test.pcap
argus -r test.pcap -W - | ra -r -
```

2. **Check flow direction:**
```bash
# Verify bidirectional vs unidirectional
argus -i eth0 ARGUS_FLOW_TYPE=Unidirectional
```

3. **Inspect raw records:**
```bash
# Use radump for detailed inspection
radump -r data.argus | head -50
```

4. **Verify timestamp source:**
```bash
# Check system time
date
timedatectl

# Check NTP
ntpstat
```

### Problem: Can't read Argus files with ra

**Symptoms:**
```
ra: file format not recognized
```

**Solutions:**

1. **Check file format:**
```bash
file data.argus
# Should show: Argus data file
```

2. **Verify version compatibility:**
```bash
argus -V
ra -V
# Versions should match
```

3. **Check file integrity:**
```bash
# File may be truncated
ls -l data.argus
# Compare with expected size
```

4. **Try different read modes:**
```bash
# Auto-detect format
ra -r data.argus

# Force format
ra -F argus -r data.argus
```

### Problem: Missing metrics in output

**Symptoms:**
- Expected fields not shown
- Zero values for metrics

**Solutions:**

1. **Request specific fields:**
```bash
# Default may not show all fields
ra -r data.argus -o st,et,saddr,daddr,sbytes,dbytes,tcp.state
```

2. **Enable metric collection:**
```bash
# Some metrics require explicit enabling
ARGUS_ENABLE_JITTER_METRICS=yes
```

3. **Check protocol support:**
```bash
# Not all protocols have all metrics
ra -r data.argus proto tcp -o tcp.state,tcp.flags
```

---

## Platform-Specific Issues

### Linux

**Problem: Interface names changed**

```bash
# Check for predictable interface names
ls /sys/class/net/

# Use ethtool to identify
sudo ethtool -i eth0
```

**Problem: NetworkManager interference**

```bash
# Disable NetworkManager for monitored interfaces
sudo nmcli connection modify "eth0" connection.autoconnect no
sudo nmcli connection down "eth0"
```

### macOS

**Problem: No packet capture**

```bash
# Check firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps

# Add argus to allowed apps
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/local/sbin/argus
```

**Problem: Interface naming**

```bash
# macOS uses different naming
ifconfig -a
# en0, en1, etc.

# Use airport utility
sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I
```

### FreeBSD/OpenBSD

**Problem: Packet capture permissions**

```bash
# Add user to network group
sudo pw groupmod network -m $USER

# Or use bpf permissions
sudo chmod 600 /dev/bpf*
```

### Solaris

**Problem: Interface monitoring**

```bash
# Use dladm for interface management
sudo dladm show-link

# Grant privileges
usermod -K defaultpriv=basic,pckafka,user
```

---

## Debugging Tools

### Argus Debug Options

**Enable debug output:**
```bash
argus -i eth0 -D 1
# Levels 1-8, higher = more verbose
```

**Debug specific components:**
```bash
# Debug filter engine
argus -i eth0 -D filter

# Debug output
argus -i eth0 -D output
```

### System Debugging

**Monitor system calls:**
```bash
# Linux
strace -f -p $(pidof argus)

# macOS
dtruss -p $(pidof argus)
```

**Check resource usage:**
```bash
# Memory
pmap $(pidof argus)

# File descriptors
ls -l /proc/$(pidof argus)/fd/

# Network connections
netstat -an | grep argus
```

### Packet Analysis

**Capture for analysis:**
```bash
# Capture Argus traffic
tcpdump -i any -w argus_debug.pcap 'port 5100'

# Analyze with Wireshark
wireshark argus_debug.pcap
```

**Compare with tcpdump:**
```bash
# Run both simultaneously
tcpdump -i eth0 -w tcpdump.pcap &
argus -i eth0 -w argus.argus &

# Compare results
radump -r argus.argus | wc -l
tcpprint -r tcpdump.pcap | wc -l
```

### Logging

**Enable syslog:**
```bash
# Configure argus to use syslog
ARGUS_LOG_SYSLOG=yes

# Check logs
sudo tail -f /var/log/syslog | grep argus
```

**Custom logging:**
```bash
# Redirect stderr
argus -i eth0 2> argus_errors.log
```

---

## Getting More Help

### Information Gathering

Before contacting support, gather:

1. **System information:**
```bash
uname -a
argus -V
cat /etc/os-release
```

2. **Configuration:**
```bash
cat /etc/argus.conf
argus -F /etc/argus.conf -V
```

3. **Error logs:**
```bash
sudo dmesg | tail -50
sudo journalctl -u argus -n 100
```

4. **Test capture:**
```bash
argus -i eth0 -D 3 -w test.argus &
sleep 30
killall argus
radump -r test.argus | head -20
```

### Using argusbug

```bash
# Collect automatic diagnostic
./bin/argusbug

# This will:
# - Collect system info
# - Gather configuration
# - Format your report
```

### Mailing List

Send to: argus-info@lists.andrew.cmu.edu

Include:
- Problem description
- Steps to reproduce
- Expected vs actual behavior
- System information
- Relevant logs

---

## Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `Permission denied` | No packet capture rights | Run as root or set capabilities |
| `Interface not found` | Wrong interface name | Check `ip link show` |
| `Out of memory` | Too many flows | Reduce flow timeout or count |
| `Can't bind` | Port in use | Change port or stop conflicting service |
| `File format error` | Version mismatch | Match argus/ra versions |
| `Filter compile error` | Invalid filter syntax | Check filter with tcpdump |
| `No such device` | Interface down | Bring interface up with `ip link set up` |

---

## Prevention Tips

1. **Test in development first** before production deployment
2. **Monitor resource usage** during initial deployment
3. **Document your configuration** for troubleshooting
4. **Keep versions synchronized** between argus and clients
5. **Regular log rotation** to prevent disk exhaustion
6. **Use health checks** to monitor argus status
7. **Maintain backup configurations** for quick recovery

---

For additional help, see:
- [Argus Mailing List](https://lists.andrew.cmu.edu/mailman/listinfo/argus-info)
- [Documentation](https://openargus.com/docs)
- [GitHub Issues](https://github.com/openargus/argus/issues)
