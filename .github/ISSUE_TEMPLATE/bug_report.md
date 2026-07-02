---
name: Bug Report
about: Create a report to help us improve Argus
title: '[Bug] '
labels: 'bug'
assignees: ''
---

## Bug Description

A clear and concise description of what the bug is.

## How to Reproduce

Steps to reproduce the behavior:
1. Start Argus with command '...'
2. Configure with '...'
3. Observe behavior
4. See error

## Expected Behavior

A clear and concise description of what you expected to happen.

## Actual Behavior

What actually happened instead.

## Environment

Please run the following and paste the output:

```bash
argus -V
uname -a
cat /etc/os-release
```

**Argus Version:** [e.g. 5.0.0]
**Operating System:** [e.g. Ubuntu 22.04, macOS 13.0]
**Architecture:** [e.g. x86_64, aarch64]
**libpcap Version:** [e.g. 1.10.4]

## Configuration

If applicable, attach your `argus.conf` file (remove any sensitive information):

```conf
# Paste relevant configuration here
```

## Steps Taken

Please run `./bin/argusbug` and attach the output, or provide:

```bash
# Commands you've tried
# What worked/didn't work
```

## Logs

Attach relevant logs:
- Argus debug output (run with `-D 3` or higher)
- System logs (`/var/log/syslog`, `journalctl -u argus`)
- Error messages

## Additional Context

Add any other context about the problem here.

## Screenshots

If applicable, add screenshots to help explain your problem.

## Possible Solution

If you have suggestions for fixing the issue, describe them here.

---

**Note:** Please use `./bin/argusbug` to generate a properly formatted bug report with system information.
