# Security Policy

Argus captures and processes raw network traffic, including traffic from
untrusted or adversarial sources. A memory-safety or logic bug in a packet
parser can be a real security vulnerability (crash, memory disclosure, or
potentially worse), not just a reliability bug. Please help us handle these
reports responsibly.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**
Public issues are appropriate for ordinary bugs, but a public report of an
exploitable parsing bug gives attackers a head start before a fix is
available to users.

Instead, report suspected vulnerabilities privately using one of the
following:

1. **GitHub private vulnerability reporting** (preferred): use the
   "Report a vulnerability" button under this repository's
   [Security tab](https://github.com/openargus/argus/security/advisories/new).
   This creates a private advisory visible only to maintainers until a fix
   is ready.
2. **Email**: send details to carter@qosient.com. Please include "SECURITY"
   in the subject line.

### What to Include

To help us triage and fix the issue quickly, please include:

- A clear description of the vulnerability and its potential impact
  (crash, memory disclosure, out-of-bounds read/write, infinite loop /
  resource exhaustion, etc.)
- Argus version (`argus -V`) and platform (OS, architecture)
- Steps to reproduce, ideally a minimal input (e.g., a crafted packet,
  pcap file, or config file) that triggers the issue
- Any relevant crash output, sanitizer output (ASan/UBSan), or debugger
  backtrace
- Whether the issue is reachable from untrusted network traffic, from a
  local config file, or only from a trusted/privileged source

### What to Expect

- We will acknowledge receipt of your report as soon as reasonably possible.
- We will work with you to understand and reproduce the issue.
- Once a fix is available, we will coordinate on disclosure timing. We
  request that reporters allow us a reasonable window to release a fix
  before any public disclosure.
- Credit will be given in the fix's commit message and/or release notes,
  unless you prefer to remain anonymous.

## Supported Versions

Security fixes are applied to the current `main` branch. There is no formal
long-term-support branch at this time; users are encouraged to track
`main` or the latest tagged release.

## Scope

This policy covers the Argus sensor (`argus`) and its bundled packet
parsers, command-line tools, and build system in this repository. Issues in
third-party dependencies (e.g., libpcap, zlib) should be reported to those
projects directly, though we're happy to help coordinate if the issue is
specific to how Argus uses them.
