# Security-review regression tests (sensor repo)

This directory holds small, targeted regression tests for specific fixes and hardening changes
from the 2026-09 security review and later follow-up work (see `../findings-log.md` and
`../SECURITY-REVIEW-REPORT.md`). It is separate from `../fuzz/`, which
fuzzes/replays a corpus against the single `ArgusProcessPacket()`
choke point. These tests exist because several of the review's fixes are in code paths that
harness never reaches (signal handling, resource-file parsing, output-filter setup, the sFlow
read loop, and DLT_LINUX_SLL packet dispatch), so the fuzz-regression job alone does not exercise
them.

## What is (and isn't) covered here

Each fix falls into one of two categories:

- **Deterministic, functional bugs** (a specific input or sequence of operations reliably
  triggers the bug every time): F-38, F-39, F-40, F-48. These have real pass/fail regression
  tests below that reproduce the original bug's exact conditions and check for the fixed
  behavior.
- **Concurrency/data-race bugs** (require a specific, timing-dependent interleaving of threads
  to manifest; not reliably reproducible on every run even on the buggy code): F-37, F-43, F-46.
  These get a **best-effort stress test** (`stress_multi_source_sll.sh`) that runs the same
  multi-source SLL scenario used during the original fixes' verification, under ASan, for many
  iterations. This substantially increases the odds of catching a reintroduced race, but -
  being a race - it is not guaranteed to fail every time the underlying bug is reintroduced.
  There is no claim here that this is a substitute for careful code review of any future change
   to this code.

- **Access-port exposure policy**: `test_access_port_loopback_default.sh` verifies that a positive
  access port with no explicit bind address listens only on IPv4 and IPv6 loopback. An explicit
  bind address remains the required configuration for external TCP access.

- **Input-filter cleanup**: `test_input_filter_cleanup.sh` verifies that resource-file and
  command-line filters are released cleanly after offline processing. The CI job enables
  `ARGUSMEMDEBUG` so allocation-family mismatches fail this test.

- **DHCP jitter statistics**: `test_dhcp_time_overflow.sh` verifies that a long DHCP replay
  interval does not overflow the microsecond jitter sum of squares. The ASan/UBSan CI job runs
  this test.

- **GRE capture bounds**: `test_gre_capture_bounds.sh` verifies that a truncated GRE routing
  header cannot advance Argus past captured packet data. The ASan/UBSan CI job runs this test.

- **PPP/HDLC capture bounds**: `test_ppp_hdlc_capture_bounds.sh` verifies that a truncated
  PPP/HDLC header cannot be read past captured packet data. The ASan/UBSan CI job runs this test.

- **PPP, PPP/BSDOS, and SLIP capture bounds**: `test_ppp_slip_capture_bounds.sh` creates
  one-byte `DLT_PPP`, `DLT_PPP_BSDOS`, and `DLT_SLIP` captures with larger wire lengths and
  verifies that the reported callbacks reject them before reading or pointer arithmetic. The
  ASan/UBSan CI job runs this test.

- **ENC and NULL capture bounds**: `test_enc_null_capture_bounds.sh` creates `DLT_ENC` and
  `DLT_NULL` captures with captured or wire lengths shorter than their fixed headers and verifies
  that the callbacks reject them before fixed-header access or length subtraction. The ASan/UBSan
  CI job runs this test.

- **FDDI conversion bounds**: `test_fddi_capture_bounds.sh` creates short, inconsistent,
  truncated-payload, and oversized `DLT_FDDI` captures, plus a valid IPv4 frame. It verifies that
  FDDI conversion rejects unsafe input before FDDI/LLC access or copying while retaining normal
  conversion behavior. The ASan/UBSan CI job runs this test.

- **sFlow datagram bounds**: `test_sflow_datagram_bounds.sh` sends malformed datagrams through
  both offline `sflow:<pcap>` and live `sflow://` sources. It covers a truncated version field,
  IPv6 agent address, oversized encoded string, sampled-header record, and sampled IPv4, IPv6,
  and Ethernet headers, while retaining a valid sFlow v5 sampled-packet path. The ASan/UBSan CI
  job runs this test.

- **Radiotap capture bounds**: `test_radiotap_capture_bounds.sh` verifies that a truncated
  radiotap present-bitmap extension cannot be read past captured packet data. The ASan/UBSan CI
  job runs this test.

F-41 (encaps-capture buffer lifecycle) and F-49 (Makefile failure-masking) are not covered by
tests in this directory: F-41 is not yet merged, and F-49 was verified via `make`-level fault
injection, not a program input, and doesn't fit this directory's per-fix-test pattern.

## Running locally

```sh
./configure
sh security-review/fuzz/build.sh plain   # builds an ASan/UBSan sensor into security-review/fuzz/build/
sh security-review/regression-tests/run_all.sh
```

`run_all.sh` builds a plain (non-sanitized) `bin/argus` via the normal top-level `make`, plus
reuses the ASan build from `security-review/fuzz/build.sh` for the tests that need it, and runs
every `test_*.sh` script in this directory, reporting a final pass/fail summary. Each script can
also be run standalone; see the comment header in each file for what it checks and why.

## Fixtures

`fixtures/babel.pcap`, `fixtures/bgp-infinite-loop.pcap`, `fixtures/dhcp-rfc4388.pcap`,
`fixtures/gre-heapoverflow-2.pcap`, `fixtures/heapoverflow-ppp_hdlc_if_print.pcap`,
`fixtures/lsp-ping-timestamp.pcap`, and `fixtures/radiotap-heapoverflow.pcap` are copied from
tcpdump's own public, BSD-licensed regression-test corpus
(https://github.com/the-tcpdump-group/tcpdump, `tests/` directory). They are tiny (42 bytes - 14
KB) and safe to redistribute. No
proprietary, customer, or otherwise sensitive capture data is used anywhere in this directory.
