# Security-review regression tests (sensor repo)

This directory holds small, targeted regression tests for specific fixes made during the
2026-09 security review (see `../findings-log.md` and `../SECURITY-REVIEW-REPORT.md`). It is
separate from `../fuzz/`, which fuzzes/replays a corpus against the single `ArgusProcessPacket()`
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

`fixtures/babel.pcap`, `fixtures/bgp-infinite-loop.pcap`, and `fixtures/lsp-ping-timestamp.pcap`
are copied from tcpdump's own public, BSD-licensed regression-test corpus
(https://github.com/the-tcpdump-group/tcpdump, `tests/` directory) — all three are
`DLT_LINUX_SLL`-linktype captures, tiny (116 bytes - 3.3 KB), and safe to redistribute. No
proprietary, customer, or otherwise sensitive capture data is used anywhere in this directory.
