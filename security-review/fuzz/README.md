# security-review/fuzz

Fuzzing harness and regression corpus from the 2026-09-02 security review.
Findings F-1 through F-34 were fixed directly in the sensor source (see git
log / commit messages for each fix); this directory holds the fuzzing
harness and the regression corpus used to guard against those bugs
reappearing.

## Contents

- `fuzz_process_packet.c` — a standalone harness that calls
  `ArgusProcessPacket()` directly on a raw packet buffer, without needing a
  live capture interface or PCAP file. Compiled with
  `-fsanitize=address,undefined` so it aborts on any memory-safety or
  undefined-behavior violation, not just on outright segfaults.
- `build.sh` — builds the harness against the real sensor object files.
  Requires `./configure` to have already been run (needs
  `include/argus_config.h`). Two modes:
  - `build.sh` (default) — AFL++-instrumented build, for running new fuzzing
    campaigns (`afl-fuzz`) if you have `afl-clang-fast` installed.
  - `build.sh plain` — plain clang build, no AFL instrumentation. This is
    what CI uses to replay saved inputs quickly.
- `corpus/` — a small set of hand-crafted, valid protocol packets (ARP,
  ICMP, TCP SYN, UDP/DNS, GRE, IPv6, NetFlow v9, VLAN, IP fragment, etc.)
  used both as an initial AFL seed corpus and as a basic smoke-test set.
- `crashes/` — a handful of specific hand-minimized reproducers for early
  findings, kept for readability/documentation purposes.
- `regression-corpus/` — the deduplicated, accumulated set of every unique
  crashing input saved across every AFL campaign run during the review
  (spanning multiple pre-fix/post-fix snapshots). This is the actual
  regression-test asset: at the end of the original review, replaying this
  entire set against the fully-fixed sensor produced zero crashes. CI
  replays it on every push/PR to make sure that stays true.

## Running locally

```sh
./configure
sh security-review/fuzz/build.sh plain
for f in security-review/fuzz/corpus/* \
         security-review/fuzz/crashes/* \
         security-review/fuzz/regression-corpus/*; do
  ./security-review/fuzz/fuzz_process_packet "$f" || echo "CRASH: $f"
done
```

## Running a new AFL campaign

```sh
./configure
sh security-review/fuzz/build.sh          # afl-clang-fast build
afl-fuzz -i security-review/fuzz/corpus -o /tmp/afl-out \
  -- security-review/fuzz/fuzz_process_packet @@
```

Any new crashes found should be minimized (`afl-tmin`), triaged, fixed
upstream in the sensor code, and — once confirmed to reproduce the bug
pre-fix and not reproduce post-fix — added to `regression-corpus/` so CI
guards against a regression going forward.
