# Argus Daemon Architecture

**This file has been superseded.** The detailed, source-verified architecture description now lives at
[`docs/architecture.md`](docs/architecture.md), which covers the sensor's process structure, source file
responsibilities, protocol dispatch mechanism, output/configuration behavior, privilege handling, and
deployment topology — all confirmed directly against source rather than described generically.

For the on-wire data format and DSR (Destination Specific Record) reference, see
[`docs/data-model.md`](docs/data-model.md).

This file is kept only for the build-system/platform information below, which is orthogonal to the
runtime architecture.

---

## Build System

### Directory Structure

```
argus/
├── argus/           # Sensor daemon source (argus.c, ArgusModeler.c, ArgusSource.c, ArgusOutput.c, ...)
├── common/          # Shared libraries (BPF filter engine, SASL auth, grammar/scanner)
│   ├── grammar.y    # Filter parser grammar
│   ├── scanner.l    # Filter lexer
│   └── *.c          # Common utilities
├── include/         # Header files
│   ├── argus/       # Argus-specific headers
│   └── net/         # Network protocol headers
├── bin/             # Helper scripts (e.g. argusbug)
├── man/             # Manual pages
│   ├── man5/        # argus.conf.5
│   └── man8/        # argus.8
├── debian/          # Debian packaging
└── pkg/             # Packaging for other targets
    ├── systemd/     # Systemd service files
    ├── init.d/      # SysV init scripts
    ├── sysconfig/   # sysconfig defaults
    ├── osx/, win/   # macOS / Windows packaging
    └── argus.conf   # Example configuration
```

### Build Process

```bash
./configure              # Detect system capabilities
make                      # Build all components
sudo make install         # Install to system
```

## Platform Support

Build-system support (verified via `configure.ac` platform-specific branches) exists for:

| Platform | Notes |
|---|---|
| Linux | Primary platform |
| macOS | |
| FreeBSD / OpenBSD / NetBSD | |
| Solaris | |
| AIX | |
| HP-UX (9.x, 10.x) | |
| Cygwin | Windows via Cygwin |

*(Runtime testing/support status per platform was not verified as part of this review — the above only
confirms that `configure.ac` has platform-specific build logic for each.)*

## Related Documentation

- [Architecture Overview](docs/architecture.md) — sensor process/component architecture (source-verified)
- [Data Model & DSR Reference](docs/data-model.md) — wire format and record structures (source-verified)
- [argus.conf(5)](man/man5/argus.conf.5) — configuration reference
- [argus(8)](man/man8/argus.8) — command reference
- [INSTALL](INSTALL) — build instructions
- [CONTRIBUTING.md](CONTRIBUTING.md) — development guidelines
