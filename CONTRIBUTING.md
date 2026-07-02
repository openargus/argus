# Contributing to Argus

Thank you for your interest in contributing to Argus! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

Please note that all participants are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project, you agree to abide by its terms.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, use the `argusbug` script or include as much detail as possible:

**Using argusbug (Preferred):**
```bash
./bin/argusbug
```

**Manual bug report should include:**
- Argus version (`argus -V`)
- Operating system and version
- Hardware architecture
- libpcap version
- Steps to reproduce the issue
- Expected vs. actual behavior
- Any relevant logs or error messages
- Configuration files (with sensitive data removed)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. Please include:
- Clear description of the enhancement
- Use case and motivation
- Any relevant examples or mockups
- Consideration of backwards compatibility

### Pull Requests

1. **Fork the repository** and create your branch from `master`
2. **Make your changes** following the coding guidelines below
3. **Test your changes** thoroughly
4. **Update documentation** if needed
5. **Submit a pull request** with a clear description

## Development Setup

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install build-essential libpcap-dev flex bison zlib1g-dev

# Fedora/RHEL
sudo dnf install gcc make libpcap-devel flex bison zlib-devel

# macOS
brew install libpcap flex bison zlib
```

### Building for Development

```bash
# Clone your fork
git clone https://github.com/yourusername/argus.git
cd argus

# Configure with debug symbols
./configure --enable-debug

# Build
make

# Run tests (if available)
make check

# Install locally for testing
make install prefix=/usr/local
```

## Coding Guidelines

### Code Style

Argus follows traditional C coding conventions:

**Indentation:**
- Use 4 spaces for indentation (no tabs)
- Align code for readability
- Keep lines under 100 characters when possible

**Example:**
```c
/* Good */
if (condition) {
    do_something();
    if (nested_condition) {
        do_something_else();
    }
}

/* Bad */
if(condition){
do_something();
}
```

**Naming Conventions:**
- Functions: `ArgusFunctionName` or `argus_function_name`
- Variables: `camelCase` or `snake_case`
- Constants: `UPPER_CASE`
- Types: `ArgusTypeName` (structs, typedefs)

**File Organization:**
```c
/*
 * File comment with description
 * Copyright notice
 */

/* Include guards */
#ifndef FILENAME_H
#define FILENAME_H

/* Includes */
#include "header.h"

/* Function declarations */
void ArgusFunction(void);

#endif /* FILENAME_H */
```

### Documentation

**Inline Comments:**
- Comment complex logic
- Explain "why" not "what"
- Keep comments up-to-date with code changes

**Function Documentation:**
```c
/*
 * ArgusProcessPacket - Process a single packet
 *
 * This function parses packet headers and updates flow statistics.
 * It handles protocol-specific processing based on packet type.
 *
 * @param packet    Pointer to packet data
 * @param length    Length of packet data
 * @param flow      Flow structure to update
 *
 * @return 0 on success, -1 on error
 */
int ArgusProcessPacket(u_char *packet, int length, struct ArgusFlow *flow)
{
    /* Implementation */
}
```

### Error Handling

- Always check return values
- Use appropriate error codes
- Provide meaningful error messages
- Clean up resources on error

```c
int ArgusAllocateMemory(void)
{
    void *ptr = malloc(SIZE);
    if (ptr == NULL) {
        ArgusLog(LOG_ERR, "Failed to allocate memory: %s", strerror(errno));
        return -1;
    }
    return 0;
}
```

### Testing

- Test on multiple platforms when possible
- Test edge cases and error conditions
- Verify no memory leaks (use valgrind)
- Ensure backwards compatibility

```bash
# Run with valgrind for memory checks
valgrind --leak-check=full ./argus -i eth0 -r test.pcap

# Test with different configurations
./argus -i eth0 ARGUS_FLOW_TYPE=Unidirectional
```

## Git Workflow

### Commit Messages

Follow conventional commit format:
```
type(scope): subject

body (optional)

footer (optional)
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Build process or auxiliary tool changes

**Examples:**
```
feat(tcp): add TCP timestamp tracking

Fixes issue #123 by implementing RFC 1323 timestamp support.

- Add timestamp parsing to ArgusTcp.c
- Add new DSR metric for RTT calculation
- Update documentation

refs: #123
```

```
fix(parse): handle fragmented ICMP packets

Previously, fragmented ICMP packets caused a crash.
This fix adds proper fragmentation reassembly handling.
```

### Branch Naming

```
feature/<description>
bugfix/<issue-number>
hotfix/<description>
docs/<topic>
```

## Review Process

1. All pull requests require at least one reviewer approval
2. Maintainers will review within a reasonable timeframe
3. Address review feedback promptly
4. Squash minor commits before merging

## Release Process

Releases are managed by maintainers. Contributors should:
- Tag releases with semantic versioning (vX.Y.Z)
- Update CHANGELOG with changes
- Create release notes

## Getting Help

- **Mailing List**: argus-info@lists.andrew.cmu.edu
- **Development**: argus-dev@lists.andrew.cmu.edu
- **Issues**: GitHub Issues (use argusbug for bugs)

## Recognition

Contributors will be recognized in:
- CREDITS file
- Release notes
- Git commit history

## License

By contributing to Argus, you agree that your contributions will be licensed under the GPL-3.0 license.

---

Thank you for making Argus better!
