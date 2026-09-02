#!/bin/sh
# Build the ArgusProcessPacket fuzz harness against the real sensor object files.
#
# Prerequisite: the sensor must already be configured (./configure) so that
# include/argus_config.h exists. This script does NOT run configure itself.
#
# Usage:
#   security-review/fuzz/build.sh            # AFL++ persistent-mode instrumented build
#   security-review/fuzz/build.sh plain      # plain clang build (no instrumentation, for quick repro/debug)

set -e

cd "$(dirname "$0")/../.."   # repo root (argus/argus)

REPO_ROOT="$(pwd)"
FUZZ_DIR="$REPO_ROOT/security-review/fuzz"
BUILD_DIR="$FUZZ_DIR/build"

mkdir -p "$BUILD_DIR"

if [ ! -f include/argus_config.h ]; then
   echo "error: include/argus_config.h not found -- run ./configure first" >&2
   exit 1
fi

MODE="${1:-afl}"

if [ "$MODE" = "afl" ]; then
   CC=afl-clang-fast
else
   CC=clang
fi

CFLAGS="-O1 -g -fno-omit-frame-pointer -DHAVE_CONFIG_H -I. -Iargus -Iinclude -Icommon -I/opt/homebrew/include"
# AddressSanitizer is essential here -- most of the interesting bug classes from the static
# analysis phase (F-6 UB shift, F-1/F-2 OOB array access, F-3 heap overflow) are exactly what
# ASan is built to catch, and afl-clang-fast's default instrumentation alone won't flag them
# unless the program crashes outright.
#
# UBSan's "alignment" check is deliberately EXCLUDED: Ethernet headers are 14 bytes, so an IP
# header (or any 4-byte-aligned struct) immediately following one is never 4-byte aligned
# relative to a 4-byte-aligned packet buffer -- this is universally tolerated, expected
# behavior in networking code on x86/ARM64 (both tolerate unaligned loads transparently) and
# would otherwise drown every single run in irrelevant noise before reaching a real bug.
CFLAGS="$CFLAGS -fsanitize=address,undefined -fno-sanitize=alignment -fno-sanitize-recover=all"

echo "Compiling sensor object files needed by the harness (mode=$MODE, CC=$CC)..."

# Object files required by ArgusProcessPacket's full call graph. Mirrors the real SRC list
# in argus/Makefile.in exactly (minus argus.c, which has main() + CLI/config parsing we don't
# want here). Note: ArgusMac.c is intentionally excluded -- it is NOT part of the real build
# (confirmed absent from argus/Makefile.in's SRC list; it does not compile against the current
# struct definitions and is dead/unmaintained code, not part of the shipped sensor).
SENSOR_SRCS="
argus/ArgusModeler.c
argus/ArgusSource.c
argus/ArgusUtil.c
argus/ArgusOutput.c
argus/ArgusUdp.c
argus/ArgusTcp.c
argus/ArgusIcmp.c
argus/ArgusIgmp.c
argus/ArgusEsp.c
argus/ArgusArp.c
argus/ArgusFrag.c
argus/ArgusUdt.c
argus/ArgusLcp.c
argus/ArgusIsis.c
argus/ArgusAuth.c
argus/Argus802.11.c
argus/ArgusApp.c
argus/ArgusEvents.c
argus/ArgusNetflow.c
argus/ArgusSflow.c
argus/ArgusVxLan.c
argus/ArgusGre.c
argus/ArgusL2TP.c
argus/ArgusIfnam.c
argus/ArgusGeneve.c
common/argus_util.c
common/argus_code.c
common/argus_filter.c
common/grammar.c
common/scanner.c
"

# grammar.y/scanner.l need bison/flex to regenerate grammar.c/scanner.c -- mirrors the real
# rules in common/Makefile exactly (LEX = "flex -Pargus_", YACC = "bison -y -p argus_").
if [ ! -f common/grammar.c ] || [ ! -f common/scanner.c ] || [ ! -f common/tokdefs.h ]; then
   echo "Generating common/grammar.c, tokdefs.h, and common/scanner.c via bison/flex..."
   ( cd common && rm -f grammar.c tokdefs.h && bison -y -p argus_ grammar.y -d && mv y.tab.c grammar.c && mv y.tab.h tokdefs.h )
   ( cd common && rm -f scanner.c && flex -Pargus_ -t scanner.l > scanner.c )
fi

OBJS=""
for src in $SENSOR_SRCS; do
   obj="$BUILD_DIR/$(basename "$src" .c).o"
   echo "  CC $src"
   if [ "$(basename "$src")" = "grammar.c" ]; then
      $CC $CFLAGS -Dyylval=argus_lval -c "$src" -o "$obj"
   else
      $CC $CFLAGS -c "$src" -o "$obj"
   fi
   OBJS="$OBJS $obj"
done

echo "Compiling harness..."
$CC $CFLAGS -c "$FUZZ_DIR/fuzz_process_packet.c" -o "$BUILD_DIR/fuzz_process_packet.o"

echo "Linking..."
$CC $CFLAGS \
   "$BUILD_DIR/fuzz_process_packet.o" $OBJS \
   -L/opt/homebrew/lib -lpcap -lz -lm \
   -o "$FUZZ_DIR/fuzz_process_packet"

echo "Built: $FUZZ_DIR/fuzz_process_packet"
