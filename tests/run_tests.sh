#!/bin/bash
# run_tests.sh - Build and run all libmacho unit tests.
#
# Usage:
#   cd tests/
#   bash run_tests.sh          # build (if needed) then run
#   bash run_tests.sh --no-build  # skip build, only run existing binaries

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

NO_BUILD=0
for arg in "$@"; do
    [ "$arg" = "--no-build" ] && NO_BUILD=1
done

TESTS="test_macho test_header test_command test_segment test_symtab"

# ── colours ─────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

echo "========================================"
echo " libmacho Test Suite"
echo "========================================"
echo ""

# ── optional build step ──────────────────────────────────────────────────
if [ "$NO_BUILD" -eq 0 ]; then
    needs_build=0
    for t in $TESTS; do
        [ ! -x "./$t" ] && needs_build=1 && break
    done
    if [ "$needs_build" -eq 1 ]; then
        echo "Building test binaries..."
        make all
        echo ""
    fi
fi

# ── run each binary ──────────────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0

for t in $TESTS; do
    echo "----------------------------------------"
    echo "Running: $t"
    echo "----------------------------------------"
    if [ ! -x "./$t" ]; then
        printf "%b[SKIP]%b %s – binary not found\n" "$YELLOW" "$NC" "$t"
        SKIP=$((SKIP + 1))
        echo ""
        continue
    fi
    if "./$t"; then
        printf "%b[PASSED]%b %s\n" "$GREEN" "$NC" "$t"
        PASS=$((PASS + 1))
    else
        printf "%b[FAILED]%b %s\n" "$RED" "$NC" "$t"
        FAIL=$((FAIL + 1))
    fi
    echo ""
done

# ── summary ──────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL + SKIP))
echo "========================================"
printf " Results: %d/%d test binaries passed" "$PASS" "$TOTAL"
[ "$SKIP" -gt 0 ] && printf " (%d skipped)" "$SKIP"
echo ""
if [ "$FAIL" -gt 0 ]; then
    printf "%b %d test(s) FAILED%b\n" "$RED" "$FAIL" "$NC"
    echo "========================================"
    exit 1
else
    printf "%b All tests passed!%b\n" "$GREEN" "$NC"
    echo "========================================"
    exit 0
fi
