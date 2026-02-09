#!/bin/bash
#
# run_tests.sh - Run test binaries through alt-rosetta and verify results
#
# Usage: ./tests/run_tests.sh [test_name]
# If test_name is given, only run that test. Otherwise run all tests.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ALT_ROSETTA="$PROJECT_DIR/build/alt-rosetta"
TEST_BIN_DIR="$PROJECT_DIR/build/tests"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

passed=0
failed=0
skipped=0

run_test() {
    local test_name="$1"
    local binary="$TEST_BIN_DIR/$test_name"
    local expected_file="$SCRIPT_DIR/expected/${test_name}.expected"

    if [ ! -f "$binary" ]; then
        echo -e "${YELLOW}SKIP${NC} $test_name (binary not found)"
        ((skipped++))
        return
    fi

    # Run through alt-rosetta, capture stdout and exit code
    local stdout
    local exit_code
    stdout=$("$ALT_ROSETTA" "$binary" 2>/dev/null) || true
    exit_code=$?

    # If we have an expected file, verify against it
    if [ -f "$expected_file" ]; then
        local exp_exit=""
        local exp_stdout=""

        while IFS='=' read -r key value; do
            case "$key" in
                exit_code) exp_exit="$value" ;;
                stdout)    exp_stdout="$value" ;;
            esac
        done < "$expected_file"

        local test_passed=true

        if [ -n "$exp_exit" ] && [ "$exit_code" != "$exp_exit" ]; then
            echo -e "${RED}FAIL${NC} $test_name: expected exit code $exp_exit, got $exit_code"
            test_passed=false
        fi

        if [ -n "$exp_stdout" ] && [ "$stdout" != "$exp_stdout" ]; then
            echo -e "${RED}FAIL${NC} $test_name: expected stdout '$exp_stdout', got '$stdout'"
            test_passed=false
        fi

        if $test_passed; then
            echo -e "${GREEN}PASS${NC} $test_name (exit=$exit_code)"
            ((passed++))
        else
            ((failed++))
        fi
    else
        # No expected file - just report the result
        if [ "$exit_code" -eq 0 ]; then
            echo -e "${GREEN}PASS${NC} $test_name (exit=$exit_code)"
            ((passed++))
        else
            echo -e "${RED}FAIL${NC} $test_name (exit=$exit_code)"
            ((failed++))
        fi
    fi
}

echo "=== Alternative Rosetta Test Suite ==="
echo "Translator: $ALT_ROSETTA"
echo ""

if [ ! -f "$ALT_ROSETTA" ]; then
    echo "Error: alt-rosetta binary not found. Run 'make && make sign' first."
    exit 1
fi

if [ -n "$1" ]; then
    # Run specific test
    run_test "$1"
else
    # Run all tests
    for binary in "$TEST_BIN_DIR"/test_*; do
        if [ -f "$binary" ]; then
            test_name=$(basename "$binary")
            run_test "$test_name"
        fi
    done
fi

echo ""
echo "=== Results ==="
echo -e "${GREEN}Passed: $passed${NC}"
echo -e "${RED}Failed: $failed${NC}"
echo -e "${YELLOW}Skipped: $skipped${NC}"

if [ "$failed" -gt 0 ]; then
    exit 1
fi
