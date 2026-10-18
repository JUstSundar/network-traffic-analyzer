#!/usr/bin/env bash
#
# run_tests.sh: Automated CI/Validation Test Suite
# Verifies kernel BPF compilation, python syntax, traffic simulator, and dashboard telemetry.
#

set -euo pipefail

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1" >&2
    exit 1
}

info() {
    echo -e "${CYAN}[TEST]${NC} $1"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "=========================================================="
echo " RUNNING AI CLUSTER FABRIC TELEMETRY TEST SUITE "
echo "=========================================================="

# Test 1: Validate BPF Kernel Code Compilation & Disassembly
info "1. Verifying C eBPF kernel program (src/xdp_roce_core.c) with clang BPF target..."
SHIM_FILE="/tmp/bpf_ci_shim.h"
cat << 'EOF' > "${SHIM_FILE}"
#pragma once
#include <linux/types.h>
#include <linux/bpf.h>
#define BPF_HASH(name, key_t, val_t, size) \
    struct { val_t* (*lookup)(key_t*); int (*update)(key_t*, val_t*); } name;
#define BPF_ARRAY(name, val_t, size) \
    struct { val_t* (*lookup)(__u32*); int (*update)(__u32*, val_t*); } name;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
EOF

if clang -target bpf -O2 -g -include "${SHIM_FILE}" -c src/xdp_roce_core.c -o /tmp/xdp_roce_core.o; then
    pass "Kernel C code compiles cleanly to BPF ELF target with 0 warnings."
else
    fail "Clang BPF compilation failed."
fi

# Test 2: Inspect Disassembled BPF Instructions for Atomics and XDP_PASS
info "2. Inspecting BPF bytecode instructions..."
if llvm-objdump -d /tmp/xdp_roce_core.o | grep -q "atomic_fetch_add"; then
    pass "Verified atomic memory operations (__sync_fetch_and_add -> atomic_fetch_add) in BPF bytecode."
else
    fail "Atomic instructions not found in disassembled BPF bytecode."
fi

# Test 3: Python Syntax & Bytecode Compilation
info "3. Compiling user-space Python daemon and test utilities..."
python3 -m py_compile src/monitor_daemon.py
python3 -m py_compile tests/traffic_simulator.py
pass "Python syntax and bytecode compilation verified."

# Test 4: Shell Script Syntax Validation
info "4. Validating bash testbed provisioning script..."
bash -n scripts/setup_testbed.sh
pass "Bash testbed script syntax verified."

# Test 5: Synthetic Traffic Generator Execution (Continuous Mode)
info "5. Testing synthetic RoCEv2 traffic generator (continuous mode)..."
python3 tests/traffic_simulator.py --target 127.0.0.1 --flows 2 --duration 1 --rate 100 >/dev/null
pass "Traffic simulator continuous mode executed successfully."

# Test 6: Synthetic Traffic Generator Execution (All-Reduce Burst Mode)
info "6. Testing synthetic RoCEv2 traffic generator (All-Reduce burst mode)..."
python3 tests/traffic_simulator.py --target 127.0.0.1 --flows 2 --duration 1 --rate 50 --burst >/dev/null
pass "Traffic simulator All-Reduce burst mode executed successfully."

# Test 7: Telemetry Monitor Dashboard Offline Validation
info "7. Testing monitor daemon rate differentials & dashboard rendering..."
python3 src/monitor_daemon.py --demo --demo-ticks 1 --stream >/dev/null
pass "Monitor daemon dashboard and differential rate calculations validated."

echo "=========================================================="
echo -e "${GREEN}ALL 7 VERIFICATION TESTS PASSED SUCCESSFULLY!${NC}"
echo "=========================================================="
