#!/usr/bin/env bash
#
# setup_testbed.sh: Provision isolated Linux Network Testbed for RoCEv2 AI Telemetry Emulation
#
# Creates an isolated network namespace (sim-ai-sender) representing a distributed GPU node,
# linked via a virtual Ethernet pair (veth-tx <---> veth-rx) configured with 9000 MTU Jumbo Frames.
#

set -euo pipefail

NS_NAME="sim-ai-sender"
VETH_TX="veth-tx"
VETH_RX="veth-rx"
TX_IP="192.168.100.1/24"
RX_IP="192.168.100.2/24"
MTU_SIZE=9000

# Color formatting
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be executed with root privileges."
        echo "Please re-run using: sudo $0 $@"
        exit 1
    fi
}

teardown_testbed() {
    log_info "Initiating testbed teardown..."

    # Delete veth pair if exists (deleting one endpoint automatically deletes the pair)
    if ip link show "${VETH_RX}" >/dev/null 2>&1; then
        ip link delete "${VETH_RX}" 2>/dev/null || true
        log_info "Deleted interface ${VETH_RX}."
    fi

    # Delete sender network namespace if exists
    if ip netns list | grep -q "${NS_NAME}"; then
        ip netns delete "${NS_NAME}" 2>/dev/null || true
        log_info "Deleted network namespace ${NS_NAME}."
    fi

    log_success "Testbed cleaned up successfully."
}

setup_testbed() {
    log_info "Provisioning AI Cluster RoCEv2 Testbed..."

    # Teardown any existing stale artifacts
    teardown_testbed >/dev/null 2>&1 || true

    # 1. Create isolated network namespace for the simulated GPU sender
    log_info "Creating network namespace '${NS_NAME}'..."
    ip netns add "${NS_NAME}"

    # 2. Provision virtual Ethernet pair
    log_info "Creating veth pair: ${VETH_TX} <---> ${VETH_RX}..."
    ip link add "${VETH_TX}" type veth peer name "${VETH_RX}"

    # 3. Migrate TX interface into sender namespace
    log_info "Moving interface ${VETH_TX} into namespace '${NS_NAME}'..."
    ip link set "${VETH_TX}" netns "${NS_NAME}"

    # 4. Configure MTU to 9000 (Jumbo Frames standard in RoCEv2 AI Fabrics)
    log_info "Configuring MTU ${MTU_SIZE} (AI Fabric Jumbo Frames)..."
    ip netns exec "${NS_NAME}" ip link set dev "${VETH_TX}" mtu "${MTU_SIZE}"
    ip link set dev "${VETH_RX}" mtu "${MTU_SIZE}"

    # 5. Assign static IP addresses
    log_info "Assigning IP ${TX_IP} to ${VETH_TX} and ${RX_IP} to ${VETH_RX}..."
    ip netns exec "${NS_NAME}" ip addr add "${TX_IP}" dev "${VETH_TX}"
    ip addr add "${RX_IP}" dev "${VETH_RX}"

    # 6. Bring up loopback and interfaces
    log_info "Bringing interfaces UP..."
    ip netns exec "${NS_NAME}" ip link set lo up
    ip netns exec "${NS_NAME}" ip link set dev "${VETH_TX}" up
    ip link set dev "${VETH_RX}" up

    # 7. Disable offloads on receiver interface for predictable XDP packet inspection
    log_info "Disabling hardware offload bottlenecks on ${VETH_RX} (GRO, LRO, TSO, GSO)..."
    if command -v ethtool >/dev/null 2>&1; then
        ethtool -K "${VETH_RX}" rx off tx off tso off gso off gro off lro off >/dev/null 2>&1 || true
    fi

    # 8. Verify end-to-end loopback ping connectivity
    log_info "Validating connectivity with ICMP probe..."
    if ip netns exec "${NS_NAME}" ping -c 2 -W 1 192.168.100.2 >/dev/null 2>&1; then
        log_success "ICMP probe verified: ${TX_IP} can reach ${RX_IP} across ${VETH_RX}."
    else
        log_warn "ICMP probe failed or timed out. Check routing configuration."
    fi

    echo ""
    log_success "=========================================================="
    log_success " AI Cluster Emulation Testbed Successfully Provisioned!  "
    log_success "=========================================================="
    echo "  - Sender Node:    Namespace '${NS_NAME}' (IP: 192.168.100.1, dev: ${VETH_TX})"
    echo "  - Receiver Node:  Default Host        (IP: 192.168.100.2, dev: ${VETH_RX})"
    echo "  - Link MTU:       ${MTU_SIZE} (Jumbo Frames)"
    echo "  - Target Port:    UDP 4791 (RoCEv2 standard)"
    echo ""
    echo "NEXT STEPS TO RUN:"
    echo "  1. Terminal 1 (Start Telemetry Monitor):"
    echo "     sudo python3 src/monitor_daemon.py -i ${VETH_RX}"
    echo ""
    echo "  2. Terminal 2 (Inject Simulated GPU RoCEv2 Traffic):"
    echo "     sudo ip netns exec ${NS_NAME} python3 tests/traffic_simulator.py --target 192.168.100.2 --flows 4"
    echo ""
}

show_status() {
    echo "=== AI TESTBED STATUS ==="
    echo "Network Namespaces:"
    ip netns list || true
    echo ""
    echo "Receiver Interface (${VETH_RX}):"
    ip addr show "${VETH_RX}" 2>/dev/null || echo "Not configured"
    echo ""
    echo "Sender Interface in ${NS_NAME} (${VETH_TX}):"
    ip netns exec "${NS_NAME}" ip addr show "${VETH_TX}" 2>/dev/null || echo "Namespace or interface not found"
}

# Entrypoint argument parsing
check_root

ACTION="${1:-setup}"

case "${ACTION}" in
    setup)
        setup_testbed
        ;;
    teardown|clean|delete)
        teardown_testbed
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 {setup|teardown|status}"
        exit 1
        ;;
esac
