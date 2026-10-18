#!/usr/bin/env python3
"""
Synthetic RoCEv2 Traffic Generator for AI Fabric Telemetry Validation
Simulates multi-flow GPU All-Reduce synchronization traffic over UDP Port 4791.

In high-performance AI clusters (e.g., PyTorch workloads over GPU fabrics using NCCL),
traffic consists of parallel flows operating across multiple Queue Pairs (QPs).
Spine-leaf datacenter switches use UDP source port entropy for Equal-Cost Multi-Path
(ECMP) load balancing.

This script generates:
1. Valid RoCEv2 BTH (Base Transport Header) encapsulated payloads targeting UDP port 4791.
2. Parallel multi-flow streams with unique source ports and QP numbers.
3. Realistic AI workload modes:
   - Continuous line-rate streaming
   - Burst pattern simulating alternating Forward/Backward Compute and All-Reduce collectives.
"""

import argparse
import os
import random
import socket
import struct
import sys
import threading
import time
from typing import List

# RoCEv2 Standard Protocol Constants
ROCE_V2_UDP_PORT = 4791
IB_OPCODE_RC_RDMA_WRITE_ONLY = 0x0A
IB_OPCODE_CNP = 0x81  # Congestion Notification Packet
IB_DEFAULT_PKEY = 0xFFFF

# ANSI Colors for terminal UI
ANSI_CYAN = "\033[36m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_BOLD = "\033[1m"
ANSI_RESET = "\033[0m"


def build_roce_bth(opcode: int, dest_qp: int, psn: int, pad_count: int = 0) -> bytes:
    """
    Construct a 12-byte InfiniBand Base Transport Header (BTH) for RoCEv2.
    
    Header Format (RFC / InfiniBand Architecture Specification):
    - Byte 0: Opcode (8 bits)
    - Byte 1: Solicited Event (1b) | MigReq (1b) | Pad Count (2b) | Transport Header Version (4b)
    - Bytes 2-3: Partition Key / P_Key (16 bits, Big-Endian)
    - Bytes 4-6: Reserved (8b) | Destination QP (24 bits, Big-Endian)
    - Byte 7: Acknowledge Request (1b) | Reserved (7b)
    - Bytes 8-10: Packet Sequence Number / PSN (24 bits, Big-Endian)
    """
    byte1 = (pad_count & 0x03) << 4  # Pad count in bits [5:4]
    bth_p1 = struct.pack("!BBH", opcode, byte1, IB_DEFAULT_PKEY)
    
    # 24-bit Destination QP
    qp_bytes = struct.pack("!I", dest_qp & 0x00FFFFFF)[1:]  # Take lower 3 bytes
    
    # Ack request bit (0x80) + 24-bit PSN
    ack_req = 0x80
    psn_bytes = struct.pack("!I", psn & 0x00FFFFFF)[1:]  # Take lower 3 bytes
    
    return bth_p1 + qp_bytes + bytes([ack_req]) + psn_bytes


class FlowWorker(threading.Thread):
    """Worker thread generating traffic for an individual simulated GPU Queue Pair."""

    def __init__(
        self,
        flow_id: int,
        target_ip: str,
        target_port: int,
        src_port: int,
        packet_size: int,
        rate_pps: int,
        stop_event: threading.Event,
        burst_mode: bool = False,
        burst_duration_ms: int = 100,
        idle_duration_ms: int = 200,
    ):
        super().__init__(name=f"Flow-{flow_id}")
        self.flow_id = flow_id
        self.target_ip = target_ip
        self.target_port = target_port
        self.src_port = src_port
        self.packet_size = max(packet_size, 64)
        self.rate_pps = rate_pps
        self.stop_event = stop_event
        self.burst_mode = burst_mode
        self.burst_duration_s = burst_duration_ms / 1000.0
        self.idle_duration_s = idle_duration_ms / 1000.0

        self.dest_qp = 0x1000 + flow_id
        self.psn = random.randint(1000, 50000)

        # Thread local counters
        self.packets_sent = 0
        self.bytes_sent = 0

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Bind to specific source port to establish consistent flow 4-tuple
            sock.bind(("", self.src_port))
        except OSError:
            # Fallback to ephemeral port if explicit port is busy
            pass

        # Precompute payload chunk (simulating float16 tensor weights)
        # Payload size = total requested size - 12 bytes (BTH) - 4 bytes (ICRC placeholder)
        raw_payload_len = max(self.packet_size - 16, 16)
        payload_data = os.urandom(raw_payload_len)
        icrc_placeholder = b"\xde\xad\xbe\xef"

        sleep_interval = 1.0 / self.rate_pps if self.rate_pps > 0 else 0.0

        try:
            while not self.stop_event.is_set():
                if self.burst_mode:
                    # Burst transmission phase (simulating All-Reduce synchronization)
                    burst_end = time.time() + self.burst_duration_s
                    while time.time() < burst_end and not self.stop_event.is_set():
                        bth = build_roce_bth(IB_OPCODE_RC_RDMA_WRITE_ONLY, self.dest_qp, self.psn)
                        packet = bth + payload_data + icrc_placeholder

                        sock.sendto(packet, (self.target_ip, self.target_port))
                        self.packets_sent += 1
                        self.bytes_sent += len(packet)
                        self.psn = (self.psn + 1) & 0x00FFFFFF

                        if sleep_interval > 0:
                            time.sleep(sleep_interval)

                    # Idle compute phase (simulating GPU forward/backward pass)
                    idle_end = time.time() + self.idle_duration_s
                    while time.time() < idle_end and not self.stop_event.is_set():
                        time.sleep(0.01)
                else:
                    # Continuous line-rate stream
                    bth = build_roce_bth(IB_OPCODE_RC_RDMA_WRITE_ONLY, self.dest_qp, self.psn)
                    packet = bth + payload_data + icrc_placeholder

                    sock.sendto(packet, (self.target_ip, self.target_port))
                    self.packets_sent += 1
                    self.bytes_sent += len(packet)
                    self.psn = (self.psn + 1) & 0x00FFFFFF

                    if sleep_interval > 0:
                        time.sleep(sleep_interval)
        finally:
            sock.close()


class RoCETrafficSimulator:
    """Multi-flow coordinator orchestrating parallel GPU traffic streams."""

    def __init__(
        self,
        target_ip: str,
        target_port: int,
        flows: int,
        packet_size: int,
        rate_pps: int,
        duration: int,
        base_src_port: int,
        burst_mode: bool,
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.flows = flows
        self.packet_size = packet_size
        self.rate_pps = rate_pps
        self.duration = duration
        self.base_src_port = base_src_port
        self.burst_mode = burst_mode
        self.stop_event = threading.Event()
        self.workers: List[FlowWorker] = []

    def run(self):
        print(f"{ANSI_BOLD}{ANSI_CYAN}========================================================================={ANSI_RESET}")
        print(f"{ANSI_BOLD} SYNTHETIC RoCEv2 AI FABRIC TRAFFIC GENERATOR (UDP PORT 4791) {ANSI_RESET}")
        print(f"{ANSI_BOLD}{ANSI_CYAN}========================================================================={ANSI_RESET}")
        print(f" Target Endpoint:   {ANSI_YELLOW}{self.target_ip}:{self.target_port}{ANSI_RESET}")
        print(f" Parallel Flows:    {ANSI_GREEN}{self.flows}{ANSI_RESET} (Simulating concurrent GPU Queue Pairs)")
        print(f" Packet Size:       {self.packet_size} bytes (RoCEv2 MTU)")
        print(f" Traffic Pattern:   {ANSI_YELLOW}{'All-Reduce Micro-Burst' if self.burst_mode else 'Continuous Stream'}{ANSI_RESET}")
        print(f" Rate per Flow:     {f'{self.rate_pps} pps' if self.rate_pps > 0 else 'Unthrottled (Max Line-Rate)'}")
        print(f" Duration:          {f'{self.duration}s' if self.duration > 0 else 'Continuous (Ctrl+C to stop)'}")
        print("-------------------------------------------------------------------------")

        # Spawn flow worker threads
        for i in range(self.flows):
            worker = FlowWorker(
                flow_id=i,
                target_ip=self.target_ip,
                target_port=self.target_port,
                src_port=self.base_src_port + i,
                packet_size=self.packet_size,
                rate_pps=self.rate_pps,
                stop_event=self.stop_event,
                burst_mode=self.burst_mode,
            )
            self.workers.append(worker)
            worker.start()

        start_time = time.time()
        prev_pkts = 0
        prev_bytes = 0
        prev_time = start_time

        try:
            while True:
                time.sleep(1.0)
                now = time.time()
                elapsed = now - start_time
                dt = max(now - prev_time, 0.0001)

                total_pkts = sum(w.packets_sent for w in self.workers)
                total_bytes = sum(w.bytes_sent for w in self.workers)

                delta_pkts = total_pkts - prev_pkts
                delta_bytes = total_bytes - prev_bytes

                current_pps = delta_pkts / dt
                current_mbps = (delta_bytes * 8) / (dt * 1_000_000)

                sys.stdout.write(
                    f"\r[{elapsed:5.1f}s] Sent: {total_pkts:,} pkts ({total_bytes / (1024*1024):,.2f} MB) | "
                    f"Rate: {current_pps:,.0f} pps | Throughput: {current_mbps:,.2f} Mbps  "
                )
                sys.stdout.flush()

                prev_pkts = total_pkts
                prev_bytes = total_bytes
                prev_time = now

                if self.duration > 0 and elapsed >= self.duration:
                    break

        except KeyboardInterrupt:
            print("\n[INFO] Traffic generation interrupted by user (Ctrl+C).")
        finally:
            self.stop_event.set()
            for w in self.workers:
                w.join()

        total_elapsed = max(time.time() - start_time, 0.0001)
        final_pkts = sum(w.packets_sent for w in self.workers)
        final_bytes = sum(w.bytes_sent for w in self.workers)
        avg_mbps = (final_bytes * 8) / (total_elapsed * 1_000_000)

        print("\n-------------------------------------------------------------------------")
        print(f"{ANSI_GREEN}[SUCCESS] Traffic generation complete.{ANSI_RESET}")
        print(f" Total Transmitted: {final_pkts:,} packets ({final_bytes / (1024*1024):,.2f} MB)")
        print(f" Total Time:        {total_elapsed:.2f} seconds")
        print(f" Average Bandwidth: {avg_mbps:,.2f} Mbps")
        print("-------------------------------------------------------------------------\n")


def parse_arguments() -> argparse.Namespace:
    """Parse simulator CLI options."""
    parser = argparse.ArgumentParser(
        description="Synthetic RoCEv2 Traffic Generator for AI Fabric Telemetry Testing."
    )
    parser.add_argument(
        "--target",
        type=str,
        default="192.168.100.2",
        help="Target IP address (default: 192.168.100.2)."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=ROCE_V2_UDP_PORT,
        help=f"Target UDP destination port (default: {ROCE_V2_UDP_PORT})."
    )
    parser.add_argument(
        "--flows",
        type=int,
        default=4,
        help="Number of concurrent parallel flows / Queue Pairs (default: 4)."
    )
    parser.add_argument(
        "--packet-size",
        type=int,
        default=1024,
        help="Frame payload size in bytes (default: 1024; up to 8900 for Jumbo Frames)."
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=0,
        help="Target packet rate per flow in PPS (0 = unthrottled burst, default: 0)."
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Total run duration in seconds (0 = run indefinitely, default: 10s)."
    )
    parser.add_argument(
        "--base-port",
        type=int,
        default=51000,
        help="Starting source UDP port for multi-flow hashing (default: 51000)."
    )
    parser.add_argument(
        "--burst",
        action="store_true",
        default=False,
        help="Enable All-Reduce micro-burst simulation pattern (alternating compute/communication)."
    )
    return parser.parse_args()


def main():
    """Main execution function."""
    args = parse_arguments()
    simulator = RoCETrafficSimulator(
        target_ip=args.target,
        target_port=args.port,
        flows=args.flows,
        packet_size=args.packet_size,
        rate_pps=args.rate,
        duration=args.duration,
        base_src_port=args.base_port,
        burst_mode=args.burst,
    )
    simulator.run()


if __name__ == "__main__":
    main()
