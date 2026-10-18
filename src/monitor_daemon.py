#!/usr/bin/env python3
"""
RoCEv2 eBPF/XDP Telemetry Monitor Daemon
Control plane engine for real-time AI cluster network bottleneck detection.

This daemon:
1. Dynamically compiles src/xdp_roce_core.c using the BCC framework.
2. Attaches the eBPF program to the target interface at the XDP driver level,
   with automatic fallback to generic SKB mode if driver mode is unsupported.
3. Periodically queries the BPF_HASH (roce_flow_map) and BPF_ARRAY (roce_global_stats)
   shared memory maps to extract per-flow telemetry without kernel copy overhead.
4. Calculates real-time differentials (PPS, Bandwidth Gbps) across sampling windows.
5. Traps termination signals (SIGINT, SIGTERM) to cleanly detach the XDP hook,
   preventing dangling hooks and kernel interface lockouts.
6. Provides an offline '--demo' mode to test and validate UI formatting without kernel root.
"""

import argparse
import os
import random
import signal
import socket
import sys
import time
from typing import Dict, Tuple

try:
    from bcc import BPF
    HAS_BCC = True
except ImportError:
    HAS_BCC = False

# ANSI terminal escape sequences for clean dashboard rendering
ANSI_CLEAR = "\033[2J\033[H"
ANSI_BOLD = "\033[1m"
ANSI_CYAN = "\033[36m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_RED = "\033[31m"
ANSI_RESET = "\033[0m"


def format_bytes(num_bytes: int) -> str:
    """Format byte integers into human-readable binary units."""
    n = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(n) < 1024.0:
            return f"{n:6.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"


def format_bandwidth(bits_per_sec: float) -> str:
    """Format bandwidth into human-readable network transfer rates."""
    b = float(bits_per_sec)
    for unit in ["bps", "Kbps", "Mbps", "Gbps", "Tbps"]:
        if abs(b) < 1000.0:
            return f"{b:6.2f} {unit}"
        b /= 1000.0
    return f"{b:.2f} Pbps"


def format_pps(pps: float) -> str:
    """Format packet rates into clean metric notations."""
    p = float(pps)
    if p < 1000.0:
        return f"{p:6.1f} pps"
    elif p < 1000000.0:
        return f"{p / 1000.0:6.2f} Kpps"
    else:
        return f"{p / 1000000.0:6.2f} Mpps"


def ipv4_to_str(ip_int: int) -> str:
    """Convert raw 32-bit network-endian integer to standard dotted-decimal IP."""
    return socket.inet_ntoa(int(ip_int).to_bytes(4, byteorder="little"))


class RoCETelemetryDaemon:
    """User-space control plane managing the XDP lifecycle and telemetry extraction."""

    def __init__(
        self,
        interface: str,
        interval: float,
        mode: str = "auto",
        log_stream: bool = False,
        demo_mode: bool = False,
        demo_ticks: int = 0,
    ):
        self.interface = interface
        self.interval = max(interval, 0.1)
        self.mode = mode
        self.log_stream = log_stream
        self.demo_mode = demo_mode
        self.demo_ticks = demo_ticks

        self.bpf = None
        self.attached_flags: int = 0
        self.is_attached: bool = False
        self.running: bool = True

        # Cache previous snapshot for rate calculation: (src_ip, dst_ip, src_port, dst_port) -> (packets, bytes, timestamp)
        self.prev_flow_stats: Dict[Tuple[str, str, int, int], Tuple[int, int, float]] = {}
        self.prev_total_roce_pkts = 0
        self.prev_total_roce_bytes = 0
        self.prev_global_time = 0.0

        if not self.demo_mode:
            self._resolve_source_path()
        self._register_signal_handlers()

    def _resolve_source_path(self):
        """Locate the C kernel-space eBPF program."""
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.c_source_file = os.path.join(base_dir, "xdp_roce_core.c")
        if not os.path.isfile(self.c_source_file):
            raise FileNotFoundError(f"eBPF source file not found at: {self.c_source_file}")

    def _register_signal_handlers(self):
        """Trap system termination signals to ensure guaranteed teardown."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Flag the daemon for clean shutdown upon receiving termination signal."""
        sig_name = "SIGINT" if signum == signal.SIGINT else "SIGTERM"
        sys.stderr.write(f"\n[INFO] {sig_name} received. Initiating graceful detachment...\n")
        self.running = False

    def compile_and_attach(self):
        """Compile C source to BPF bytecode and attach to network interface."""
        if not HAS_BCC:
            sys.exit(
                f"{ANSI_RED}[FATAL] BCC (BPF Compiler Collection) Python module not found.{ANSI_RESET}\n"
                "Please install BCC packages on your host:\n"
                "  - Fedora/RHEL: sudo dnf install -y python3-bcc bcc-tools kernel-devel\n"
                "  - Ubuntu/Debian: sudo apt-get install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)\n"
                "To test the telemetry dashboard without kernel root, run with: --demo"
            )

        print(f"[INFO] Compiling eBPF kernel program: {self.c_source_file}...")
        self.bpf = BPF(src_file=self.c_source_file, cflags=["-w"])

        fn = self.bpf.load_func("xdp_roce_filter", BPF.XDP)

        # Determine attachment strategy based on requested mode
        modes_to_try = []
        if self.mode == "drv":
            modes_to_try.append(("Driver/Native XDP", BPF.XDP_FLAGS_DRV_MODE))
        elif self.mode == "skb":
            modes_to_try.append(("Generic/SKB XDP", BPF.XDP_FLAGS_SKB_MODE))
        else:  # auto
            modes_to_try.append(("Driver/Native XDP", BPF.XDP_FLAGS_DRV_MODE))
            modes_to_try.append(("Generic/SKB XDP (Fallback)", BPF.XDP_FLAGS_SKB_MODE))

        attached = False
        last_error = None

        for mode_desc, flags in modes_to_try:
            try:
                print(f"[INFO] Attempting to attach XDP hook in {mode_desc} mode on {self.interface}...")
                self.bpf.attach_xdp(self.interface, fn, flags)
                self.attached_flags = flags
                self.is_attached = True
                attached = True
                print(f"{ANSI_GREEN}[SUCCESS] Attached XDP telemetry hook in {mode_desc} mode.{ANSI_RESET}")
                break
            except Exception as e:
                last_error = e
                print(f"[WARN] Failed to attach in {mode_desc} mode: {e}")

        if not attached:
            raise RuntimeError(
                f"Failed to attach XDP program to {self.interface} across all attempted modes. "
                f"Root cause: {last_error}"
            )

    def detach(self):
        """Safely detach the XDP program from the network interface."""
        if self.bpf and self.is_attached:
            try:
                print(f"[INFO] Detaching XDP hook from {self.interface}...")
                self.bpf.remove_xdp(self.interface, self.attached_flags)
                self.is_attached = False
                print(f"{ANSI_GREEN}[SUCCESS] XDP hook detached cleanly. Kernel state restored.{ANSI_RESET}")
            except Exception as e:
                sys.stderr.write(f"[ERROR] Exception during XDP hook detachment: {e}\n")

    def run_demo(self):
        """Run simulated telemetry loop to validate dashboard rendering and rate calculation."""
        print(f"{ANSI_CYAN}[DEMO MODE] Running synthetic AI fabric telemetry dashboard...{ANSI_RESET}")
        print("Simulating 4 concurrent RoCEv2 GPU Queue Pairs on UDP Port 4791.\n")

        demo_flows = [
            ("192.168.100.1", "192.168.100.2", 51000, 4791),
            ("192.168.100.1", "192.168.100.2", 51001, 4791),
            ("192.168.100.1", "192.168.100.2", 51002, 4791),
            ("192.168.100.1", "192.168.100.2", 51003, 4791),
        ]

        flow_accum = {f: [0, 0] for f in demo_flows}
        total_roce_pkts = 0
        total_roce_bytes = 0
        total_non_roce_pkts = 142
        ticks = 0

        self.prev_global_time = time.time()

        try:
            while self.running:
                time.sleep(self.interval)
                now = time.time()
                time_delta = max(now - self.prev_global_time, 0.0001)

                current_flow_entries = []
                for f in demo_flows:
                    # Simulate realistic GPU All-Reduce traffic: ~45,000 pps per flow
                    pkts_inc = random.randint(40000, 50000)
                    bytes_inc = pkts_inc * 1024

                    flow_accum[f][0] += pkts_inc
                    flow_accum[f][1] += bytes_inc
                    total_roce_pkts += pkts_inc
                    total_roce_bytes += bytes_inc

                    src_str = f"{f[0]}:{f[2]}"
                    dst_str = f"{f[1]}:{f[3]}"
                    f_pps = pkts_inc / time_delta
                    f_bps = (bytes_inc * 8) / time_delta

                    current_flow_entries.append({
                        "src": src_str,
                        "dst": dst_str,
                        "pkts": flow_accum[f][0],
                        "bytes": flow_accum[f][1],
                        "pps": f_pps,
                        "bps": f_bps,
                        "last_seen_ns": int(now * 1e9),
                    })

                delta_roce_pkts = total_roce_pkts - self.prev_total_roce_pkts
                delta_roce_bytes = total_roce_bytes - self.prev_total_roce_bytes
                agg_pps = delta_roce_pkts / time_delta
                agg_bandwidth_bps = (delta_roce_bytes * 8) / time_delta

                self.prev_total_roce_pkts = total_roce_pkts
                self.prev_total_roce_bytes = total_roce_bytes
                self.prev_global_time = now

                self._render_dashboard(
                    now=now,
                    time_delta=time_delta,
                    flows=current_flow_entries,
                    total_roce_pkts=total_roce_pkts,
                    total_roce_bytes=total_roce_bytes,
                    total_non_roce_pkts=total_non_roce_pkts,
                    agg_pps=agg_pps,
                    agg_bandwidth_bps=agg_bandwidth_bps,
                )

                ticks += 1
                if self.demo_ticks > 0 and ticks >= self.demo_ticks:
                    break

        except KeyboardInterrupt:
            print("\n[INFO] Demo stopped by user.")

    def run(self):
        """Main telemetry collection loop."""
        if self.demo_mode:
            self.run_demo()
            return

        self.compile_and_attach()

        roce_flow_map = self.bpf["roce_flow_map"]
        roce_global_stats = self.bpf["roce_global_stats"]

        print(f"[INFO] Telemetry engine active on {self.interface} (UDP Port 4791).")
        print(f"[INFO] Polling interval: {self.interval}s. Press Ctrl+C to stop.\n")

        self.prev_global_time = time.time()

        try:
            while self.running:
                time.sleep(self.interval)
                now = time.time()
                time_delta = max(now - self.prev_global_time, 0.0001)

                # Query global aggregate counters
                total_roce_pkts = 0
                total_roce_bytes = 0
                total_non_roce_pkts = 0

                try:
                    global_entry = roce_global_stats[0]
                    total_roce_pkts = int(global_entry.total_roce_packets)
                    total_roce_bytes = int(global_entry.total_roce_bytes)
                    total_non_roce_pkts = int(global_entry.total_non_roce_packets)
                except Exception:
                    pass

                delta_roce_pkts = max(total_roce_pkts - self.prev_total_roce_pkts, 0)
                delta_roce_bytes = max(total_roce_bytes - self.prev_total_roce_bytes, 0)
                agg_pps = delta_roce_pkts / time_delta
                agg_bandwidth_bps = (delta_roce_bytes * 8) / time_delta

                # Query per-flow telemetry
                current_flow_entries = []
                for k, v in roce_flow_map.items():
                    src_ip = ipv4_to_str(k.src_ip)
                    dst_ip = ipv4_to_str(k.dst_ip)
                    src_port = int(k.src_port)
                    dst_port = int(k.dst_port)
                    pkts = int(v.packet_count)
                    nbytes = int(v.byte_count)
                    last_ts_ns = int(v.last_timestamp_ns)

                    flow_tuple = (src_ip, dst_ip, src_port, dst_port)
                    prev = self.prev_flow_stats.get(flow_tuple)

                    if prev:
                        prev_pkts, prev_nbytes, prev_time = prev
                        f_dt = max(now - prev_time, 0.0001)
                        f_delta_pkts = max(pkts - prev_pkts, 0)
                        f_delta_bytes = max(nbytes - prev_nbytes, 0)
                        f_pps = f_delta_pkts / f_dt
                        f_bps = (f_delta_bytes * 8) / f_dt
                    else:
                        f_pps = pkts / time_delta
                        f_bps = (nbytes * 8) / time_delta

                    self.prev_flow_stats[flow_tuple] = (pkts, nbytes, now)

                    current_flow_entries.append({
                        "src": f"{src_ip}:{src_port}",
                        "dst": f"{dst_ip}:{dst_port}",
                        "pkts": pkts,
                        "bytes": nbytes,
                        "pps": f_pps,
                        "bps": f_bps,
                        "last_seen_ns": last_ts_ns,
                    })

                self.prev_total_roce_pkts = total_roce_pkts
                self.prev_total_roce_bytes = total_roce_bytes
                self.prev_global_time = now

                self._render_dashboard(
                    now=now,
                    time_delta=time_delta,
                    flows=current_flow_entries,
                    total_roce_pkts=total_roce_pkts,
                    total_roce_bytes=total_roce_bytes,
                    total_non_roce_pkts=total_non_roce_pkts,
                    agg_pps=agg_pps,
                    agg_bandwidth_bps=agg_bandwidth_bps,
                )

        finally:
            self.detach()

    def _render_dashboard(
        self,
        now: float,
        time_delta: float,
        flows: list,
        total_roce_pkts: int,
        total_roce_bytes: int,
        total_non_roce_pkts: int,
        agg_pps: float,
        agg_bandwidth_bps: float,
    ):
        """Format and print real-time telemetry metrics to stdout."""
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

        output_lines = []
        if not self.log_stream:
            output_lines.append(ANSI_CLEAR)

        output_lines.append(f"{ANSI_BOLD}{ANSI_CYAN}========================================================================================={ANSI_RESET}")
        output_lines.append(f"{ANSI_BOLD} AI CLUSTER FABRIC TELEMETRY AGENT (eBPF / XDP LINE-RATE MONITOR) {ANSI_RESET}")
        output_lines.append(f" Interface: {ANSI_YELLOW}{self.interface}{ANSI_RESET} | Sampling Window: {self.interval:.1f}s | Timestamp: {timestamp_str}")
        output_lines.append(f"{ANSI_BOLD}{ANSI_CYAN}========================================================================================={ANSI_RESET}")

        # Summary line
        output_lines.append(
            f" {ANSI_BOLD}Aggregate RoCEv2 Throughput:{ANSI_RESET} {ANSI_GREEN}{format_bandwidth(agg_bandwidth_bps)}{ANSI_RESET}  |  "
            f"{ANSI_BOLD}Packet Rate:{ANSI_RESET} {ANSI_GREEN}{format_pps(agg_pps)}{ANSI_RESET}  |  "
            f"{ANSI_BOLD}Active Flows:{ANSI_RESET} {len(flows)}"
        )
        output_lines.append(
            f" Cumulative RoCEv2: {total_roce_pkts:,} packets ({format_bytes(total_roce_bytes)})  |  "
            f"Non-RoCEv2 Ignored: {total_non_roce_pkts:,} packets"
        )
        output_lines.append("-----------------------------------------------------------------------------------------")

        # Table header
        header = f"{'SOURCE (IP:PORT)':<23} {'DESTINATION (IP:PORT)':<23} {'PACKETS':>10} {'BYTES':>12} {'RATE (PPS)':>12} {'THROUGHPUT':>13}"
        output_lines.append(f"{ANSI_BOLD}{header}{ANSI_RESET}")
        output_lines.append("-----------------------------------------------------------------------------------------")

        if not flows:
            output_lines.append(" (No active RoCEv2 flows detected on destination port 4791)")
        else:
            # Sort flows by highest bandwidth
            flows.sort(key=lambda x: x["bps"], reverse=True)
            for f in flows:
                row = (
                    f"{f['src']:<23} "
                    f"{f['dst']:<23} "
                    f"{f['pkts']:>10,d} "
                    f"{format_bytes(f['bytes']):>12} "
                    f"{format_pps(f['pps']):>12} "
                    f"{format_bandwidth(f['bps']):>13}"
                )
                output_lines.append(row)

        output_lines.append("-----------------------------------------------------------------------------------------")
        output_lines.append(f"{ANSI_CYAN}Status: Monitoring active. Press Ctrl+C to terminate cleanly.{ANSI_RESET}\n")

        sys.stdout.write("\n".join(output_lines) + "\n")
        sys.stdout.flush()


def parse_arguments() -> argparse.Namespace:
    """Parse command line flags."""
    parser = argparse.ArgumentParser(
        description="RoCEv2 Line-Rate Telemetry Monitor Daemon using eBPF/XDP."
    )
    parser.add_argument(
        "-i", "--iface",
        type=str,
        default="veth-rx",
        help="Target network interface name to attach XDP hook (default: veth-rx)."
    )
    parser.add_argument(
        "-t", "--interval",
        type=float,
        default=1.0,
        help="Polling interval in seconds (default: 1.0s)."
    )
    parser.add_argument(
        "-m", "--mode",
        type=str,
        choices=["auto", "drv", "skb"],
        default="auto",
        help="XDP attachment mode: 'auto' (try driver then fallback to skb), 'drv' (native driver only), 'skb' (generic only)."
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        default=False,
        help="Append output as a continuous stream instead of refreshing the terminal screen."
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        default=False,
        help="Run in offline synthetic demo mode to preview dashboard without kernel root/BCC."
    )
    parser.add_argument(
        "--demo-ticks",
        type=int,
        default=0,
        help="Exit demo mode after N ticks (0 = run indefinitely, default: 0)."
    )
    return parser.parse_args()


def main():
    """Entry point for the telemetry daemon."""
    args = parse_arguments()

    # If not in demo mode, enforce root/CAP_BPF privileges
    if not args.demo and os.geteuid() != 0:
        sys.exit(
            f"{ANSI_RED}[FATAL] Root privileges required to load eBPF/XDP programs.{ANSI_RESET}\n"
            f"Please run with: sudo python3 {sys.argv[0]} -i {args.iface}\n"
            f"Or test the UI and rate calculations with: python3 {sys.argv[0]} --demo"
        )

    daemon = RoCETelemetryDaemon(
        interface=args.iface,
        interval=args.interval,
        mode=args.mode,
        log_stream=args.stream,
        demo_mode=args.demo,
        demo_ticks=args.demo_ticks,
    )
    daemon.run()


if __name__ == "__main__":
    main()
