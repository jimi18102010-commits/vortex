"""
L4 XDP / eBPF Kernel Loader & Blacklist Manager for Project VORTEX.
Handles compiling, attaching/detaching XDP filters to network interfaces,
and managing the BPF blacklisted_ips map.
"""
import os
import subprocess
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

KERNEL_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../kernel/xdp_filter.c"))
KERNEL_OBJ = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../kernel/xdp_filter.o"))

class XDPShieldManager:
    def __init__(self, interface: str = "lo"):
        self.interface = interface
        self.attached = False
        self.mode = "none" # "xdp", "fallback", "simulation"
        self.local_blocked_ips: Dict[str, float] = {} # ip -> expire_time
        self.stats = {
            "rx_packets": 0,
            "rx_bytes": 0,
            "dropped_packets": 0,
            "passed_packets": 0,
        }

    def compile_ebpf(self) -> bool:
        """Compile the native C eBPF filter into BPF bytecode."""
        if not os.path.exists(KERNEL_SRC):
            return False
        
        cmd = [
            "clang", "-O2", "-g", "-target", "bpf",
            "-D__TARGET_ARCH_x86", "-I/usr/include",
            "-c", KERNEL_SRC, "-o", KERNEL_OBJ
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return os.path.exists(KERNEL_OBJ)
        except Exception as e:
            return False

    def is_root(self) -> bool:
        return os.geteuid() == 0

    def attach(self) -> bool:
        """Attempt to attach XDP filter to interface, fallback to userspace filter if unprivileged."""
        if not os.path.exists(KERNEL_OBJ):
            self.compile_ebpf()

        if self.is_root():
            try:
                # Attempt attaching generic XDP via ip link
                cmd = ["ip", "link", "set", "dev", self.interface, "xdpgeneric", "object", KERNEL_OBJ, "section", "xdp"]
                subprocess.run(cmd, capture_output=True, check=True)
                self.attached = True
                self.mode = "xdp_generic"
                return True
            except Exception:
                pass

        # Fallback to high-speed userspace L4 filter
        self.attached = True
        self.mode = "userspace_l4"
        return True

    def detach(self) -> bool:
        """Detach XDP filter from interface."""
        if self.mode.startswith("xdp") and self.is_root():
            try:
                cmd = ["ip", "link", "set", "dev", self.interface, "xdp", "off"]
                subprocess.run(cmd, capture_output=True, check=True)
            except Exception:
                pass
        self.attached = False
        self.mode = "none"
        return True

    def block_ip(self, ip_str: str, duration_sec: int = 300) -> bool:
        """Add IP to blacklist."""
        expire = time.time() + duration_sec
        self.local_blocked_ips[ip_str] = expire

        # If in kernel XDP mode and root, push to BPF map via bpftool
        if self.mode.startswith("xdp") and self.is_root():
            try:
                ip_packed = socket.inet_aton(ip_str)
                hex_key = " ".join(f"0x{b:02x}" for b in ip_packed)
                cmd = ["bpftool", "map", "update", "name", "blocked_ips", "key", "hex", *hex_key.split(), "value", "hex", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00"]
                subprocess.run(cmd, capture_output=True)
            except Exception:
                pass
        return True

    def is_ip_blocked(self, ip_str: str) -> bool:
        """Check if IP is currently blacklisted and unexpire if needed."""
        expire = self.local_blocked_ips.get(ip_str)
        if not expire:
            return False
        if time.time() > expire:
            del self.local_blocked_ips[ip_str]
            return False
        return True

    def record_drop(self, count: int = 1):
        self.stats["dropped_packets"] += count

    def record_pass(self, count: int = 1, byte_len: int = 0):
        self.stats["passed_packets"] += count
        self.stats["rx_packets"] += count
        self.stats["rx_bytes"] += byte_len

    def get_stats(self) -> dict:
        return {
            **self.stats,
            "blocked_count": len(self.local_blocked_ips),
            "mode": self.mode,
            "interface": self.interface
        }
