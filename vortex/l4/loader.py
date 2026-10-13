"""Optional XDP blacklist loader; unprivileged mode is explicitly userspace only."""
import json
import logging
import os
import platform
import socket
import struct
import subprocess
import sysconfig
import time
from pathlib import Path
from typing import Dict

log = logging.getLogger(__name__)
_REPO_SOURCE = Path(__file__).resolve().parents[2] / "kernel" / "xdp_filter.c"
_INSTALLED_SOURCE = Path(sysconfig.get_path("data")) / "share" / "vortex" / "kernel" / "xdp_filter.c"
KERNEL_SRC = str(_REPO_SOURCE if _REPO_SOURCE.is_file() else _INSTALLED_SOURCE)
KERNEL_OBJ = str(Path.home() / ".cache" / "vortex" / "xdp_filter.o")


class XDPShieldManager:
    def __init__(self, interface: str = "lo", max_blocked_ips: int = 65536):
        if max_blocked_ips <= 0:
            raise ValueError("max_blocked_ips must be positive")
        self.interface = interface
        self.attached = False
        self.mode = "none"
        self.max_blocked_ips = max_blocked_ips
        self.local_blocked_ips: Dict[str, float] = {}
        self.map_id = None
        self.stats = {"rx_packets": 0, "rx_bytes": 0, "dropped_packets": 0, "passed_packets": 0}

    def compile_ebpf(self) -> bool:
        if not os.path.isfile(KERNEL_SRC):
            log.warning("XDP source is unavailable; using userspace mode")
            return False
        arch = {"x86_64": "x86", "aarch64": "arm64"}.get(platform.machine())
        if arch is None:
            log.warning("Unsupported eBPF build architecture: %s", platform.machine())
            return False
        Path(KERNEL_OBJ).parent.mkdir(parents=True, exist_ok=True)
        cmd = ["clang", "-O2", "-g", "-target", "bpf", f"-D__TARGET_ARCH_{arch}", "-I/usr/include"]
        multiarch = sysconfig.get_config_var("MULTIARCH")
        if multiarch:
            cmd.append(f"-I/usr/include/{multiarch}")
        cmd.extend(["-c", KERNEL_SRC, "-o", KERNEL_OBJ])
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
            return os.path.isfile(KERNEL_OBJ)
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("eBPF compilation failed: %s", exc)
            return False

    def is_root(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def _resolve_map_id(self):
        """Resolve the map of OUR attached program, not a globally ambiguous map name."""
        link = json.loads(subprocess.check_output(
            ["ip", "-j", "-d", "link", "show", "dev", self.interface], timeout=10))[0]
        xdp = link.get("xdp", {})
        prog = xdp.get("prog", {})
        prog_id = prog.get("id") or xdp.get("prog_id")
        if not prog_id:
            attached = xdp.get("attached", [])
            if isinstance(attached, list):
                prog_id = next((p.get("prog", {}).get("id") or p.get("id") for p in attached if isinstance(p, dict)), None)
        if not prog_id:
            raise RuntimeError("Cannot identify the attached XDP program")
        program = json.loads(subprocess.check_output(["bpftool", "-j", "prog", "show", "id", str(prog_id)], timeout=10))
        if isinstance(program, list):
            program = program[0]
        for map_id in program.get("map_ids", []):
            info = json.loads(subprocess.check_output(["bpftool", "-j", "map", "show", "id", str(map_id)], timeout=10))
            if isinstance(info, list):
                info = info[0]
            if info.get("name") == "blocked_ips":
                self.map_id = map_id
                return
        raise RuntimeError("The attached program has no blocked_ips map")

    def attach(self) -> bool:
        # Always rebuild; never load the stale object previously committed to the repo.
        if self.is_root() and self.compile_ebpf():
            try:
                # Do not replace another program installed by the host administrator.
                link = json.loads(subprocess.check_output(["ip", "-j", "-d", "link", "show", "dev", self.interface], timeout=10))[0]
                if link.get("xdp"):
                    raise RuntimeError("An XDP program is already attached to this interface")
                subprocess.run(["ip", "link", "set", "dev", self.interface, "xdpgeneric", "object", KERNEL_OBJ, "section", "xdp"],
                               capture_output=True, check=True, timeout=10)
                self.attached, self.mode = True, "xdp_generic"
                self._resolve_map_id()
                return True
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                log.warning("XDP attachment/map discovery failed: %s", exc)
                if self.mode == "xdp_generic":
                    self.detach()
        self.attached, self.mode = True, "userspace_l4"
        self.map_id = None
        log.warning("Userspace-only filtering: no kernel-level or volumetric DDoS protection")
        return True

    def detach(self) -> bool:
        if self.mode.startswith("xdp") and self.is_root():
            try:
                subprocess.run(["ip", "link", "set", "dev", self.interface, "xdpgeneric", "off"],
                               capture_output=True, check=True, timeout=10)
            except (OSError, subprocess.SubprocessError) as exc:
                log.error("Failed to detach XDP: %s", exc)
                return False
        self.attached, self.mode, self.map_id = False, "none", None
        return True

    def _prune_expired(self):
        now = time.monotonic()
        for ip, expiry in list(self.local_blocked_ips.items()):
            if expiry <= now:
                self.local_blocked_ips.pop(ip, None)
                # The kernel also checks expiry on every packet, even before this cleanup.
                if self.mode.startswith("xdp") and self.map_id is not None:
                    try:
                        key = [f"{b:02x}" for b in socket.inet_aton(ip)]
                        subprocess.run(["bpftool", "map", "delete", "id", str(self.map_id), "key", "hex", *key],
                                       capture_output=True, timeout=10)
                    except (OSError, subprocess.SubprocessError):
                        log.warning("Could not remove expired kernel map entry for %s", ip)

    def block_ip(self, ip_str: str, duration_sec: int = 300) -> bool:
        if duration_sec <= 0:
            raise ValueError("duration_sec must be positive")
        self._prune_expired()
        if ip_str not in self.local_blocked_ips and len(self.local_blocked_ips) >= self.max_blocked_ips:
            return False
        self.local_blocked_ips[ip_str] = time.monotonic() + duration_sec
        if self.mode.startswith("xdp") and self.map_id is not None:
            try:
                key = [f"{b:02x}" for b in socket.inet_aton(ip_str)]
                # CLOCK_MONOTONIC matches bpf_ktime_get_ns. Pack in the target host's byte order.
                value = [f"{b:02x}" for b in struct.pack("=QQ", time.monotonic_ns() + int(duration_sec * 1_000_000_000), 0)]
                subprocess.run(["bpftool", "map", "update", "id", str(self.map_id), "key", "hex", *key, "value", "hex", *value],
                               capture_output=True, check=True, timeout=10)
            except (OSError, subprocess.SubprocessError) as exc:
                log.warning("Kernel ban failed for %s; userspace ban remains: %s", ip_str, exc)
                return False
        return True

    def is_ip_blocked(self, ip_str: str) -> bool:
        expiry = self.local_blocked_ips.get(ip_str)
        if expiry is None:
            return False
        if time.monotonic() >= expiry:
            self._prune_expired()
            return False
        return True

    def record_drop(self, count: int = 1):
        self.stats["dropped_packets"] += count

    def record_pass(self, count: int = 1, byte_len: int = 0):
        self.stats["passed_packets"] += count
        self.stats["rx_packets"] += count
        self.stats["rx_bytes"] += byte_len

    def get_stats(self) -> dict:
        self._prune_expired()
        return {**self.stats, "blocked_count": len(self.local_blocked_ips), "mode": self.mode,
                "interface": self.interface, "stats_source": "userspace_stream_events"}
