"""
Cyberpunk Terminal Radar TUI for Project VORTEX.
Renders real-time live telemetry, packet rates, TLS fingerprints, and security alerts.
"""
import time
from collections import deque
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

class VortexRadarTUI:
    def __init__(self, proxy_engine):
        self.proxy = proxy_engine
        self.console = Console()
        self.events_log = deque(maxlen=12)
        self.tls_log = deque(maxlen=8)
        self.start_time = time.time()
        self.last_pass = 0
        self.last_drop = 0
        self.last_time = time.time()
        self.current_pps = 0
        self.current_dps = 0

    def add_event(self, ev: dict):
        t_str = time.strftime("%H:%M:%S", time.localtime(ev.get("timestamp", time.time())))
        ev_type = ev.get("type", "info")

        if ev_type == "tls_handshake":
            self.tls_log.append({
                "time": t_str,
                "ip": ev.get("ip"),
                "tool": ev.get("tool"),
                "ja4": ev.get("ja4"),
                "risk": ev.get("risk", "NEUTRAL"),
                "score": ev.get("score", 0)
            })
        elif ev_type in ("blocked_request", "l4_escalation", "rate_limited"):
            self.events_log.append((t_str, "CRIT", f"[{ev.get('ip')}] {ev.get('reason', ev_type)}"))
        elif ev_type == "http_request":
            self.events_log.append((t_str, "INFO", f"[{ev.get('ip')}] {ev.get('line', '')}"))
        else:
            self.events_log.append((t_str, "SYS", str(ev)))

    def calculate_rates(self):
        now = time.time()
        dt = max(now - self.last_time, 0.001)
        stats = self.proxy.shield.get_stats()

        cur_pass = stats.get("passed_packets", 0)
        cur_drop = stats.get("dropped_packets", 0)

        self.current_pps = int((cur_pass - self.last_pass) / dt)
        self.current_dps = int((cur_drop - self.last_drop) / dt)

        self.last_pass = cur_pass
        self.last_drop = cur_drop
        self.last_time = now

    def generate_layout(self) -> Layout:
        self.calculate_rates()
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        layout["main"].split_row(
            Layout(name="telemetry", ratio=2),
            Layout(name="security", ratio=3)
        )

        # 1. Header
        uptime = int(time.time() - self.start_time)
        stats = self.proxy.shield.get_stats()
        header_text = Text()
        header_text.append("⚡ VORTEX SHIELD ", style="bold red")
        header_text.append(":: Edge Anycast L4/L7 Reverse-Proxy & Threat Radar\n", style="bold white")
        header_text.append(f"• Uptime: {uptime}s  ", style="dim")
        header_text.append(f"• Engine: {self.proxy.listen_host}:{self.proxy.listen_port} ➔ {self.proxy.upstream_host}:{self.proxy.upstream_port}  ", style="cyan")
        header_text.append(f"• L4 Mode: [{stats['mode'].upper()}] on [{stats['interface']}]", style="bold green" if "xdp" in stats['mode'] else "bold yellow")

        layout["header"].update(Panel(header_text, border_style="red"))

        # 2. Left: Telemetry Panel
        telemetry_table = Table.grid(padding=1)
        telemetry_table.add_column(style="bold cyan", width=18)
        telemetry_table.add_column(style="bold white")

        telemetry_table.add_row("Packets/Sec (PPS):", f"[bold green]{self.current_pps:,}[/]")
        telemetry_table.add_row("Drop Rate (DPS):", f"[bold red]{self.current_dps:,}[/]")
        telemetry_table.add_row("Total Forwarded:", f"{stats['passed_packets']:,} packets")
        telemetry_table.add_row("Total Wire Dropped:", f"[bold red]{stats['dropped_packets']:,}[/] packets")
        telemetry_table.add_row("Total Ingress:", f"{stats['rx_bytes'] / (1024*1024):.2f} MB")
        telemetry_table.add_row("Active Connections:", f"[bold yellow]{self.proxy.active_connections}[/]")
        telemetry_table.add_row("L4 Banned IPs:", f"[bold magenta]{stats['blocked_count']}[/]")

        # Logs sub-table
        log_table = Table(box=None, show_header=False, pad_edge=False)
        log_table.add_column(width=9, style="dim")
        log_table.add_column(width=6)
        log_table.add_column()
        for t_str, lvl, msg in list(self.events_log)[-5:]:
            style = "red" if lvl == "CRIT" else "green" if lvl == "INFO" else "yellow"
            log_table.add_row(t_str, f"[{style}]{lvl}[/]", msg)

        left_content = Layout()
        left_content.split_column(
            Layout(Panel(telemetry_table, title="[bold]Metrics & Wire Rates[/bold]", border_style="cyan"), ratio=1),
            Layout(Panel(log_table, title="[bold]Shield Events Log[/bold]", border_style="dim"), ratio=1)
        )
        layout["telemetry"].update(left_content)

        # 3. Right: Security & TLS JA4 Sniffer Table
        tls_table = Table(title="Live TLS ClientHello & JA4 Fingerprint Stream", border_style="red", expand=True)
        tls_table.add_column("Time", style="dim", width=8)
        tls_table.add_column("Client IP", style="cyan", width=15)
        tls_table.add_column("Identified Client / Tool", width=22)
        tls_table.add_column("JA4 Signature", style="dim", width=28)
        tls_table.add_column("Risk", justify="center", width=10)

        for item in self.tls_log:
            risk = item["risk"]
            r_style = "bold red" if risk == "MALICIOUS" else "yellow" if risk == "SUSPICIOUS" else "green"
            tls_table.add_row(
                item["time"],
                item["ip"],
                item["tool"],
                item["ja4"],
                f"[{r_style}]{risk}[/]"
            )

        layout["security"].update(tls_table)

        # 4. Footer
        footer_text = Text()
        footer_text.append("Press Ctrl+C to stop shield | Architecture: eBPF XDP Driver ➔ Zero-Copy Stream ➔ JA4 Telemetry", style="dim")
        layout["footer"].update(Panel(footer_text, border_style="dim"))

        return layout
