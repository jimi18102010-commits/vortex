"""
Main CLI Entrypoint for Project VORTEX.
"""
import argparse
import asyncio
import os
import sys
import time
from rich.live import Live
from rich.console import Console

from .l4.loader import XDPShieldManager
from .proxy.engine import VortexProxyEngine
from .ui.radar import VortexRadarTUI

console = Console()

async def run_shield_with_ui(listen_port: int, upstream_host: str, upstream_port: int, interface: str):
    shield = XDPShieldManager(interface=interface)
    shield.attach()

    tui_ref = None

    def on_event(ev):
        if tui_ref:
            tui_ref.add_event(ev)

    engine = VortexProxyEngine(
        listen_host="0.0.0.0",
        listen_port=listen_port,
        upstream_host=upstream_host,
        upstream_port=upstream_port,
        shield_manager=shield,
        on_event=on_event
    )

    tui = VortexRadarTUI(engine)
    tui_ref = tui

    await engine.start()

    with Live(tui.generate_layout(), refresh_per_second=4, screen=True) as live:
        try:
            while True:
                live.update(tui.generate_layout())
                await asyncio.sleep(0.25)
        except asyncio.CancelledError:
            pass
        finally:
            await engine.stop()
            shield.detach()

def main():
    parser = argparse.ArgumentParser(
        description="VORTEX: experimental TCP proxy, TLS telemetry & optional IPv4 XDP blacklist"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # 1. Run Command
    run_parser = subparsers.add_parser("run", help="Start the TCP proxy and TLS telemetry dashboard")
    run_parser.add_argument("-p", "--port", type=int, default=8080, help="Listen port (default: 8080)")
    run_parser.add_argument("-u", "--upstream", default="127.0.0.1:80", help="Upstream host:port (default: 127.0.0.1:80)")
    run_parser.add_argument("-i", "--interface", default="lo", help="Network interface for L4 XDP (default: lo)")

    # 2. Benchmark / Test Flood Command
    test_parser = subparsers.add_parser("test-attack", help="Run a loopback-only synthetic connection test")
    test_parser.add_argument("-p", "--port", type=int, default=8080, help="Target port (default: 8080)")
    test_parser.add_argument("-c", "--concurrency", type=int, default=50, help="Simultaneous connections")
    test_parser.add_argument("-n", "--requests", type=int, default=500, help="Total requests to fire")

    args = parser.parse_args()

    if not args.command or args.command == "run":
        port = getattr(args, "port", 8080)
        up_str = getattr(args, "upstream", "127.0.0.1:80")
        if ":" in up_str:
            up_host, up_p = up_str.split(":")
            up_port = int(up_p)
        else:
            up_host = up_str
            up_port = 80
        interface = getattr(args, "interface", "lo")

        try:
            asyncio.run(run_shield_with_ui(port, up_host, up_port, interface))
        except KeyboardInterrupt:
            console.print("\n[bold red]⚡ VORTEX Shield stopped gracefully.[/bold red]")

    elif args.command == "test-attack":
        from .test_bench import run_synthetic_flood
        asyncio.run(run_synthetic_flood(args.port, args.concurrency, args.requests))

if __name__ == "__main__":
    main()
