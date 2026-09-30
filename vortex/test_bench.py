"""
Synthetic Attack Simulator for VORTEX Shield.
Generates concurrent flood bursts, scans, and simulated TLS ClientHellos.
"""
import asyncio
import socket
import time
from rich.console import Console

console = Console()

# Sample raw TLS 1.3 ClientHello bytes
RAW_TLS_CLIENT_HELLO = (
    b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03"
    b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99"
    b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
    b"\x00\x00\x04\x13\x01\x13\x02\x01\x00\x00\x74\x00\x00\x00\x10\x00"
    b"\x0e\x00\x00\x0b\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x00"
    b"\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01"
    b"\x00\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f"
    b"\x31\x2e\x31"
)

async def send_single_req(port: int, req_type: str = "http") -> str:
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        if req_type == "tls":
            writer.write(RAW_TLS_CLIENT_HELLO)
        else:
            writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: BenchmarkBot/1.0\r\n\r\n")
        await writer.drain()

        # Try reading response
        try:
            resp = await asyncio.wait_for(reader.read(512), timeout=1.0)
            status = resp.split(b"\r\n")[0].decode("latin1", errors="ignore")
        except Exception:
            status = "Dropped / Closed"

        writer.close()
        await writer.wait_closed()
        return status
    except Exception as e:
        return f"Conn Refused / Banned ({e})"

async def run_synthetic_flood(port: int = 8080, concurrency: int = 50, total: int = 500):
    console.print(f"\n[bold red]⚡ Launching synthetic attack on port {port}...[/bold red]")
    console.print(f"• Total Requests: {total} | Concurrency: {concurrency}\n")

    t0 = time.time()
    results = {}

    sem = asyncio.Semaphore(concurrency)

    async def worker(i):
        async with sem:
            req_type = "tls" if i % 4 == 0 else "http"
            st = await send_single_req(port, req_type)
            results[st] = results.get(st, 0) + 1

    tasks = [worker(i) for i in range(total)]
    await asyncio.gather(*tasks)

    elapsed = time.time() - t0
    rps = total / max(elapsed, 0.001)

    console.print(f"[bold green]✔ Attack Simulation Complete in {elapsed:.2f}s ({rps:.0f} req/s)[/bold green]\n")
    console.print("[bold cyan]Distribution of Responses:[/bold cyan]")
    for st, count in results.items():
        pct = (count / total) * 100
        console.print(f"  • {st}: [bold]{count}[/] ({pct:.1f}%)")
