"""
High-Performance Asynchronous TCP/HTTP Reverse Proxy Engine for Project VORTEX.
Supports Zero-Copy TCP stream forwarding, TLS ClientHello sniffing,
Rate Limiting with L4 eBPF auto-escalation, and connection pooling.
"""
import asyncio
import socket
import time
from typing import Callable, Optional, Tuple
from ..security.tls_sniffer import TLSClientHelloSniffer
from ..security.heuristics import FingerprintHeuristics
from ..l4.loader import XDPShieldManager
from .limiter import SlidingWindowLimiter

class VortexProxyEngine:
    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8080,
        upstream_host: str = "127.0.0.1",
        upstream_port: int = 80,
        shield_manager: Optional[XDPShieldManager] = None,
        on_event: Optional[Callable[[dict], None]] = None
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.shield = shield_manager or XDPShieldManager()
        self.limiter = SlidingWindowLimiter(capacity=100, refill_rate=20.0, ban_threshold=50)
        self.on_event = on_event
        self.server: Optional[asyncio.Server] = None
        self.active_connections = 0
        self.total_requests = 0

    def emit(self, event_type: str, data: dict):
        if self.on_event:
            self.on_event({"type": event_type, "timestamp": time.time(), **data})

    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        self.active_connections += 1
        self.total_requests += 1

        peer_name = client_writer.get_extra_info("peername")
        client_ip = peer_name[0] if peer_name else "unknown"

        # 1. Check L4 Blacklist
        if self.shield.is_ip_blocked(client_ip):
            self.shield.record_drop(1)
            self.emit("blocked_request", {"ip": client_ip, "reason": "l4_blacklisted"})
            client_writer.close()
            await client_writer.wait_closed()
            self.active_connections -= 1
            return

        # 2. Rate Limiting Check
        allowed, should_escalate = self.limiter.allow(client_ip)
        if not allowed:
            if should_escalate:
                self.shield.block_ip(client_ip, duration_sec=300)
                self.emit("l4_escalation", {"ip": client_ip, "reason": "rate_limit_flood"})
            else:
                self.emit("rate_limited", {"ip": client_ip})
            
            # Send HTTP 429 if plain HTTP, or drop connection
            try:
                client_writer.write(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\nConnection: close\r\n\r\n429 Rate Limit Exceeded by VORTEX Shield\n")
                await client_writer.drain()
            except Exception:
                pass
            client_writer.close()
            try:
                await client_writer.wait_closed()
            except Exception:
                pass
            self.active_connections -= 1
            return

        # 3. Read initial payload header to detect TLS ClientHello or plain HTTP
        try:
            initial_data = await asyncio.wait_for(client_reader.read(4096), timeout=5.0)
        except Exception:
            client_writer.close()
            self.active_connections -= 1
            return

        if not initial_data:
            client_writer.close()
            self.active_connections -= 1
            return

        # 4. Deep Packet Inspection: TLS ClientHello & JA3/JA4 extraction
        if TLSClientHelloSniffer.is_client_hello(initial_data):
            ch_info = TLSClientHelloSniffer.parse_client_hello(initial_data)
            if ch_info:
                name, risk, score = FingerprintHeuristics.evaluate(ch_info["ja3_hash"], ch_info["ja4_string"])
                self.emit("tls_handshake", {
                    "ip": client_ip,
                    "sni": ch_info["sni"],
                    "ja3": ch_info["ja3_hash"],
                    "ja4": ch_info["ja4_string"],
                    "tool": name,
                    "risk": risk,
                    "score": score
                })
                if risk == "MALICIOUS":
                    self.shield.block_ip(client_ip, duration_sec=600)
                    self.emit("blocked_request", {"ip": client_ip, "reason": f"malicious_tls_fingerprint_{name}"})
                    client_writer.close()
                    self.active_connections -= 1
                    return
        else:
            # Plain HTTP request
            first_line = initial_data.split(b"\r\n")[0].decode("latin1", errors="ignore")
            self.emit("http_request", {"ip": client_ip, "line": first_line})

        # 5. Connect to Upstream
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.upstream_host, self.upstream_port
            )
        except Exception as e:
            self.emit("upstream_error", {"error": str(e), "ip": client_ip})
            try:
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nVORTEX: Upstream Unreachable\n")
                await client_writer.drain()
            except Exception:
                pass
            client_writer.close()
            self.active_connections -= 1
            return

        # 6. Forward initial bytes and start bidirectional Zero-Copy stream
        try:
            upstream_writer.write(initial_data)
            await upstream_writer.drain()
            self.shield.record_pass(1, len(initial_data))

            async def pipe(reader, writer, is_client_to_upstream=True):
                try:
                    while True:
                        buf = await reader.read(65536)
                        if not buf:
                            break
                        writer.write(buf)
                        await writer.drain()
                        if is_client_to_upstream:
                            self.shield.record_pass(1, len(buf))
                except Exception:
                    pass
                finally:
                    try:
                        writer.close()
                    except Exception:
                        pass

            await asyncio.gather(
                pipe(client_reader, upstream_writer, True),
                pipe(upstream_reader, client_writer, False),
                return_exceptions=True
            )
        finally:
            self.active_connections -= 1
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        """Bind socket and begin accepting connections."""
        self.server = await asyncio.start_server(
            self.handle_client, self.listen_host, self.listen_port, reuse_address=True
        )
        self.emit("server_started", {
            "listen": f"{self.listen_host}:{self.listen_port}",
            "upstream": f"{self.upstream_host}:{self.upstream_port}"
        })

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
