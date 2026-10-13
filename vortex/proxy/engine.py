"""Bounded asynchronous TCP forwarding with optional TLS fingerprint telemetry."""
import asyncio
import logging
import time
from collections import Counter
from typing import Callable, Optional

from ..security.tls_sniffer import TLSClientHelloSniffer
from ..security.heuristics import FingerprintHeuristics
from ..l4.loader import XDPShieldManager
from .limiter import SlidingWindowLimiter

log = logging.getLogger(__name__)


class VortexProxyEngine:
    def __init__(self, listen_host='0.0.0.0', listen_port=8080, upstream_host='127.0.0.1',
                 upstream_port=80, shield_manager: Optional[XDPShieldManager] = None,
                 on_event: Optional[Callable[[dict], None]] = None, max_connections=512,
                 max_connections_per_ip=50, idle_timeout=30.0, connect_timeout=5.0):
        if min(max_connections, max_connections_per_ip, idle_timeout, connect_timeout) <= 0:
            raise ValueError('Connection limits/timeouts must be positive')
        self.listen_host, self.listen_port = listen_host, listen_port
        self.upstream_host, self.upstream_port = upstream_host, upstream_port
        self.shield = shield_manager or XDPShieldManager()
        self.limiter = SlidingWindowLimiter(capacity=100, refill_rate=20.0, ban_threshold=50)
        self.on_event = on_event
        self.max_connections = max_connections
        self.max_connections_per_ip = max_connections_per_ip
        self.idle_timeout, self.connect_timeout = idle_timeout, connect_timeout
        self.server = None
        self.active_connections = self.total_requests = 0
        self.connections_by_ip = Counter()
        self._tasks = set()

    def emit(self, event_type, data):
        if self.on_event:
            try:
                self.on_event({'type': event_type, 'timestamp': time.time(), **data})
            except Exception:
                log.exception('Event callback failed')

    async def _close(self, writer):
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except (Exception, asyncio.CancelledError):
                pass

    async def _read_initial(self, reader):
        data = bytearray(await reader.read(4096))
        if not data or data[0] != 22:
            return bytes(data), None
        offset, handshake = 0, bytearray()
        while True:
            async def ensure(size):
                if size > TLSClientHelloSniffer.MAX_HELLO_BYTES + 4096:
                    raise ValueError('ClientHello is too large')
                if len(data) < size:
                    data.extend(await reader.readexactly(size - len(data)))
            await ensure(offset + 5)
            if data[offset] != 22 or data[offset + 1] != 3:
                raise ValueError('Unexpected TLS record before ClientHello completion')
            record_size = int.from_bytes(data[offset + 3:offset + 5], 'big')
            if record_size <= 0 or record_size > 18432:
                raise ValueError('Invalid TLS record size')
            await ensure(offset + 5 + record_size)
            handshake.extend(data[offset + 5:offset + 5 + record_size])
            offset += 5 + record_size
            if len(handshake) >= 4:
                required = 4 + int.from_bytes(handshake[1:4], 'big')
                if handshake[0] != 1 or required > TLSClientHelloSniffer.MAX_HELLO_BYTES:
                    raise ValueError('Invalid ClientHello length/type')
                if len(handshake) >= required:
                    parsed = TLSClientHelloSniffer.parse_client_hello(bytes(data))
                    if parsed is None:
                        raise ValueError('Malformed ClientHello')
                    return bytes(data), parsed

    async def handle_client(self, client_reader, client_writer):
        peer = client_writer.get_extra_info('peername')
        ip = peer[0] if peer else 'unknown'
        if (self.active_connections >= self.max_connections
                or self.connections_by_ip[ip] >= self.max_connections_per_ip):
            self.emit('connection_limit', {'ip': ip})
            await self._close(client_writer)
            return
        task = asyncio.current_task()
        self._tasks.add(task)
        self.active_connections += 1
        self.connections_by_ip[ip] += 1
        self.total_requests += 1  # Compatibility: counts TCP connections, not HTTP requests.
        upstream_writer = None
        try:
            if self.shield.is_ip_blocked(ip):
                self.shield.record_drop()
                self.emit('blocked_request', {'ip': ip, 'reason': 'blacklisted'})
                return
            allowed, escalate = self.limiter.allow(ip)
            if not allowed:
                if escalate:
                    success = self.shield.block_ip(ip, duration_sec=300)
                    self.emit('l4_escalation', {'ip': ip, 'kernel_or_userspace_success': success})
                else:
                    self.emit('rate_limited', {'ip': ip})
                # Protocol-neutral TCP close; never send plaintext HTTP into TLS.
                return
            data, hello = await asyncio.wait_for(self._read_initial(client_reader), timeout=5.0)
            if not data:
                return
            if hello:
                name, risk, score = FingerprintHeuristics.evaluate(hello['ja3_hash'], hello['ja4_string'])
                self.emit('tls_handshake', {'ip': ip, 'sni': hello['sni'], 'ja3': hello['ja3_hash'],
                                          'ja4': hello['ja4_string'], 'tool': name, 'risk': risk, 'score': score})
                if risk == 'MALICIOUS':
                    self.shield.block_ip(ip, duration_sec=600)
                    return
            else:
                self.emit('http_request', {'ip': ip, 'line': data.split(b'\r\n')[0].decode('latin1', errors='replace')[:1024]})
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(self.upstream_host, self.upstream_port), timeout=self.connect_timeout)
            upstream_writer.write(data)
            await asyncio.wait_for(upstream_writer.drain(), timeout=self.idle_timeout)
            self.shield.record_pass(1, len(data))
            async def pipe(reader, writer, count):
                while True:
                    buf = await asyncio.wait_for(reader.read(65536), timeout=self.idle_timeout)
                    if not buf:
                        if writer.can_write_eof():
                            writer.write_eof()
                            await asyncio.wait_for(writer.drain(), timeout=self.idle_timeout)
                        return
                    writer.write(buf)
                    await asyncio.wait_for(writer.drain(), timeout=self.idle_timeout)
                    if count:
                        self.shield.record_pass(1, len(buf))
            pipes = [asyncio.create_task(pipe(client_reader, upstream_writer, True)),
                     asyncio.create_task(pipe(upstream_reader, client_writer, False))]
            try:
                await asyncio.gather(*pipes)
            finally:
                for pipe_task in pipes:
                    pipe_task.cancel()
                await asyncio.gather(*pipes, return_exceptions=True)
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
            self.emit('connection_error', {'ip': ip, 'error': str(exc)})
        finally:
            await self._close(upstream_writer)
            await self._close(client_writer)
            self.active_connections -= 1
            self.connections_by_ip[ip] -= 1
            if not self.connections_by_ip[ip]:
                del self.connections_by_ip[ip]
            self._tasks.discard(task)

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, self.listen_host, self.listen_port, reuse_address=True)
        self.emit('server_started', {'listen': f'{self.listen_host}:{self.listen_port}',
                                    'upstream': f'{self.upstream_host}:{self.upstream_port}'})

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
