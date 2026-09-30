import pytest
import asyncio
from vortex.security.tls_sniffer import TLSClientHelloSniffer
from vortex.security.heuristics import FingerprintHeuristics
from vortex.proxy.limiter import SlidingWindowLimiter
from vortex.l4.loader import XDPShieldManager
from vortex.proxy.engine import VortexProxyEngine

# Raw minimal ClientHello bytes sample
SAMPLE_CLIENT_HELLO = (
    b"\x16\x03\x01\x00\x4b\x01\x00\x00\x47\x03\x03"
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    b"\x00\x00\x04\x13\x01\x13\x02\x01\x00\x00\x1a\x00\x00\x00\x0f\x00"
    b"\x0d\x00\x00\x0a\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d\x00\x0a"
    b"\x00\x04\x00\x02\x00\x1d"
)

def test_tls_client_hello_detection():
    assert TLSClientHelloSniffer.is_client_hello(SAMPLE_CLIENT_HELLO) is True
    assert TLSClientHelloSniffer.is_client_hello(b"GET / HTTP/1.1\r\n") is False

def test_ja3_ja4_fingerprinting():
    parsed = TLSClientHelloSniffer.parse_client_hello(SAMPLE_CLIENT_HELLO)
    assert parsed is not None
    assert parsed["version"] == 0x0303
    assert parsed["sni"] == "google.com"
    assert len(parsed["ja3_hash"]) == 32
    assert "_" in parsed["ja4_string"]

def test_heuristics_evaluation():
    name, risk, score = FingerprintHeuristics.evaluate("b32309a26951912be7dba376398abc3b", "t13d040200_xxxx_yyyy")
    assert "Requests" in name
    assert risk == "SUSPICIOUS"

def test_rate_limiter_and_l4_escalation():
    limiter = SlidingWindowLimiter(capacity=5, refill_rate=0.0, ban_threshold=3)
    ip = "192.168.1.100"

    # Consume 5 allowed
    for _ in range(5):
        allowed, should_ban = limiter.allow(ip)
        assert allowed is True
        assert should_ban is False

    # 6th request: rejected, not yet banned
    allowed, should_ban = limiter.allow(ip)
    assert allowed is False
    assert should_ban is False

    # 7th request
    limiter.allow(ip)
    # 8th request: reaches ban_threshold of 3 violations
    allowed, should_ban = limiter.allow(ip)
    assert allowed is False
    assert should_ban is True

def test_xdp_shield_manager():
    shield = XDPShieldManager(interface="lo")
    assert shield.compile_ebpf() is True
    assert shield.attach() is True
    
    shield.block_ip("10.0.0.1", duration_sec=60)
    assert shield.is_ip_blocked("10.0.0.1") is True
    assert shield.is_ip_blocked("10.0.0.2") is False

@pytest.mark.asyncio
async def test_proxy_end_to_end():
    # 1. Start dummy upstream HTTP server
    async def dummy_upstream(reader, writer):
        data = await reader.read(1024)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello Upstream")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    upstream_srv = await asyncio.start_server(dummy_upstream, "127.0.0.1", 9991)

    # 2. Start VORTEX reverse-proxy
    proxy = VortexProxyEngine(
        listen_host="127.0.0.1",
        listen_port=9992,
        upstream_host="127.0.0.1",
        upstream_port=9991
    )
    await proxy.start()

    # 3. Client request through proxy
    c_reader, c_writer = await asyncio.open_connection("127.0.0.1", 9992)
    c_writer.write(b"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
    await c_writer.drain()

    resp = await c_reader.read(1024)
    assert b"200 OK" in resp
    assert b"Hello Upstream" in resp

    c_writer.close()
    await c_writer.wait_closed()

    await proxy.stop()
    upstream_srv.close()
    await upstream_srv.wait_closed()
