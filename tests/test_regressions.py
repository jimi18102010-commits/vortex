import asyncio
import json
import ssl
import struct
from unittest.mock import MagicMock, patch

import pytest
from vortex.l4.loader import XDPShieldManager
from vortex.proxy.engine import VortexProxyEngine
from vortex.proxy.limiter import SlidingWindowLimiter
from vortex.security.tls_sniffer import TLSClientHelloSniffer


def hello_bytes():
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    conn = ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname='example.com')
    try:
        conn.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def test_violations_reset_after_minute(monkeypatch):
    now = [100.0]
    monkeypatch.setattr('vortex.proxy.limiter.time.monotonic', lambda: now[0])
    limiter = SlidingWindowLimiter(capacity=1, refill_rate=0, ban_threshold=3)
    limiter.allow('192.0.2.1')
    limiter.allow('192.0.2.1')
    limiter.allow('192.0.2.1')
    now[0] += 61
    assert limiter.allow('192.0.2.1') == (False, False)
    assert limiter.violations['192.0.2.1'] == 1


def test_limiter_bounded_and_idle_eviction(monkeypatch):
    now = [100.0]
    monkeypatch.setattr('vortex.proxy.limiter.time.monotonic', lambda: now[0])
    limiter = SlidingWindowLimiter(max_entries=2, idle_ttl=60)
    limiter.allow('a'); limiter.allow('b')
    assert limiter.allow('c') == (False, False)
    now[0] += 61
    assert limiter.allow('c') == (True, False)
    assert set(limiter.buckets) == {'c'}


def test_kernel_ban_serializes_expiry_and_deletes(monkeypatch):
    now = [100.0]
    monkeypatch.setattr('vortex.l4.loader.time.monotonic', lambda: now[0])
    monkeypatch.setattr('vortex.l4.loader.time.monotonic_ns', lambda: int(now[0] * 1e9))
    shield = XDPShieldManager(); shield.mode = 'xdp_generic'; shield.map_id = 123
    with patch('vortex.l4.loader.subprocess.run') as run:
        assert shield.block_ip('192.0.2.1', duration_sec=5)
        cmd = run.call_args.args[0]
        data = bytes.fromhex(' '.join(cmd[cmd.index('value') + 2:]))
        assert struct.unpack('=QQ', data) == (105_000_000_000, 0)
        assert 'name' not in cmd and '123' in cmd
        now[0] = 106
        assert not shield.is_ip_blocked('192.0.2.1')
        assert 'delete' in run.call_args.args[0]


def test_kernel_update_failure_reported():
    shield = XDPShieldManager(); shield.mode = 'xdp_generic'; shield.map_id = 1
    with patch('vortex.l4.loader.subprocess.run', side_effect=OSError('missing bpftool')):
        assert not shield.block_ip('192.0.2.1')
    assert shield.is_ip_blocked('192.0.2.1')  # userspace remains protective


def test_map_resolution_scoped_to_attached_program():
    shield = XDPShieldManager()
    with patch('vortex.l4.loader.subprocess.check_output', side_effect=[
        json.dumps([{'xdp': {'prog': {'id': 12}}}]).encode(),
        json.dumps({'map_ids': [42]}).encode(),
        json.dumps({'name': 'blocked_ips'}).encode(),
    ]) as run:
        shield._resolve_map_id()
    assert shield.map_id == 42
    assert run.call_args_list[1].args[0][-1] == '12'


def test_existing_xdp_not_replaced():
    shield = XDPShieldManager()
    with patch.object(shield, 'is_root', return_value=True), patch.object(shield, 'compile_ebpf', return_value=True), \
            patch('vortex.l4.loader.subprocess.check_output', return_value=b'[{"xdp":{"prog":{"id":999}}}]'), \
            patch('vortex.l4.loader.subprocess.run') as run:
        shield.attach()
    assert shield.mode == 'userspace_l4'
    run.assert_not_called()


def test_tls13_version_and_truncated_rejection():
    data = hello_bytes()
    parsed = TLSClientHelloSniffer.parse_client_hello(data)
    assert parsed is not None and parsed['sni'] == 'example.com'
    assert parsed['negotiation_version'] == 0x0304
    assert parsed['ja4_string'].startswith('t13d')
    assert TLSClientHelloSniffer.parse_client_hello(data[:-1]) is None


def test_hello_split_across_tls_records():
    data = hello_bytes(); payload = data[5:]
    wire = b''.join(b'\x16\x03\x01' + len(part).to_bytes(2, 'big') + part for part in [payload[:20], payload[20:]])
    assert TLSClientHelloSniffer.parse_client_hello(wire)['ja3_hash'] == TLSClientHelloSniffer.parse_client_hello(data)['ja3_hash']


@pytest.mark.asyncio
async def test_fragmented_tcp_hello_is_buffered():
    wire = hello_bytes(); reader = asyncio.StreamReader()
    engine = VortexProxyEngine()
    async def feed():
        reader.feed_data(wire[:2])
        await asyncio.sleep(0)
        reader.feed_data(wire[2:10])
        await asyncio.sleep(0)
        reader.feed_data(wire[10:]); reader.feed_eof()
    feeder = asyncio.create_task(feed())
    data, parsed = await engine._read_initial(reader)
    await feeder
    assert data == wire and parsed['sni'] == 'example.com'


@pytest.mark.asyncio
async def test_connection_cap_closes_without_upstream():
    engine = VortexProxyEngine(max_connections=1)
    engine.active_connections = 1
    reader = asyncio.StreamReader(); writer = MagicMock()
    writer.get_extra_info.return_value = ('192.0.2.1', 123)
    async def wait_closed():
        pass
    writer.wait_closed.side_effect = wait_closed
    await engine.handle_client(reader, writer)
    writer.close.assert_called_once()
    assert engine.active_connections == 1


@pytest.mark.asyncio
async def test_failed_upstream_cleans_counters():
    engine = VortexProxyEngine()
    reader = asyncio.StreamReader(); reader.feed_data(b'GET / HTTP/1.1\r\n\r\n'); reader.feed_eof()
    writer = MagicMock(); writer.get_extra_info.return_value = ('192.0.2.1', 1)
    async def wait_closed():
        pass
    writer.wait_closed.side_effect = wait_closed
    with patch('vortex.proxy.engine.asyncio.open_connection', side_effect=OSError('refused')):
        await engine.handle_client(reader, writer)
    assert engine.active_connections == 0 and not engine.connections_by_ip
    assert not engine._tasks


def test_ban_and_connection_config_validation():
    with pytest.raises(ValueError): SlidingWindowLimiter(capacity=0)
    with pytest.raises(ValueError): VortexProxyEngine(idle_timeout=0)
    with pytest.raises(ValueError): XDPShieldManager().block_ip('192.0.2.1', 0)
