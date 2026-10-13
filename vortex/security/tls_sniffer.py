"""Bounded TLS ClientHello parsing and JA3/JA4 telemetry (not client identity)."""
import hashlib
import struct
from typing import Optional


class TLSClientHelloSniffer:
    GREASE_TABLE = {0x0a0a + 0x1010 * i for i in range(16)}
    MAX_HELLO_BYTES = 65536

    @classmethod
    def is_client_hello(cls, data: bytes) -> bool:
        return len(data) >= 6 and data[0] == 22 and data[1] == 3 and data[5] == 1

    @classmethod
    def _handshake(cls, data):
        payload = bytearray()
        offset = 0
        while offset + 5 <= len(data):
            if data[offset] != 22 or data[offset + 1] != 3:
                return None
            length = int.from_bytes(data[offset + 3:offset + 5], 'big')
            if length == 0 or length > 18432 or offset + 5 + length > len(data):
                return None
            payload.extend(data[offset + 5:offset + 5 + length])
            if len(payload) > cls.MAX_HELLO_BYTES:
                return None
            if len(payload) >= 4:
                required = 4 + int.from_bytes(payload[1:4], 'big')
                if payload[0] != 1 or required > cls.MAX_HELLO_BYTES:
                    return None
                if len(payload) >= required:
                    return bytes(payload[4:required])
            offset += 5 + length
        return None

    @classmethod
    def parse_client_hello(cls, data: bytes) -> Optional[dict]:
        hello = cls._handshake(data)
        if hello is None:
            return None
        try:
            cursor = 0
            def take(n):
                nonlocal cursor
                if n < 0 or cursor + n > len(hello):
                    raise ValueError('Truncated ClientHello')
                value = hello[cursor:cursor + n]
                cursor += n
                return value
            def u16():
                return int.from_bytes(take(2), 'big')
            def vector16(buf, prefix=True):
                if prefix:
                    if len(buf) < 2 or int.from_bytes(buf[:2], 'big') != len(buf) - 2:
                        raise ValueError('Invalid TLS vector')
                    buf = buf[2:]
                if len(buf) % 2:
                    raise ValueError('Odd TLS vector length')
                return [int.from_bytes(buf[i:i + 2], 'big') for i in range(0, len(buf), 2)
                        if int.from_bytes(buf[i:i + 2], 'big') not in cls.GREASE_TABLE]
            legacy_version = u16()
            take(32)
            take(take(1)[0])
            ciphers = vector16(take(u16()), prefix=False)
            take(take(1)[0])
            extensions, curves, points, signatures, versions = [], [], [], [], []
            sni = alpn = None
            if cursor < len(hello):
                remaining = u16()
                if cursor + remaining != len(hello):
                    raise ValueError('Invalid extension length')
                end = cursor + remaining
                while cursor < end:
                    kind, size = u16(), u16()
                    buf = take(size)
                    if kind not in cls.GREASE_TABLE:
                        extensions.append(kind)
                    if kind == 0:
                        if len(buf) < 5 or int.from_bytes(buf[:2], 'big') != len(buf) - 2:
                            raise ValueError('Invalid SNI')
                        if buf[2] == 0:
                            size = int.from_bytes(buf[3:5], 'big')
                            if size + 5 > len(buf):
                                raise ValueError('Truncated SNI')
                            sni = buf[5:5 + size].decode('ascii')
                    elif kind == 10:
                        curves = vector16(buf)
                    elif kind == 11:
                        if not buf or buf[0] != len(buf) - 1:
                            raise ValueError('Invalid point formats')
                        points = list(buf[1:])
                    elif kind == 13:
                        signatures = vector16(buf)
                    elif kind == 16:
                        if len(buf) < 3 or int.from_bytes(buf[:2], 'big') != len(buf) - 2 or buf[2] + 3 > len(buf):
                            raise ValueError('Invalid ALPN')
                        alpn = buf[3:3 + buf[2]].decode('ascii')
                    elif kind == 43:
                        if not buf or buf[0] != len(buf) - 1:
                            raise ValueError('Invalid supported_versions')
                        versions = vector16(buf[1:], prefix=False)
            version = max(versions) if versions else legacy_version
            ja3_string = ','.join([str(legacy_version), '-'.join(map(str, ciphers)),
                                   '-'.join(map(str, extensions)), '-'.join(map(str, curves)), '-'.join(map(str, points))])
            version_code = {0x0301: '10', 0x0302: '11', 0x0303: '12', 0x0304: '13'}.get(version, '00')
            alpn_code = (alpn[0] + alpn[-1]) if alpn else '00'
            if not alpn_code.isalnum():
                alpn_code = alpn.encode().hex()[:2] if alpn else '00'
            ja4_a = f"t{version_code}{'d' if sni else 'i'}{min(len(ciphers), 99):02d}{min(len(extensions), 99):02d}{alpn_code}"
            sorted_ciphers = ','.join(f'{c:04x}' for c in sorted(ciphers))
            # JA4 excludes SNI/ALPN extensions from c and appends signature algorithms in wire order.
            ext_ids = ','.join(f'{e:04x}' for e in sorted(extensions) if e not in (0, 16))
            sig_ids = ','.join(f'{s:04x}' for s in signatures)
            c_input = ext_ids + ('_' + sig_ids if signatures else '')
            b_hash = hashlib.sha256(sorted_ciphers.encode()).hexdigest()[:12] if ciphers else '0' * 12
            c_hash = hashlib.sha256(c_input.encode()).hexdigest()[:12] if c_input else '0' * 12
            return {'version': legacy_version, 'negotiation_version': version, 'ciphers': ciphers,
                    'extensions': extensions, 'curves': curves, 'point_formats': points, 'sni': sni,
                    'alpn': alpn, 'ja3_string': ja3_string, 'ja3_hash': hashlib.md5(ja3_string.encode()).hexdigest(),
                    'ja4_string': f'{ja4_a}_{b_hash}_{c_hash}'}
        except (ValueError, IndexError, UnicodeError, struct.error):
            return None
