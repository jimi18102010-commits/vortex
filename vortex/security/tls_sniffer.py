"""
Binary wire-level TLS ClientHello parser & JA3/JA4 fingerprinting engine.
Extracts cipher suites, extensions, elliptic curves and point formats directly
from initial TCP stream bytes without full SSL termination.
"""
import hashlib
import struct
from typing import Dict, List, Optional, Tuple

class TLSClientHelloSniffer:
    # Grease values defined in RFC 8701
    GREASE_TABLE = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
    }

    @classmethod
    def is_client_hello(cls, data: bytes) -> bool:
        """Check if incoming TCP bytes begin with a TLS Record ClientHello."""
        if len(data) < 9:
            return False
        content_type = data[0]
        # 0x16 = Handshake record
        if content_type != 0x16:
            return False
        major, minor = data[1], data[2]
        # SSL 3.0 or TLS 1.0 - 1.3 (0x03, 0x00..0x03)
        if major != 3:
            return False
        handshake_type = data[5]
        # 0x01 = ClientHello
        return handshake_type == 0x01

    @classmethod
    def parse_client_hello(cls, data: bytes) -> Optional[dict]:
        """
        Parse raw bytes of TLS ClientHello record.
        Returns dictionary containing:
        - version: int
        - ciphers: List[int]
        - extensions: List[int]
        - curves: List[int]
        - point_formats: List[int]
        - sni: Optional[str]
        - ja3_string: str
        - ja3_hash: str (MD5)
        - ja4_string: str
        """
        if not cls.is_client_hello(data):
            return None

        try:
            record_len = struct.unpack("!H", data[3:5])[0]
            if len(data) < 5 + record_len:
                # Truncated or incomplete packet
                pass

            offset = 5 # Start of handshake message
            handshake_type = data[offset]
            if handshake_type != 1:
                return None
            offset += 1

            # 3 bytes handshake length
            handshake_len = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]
            offset += 3

            # Client Version (2 bytes)
            client_version = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2

            # Random (32 bytes)
            offset += 32

            # Session ID
            session_id_len = data[offset]
            offset += 1 + session_id_len

            # Cipher Suites
            ciphers_len = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
            ciphers = []
            for i in range(0, ciphers_len, 2):
                c = struct.unpack("!H", data[offset+i:offset+i+2])[0]
                if c not in cls.GREASE_TABLE:
                    ciphers.append(c)
            offset += ciphers_len

            # Compression Methods
            comp_len = data[offset]
            offset += 1
            compressions = list(data[offset:offset+comp_len])
            offset += comp_len

            # Extensions
            extensions = []
            curves = []
            point_formats = []
            sni = None
            alpn = None

            if offset + 2 <= len(data):
                ext_total_len = struct.unpack("!H", data[offset:offset+2])[0]
                offset += 2
                end_ext = offset + ext_total_len

                while offset + 4 <= min(end_ext, len(data)):
                    ext_type = struct.unpack("!H", data[offset:offset+2])[0]
                    ext_len = struct.unpack("!H", data[offset+2:offset+4])[0]
                    offset += 4

                    if ext_type not in cls.GREASE_TABLE:
                        extensions.append(ext_type)

                    ext_data = data[offset:offset+ext_len]

                    # SNI (Extension 0)
                    if ext_type == 0 and len(ext_data) > 2:
                        try:
                            # server_name_list
                            list_len = struct.unpack("!H", ext_data[0:2])[0]
                            if len(ext_data) >= 5 and ext_data[2] == 0: # host_name
                                name_len = struct.unpack("!H", ext_data[3:5])[0]
                                sni = ext_data[5:5+name_len].decode("utf-8", errors="ignore")
                        except Exception:
                            pass

                    # Supported Groups / Elliptic Curves (Extension 10)
                    elif ext_type == 10 and len(ext_data) >= 2:
                        curves_len = struct.unpack("!H", ext_data[0:2])[0]
                        for c_i in range(2, min(2 + curves_len, len(ext_data)), 2):
                            curve_id = struct.unpack("!H", ext_data[c_i:c_i+2])[0]
                            if curve_id not in cls.GREASE_TABLE:
                                curves.append(curve_id)

                    # EC Point Formats (Extension 11)
                    elif ext_type == 11 and len(ext_data) >= 1:
                        pf_len = ext_data[0]
                        point_formats = list(ext_data[1:1+pf_len])

                    # ALPN (Extension 16)
                    elif ext_type == 16 and len(ext_data) >= 2:
                        alpn_list_len = struct.unpack("!H", ext_data[0:2])[0]
                        if len(ext_data) >= 3:
                            first_len = ext_data[2]
                            alpn = ext_data[3:3+first_len].decode("utf-8", errors="ignore")

                    offset += ext_len

            # 1. Compute JA3 Fingerprint:
            # SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
            ciphers_str = "-".join(str(c) for c in ciphers)
            exts_str = "-".join(str(e) for e in extensions)
            curves_str = "-".join(str(cr) for cr in curves)
            points_str = "-".join(str(pt) for pt in point_formats)

            ja3_string = f"{client_version},{ciphers_str},{exts_str},{curves_str},{points_str}"
            ja3_hash = hashlib.md5(ja3_string.encode("utf-8")).hexdigest()

            # 2. Compute JA4 Fingerprint:
            # t (TCP) + 13 (version) + d (sni exists: d, else i) + cipher_count + ext_count + alpn
            proto = "t" # TCP
            ver_map = {0x0303: "12", 0x0304: "13", 0x0302: "11", 0x0301: "10"}
            v_str = ver_map.get(client_version, "00")
            sni_flag = "d" if sni else "i"
            c_cnt = f"{min(len(ciphers), 99):02d}"
            e_cnt = f"{min(len(extensions), 99):02d}"
            alpn_code = "00"
            if alpn:
                alpn_code = alpn[:2] if len(alpn) >= 2 else alpn + "0"

            ja4_a = f"{proto}{v_str}{sni_flag}{c_cnt}{e_cnt}{alpn_code}"
            
            # Sorted ciphers hash (12 hex chars)
            sorted_ciphers = ",".join(f"{c:04x}" for c in sorted(ciphers))
            ja4_b = hashlib.sha256(sorted_ciphers.encode()).hexdigest()[:12] if ciphers else "000000000000"

            # Sorted extensions hash (12 hex chars)
            sorted_exts = ",".join(f"{e:04x}" for e in sorted(extensions))
            ja4_c = hashlib.sha256(sorted_exts.encode()).hexdigest()[:12] if extensions else "000000000000"

            ja4_string = f"{ja4_a}_{ja4_b}_{ja4_c}"

            return {
                "version": client_version,
                "ciphers": ciphers,
                "extensions": extensions,
                "curves": curves,
                "point_formats": point_formats,
                "sni": sni,
                "alpn": alpn,
                "ja3_string": ja3_string,
                "ja3_hash": ja3_hash,
                "ja4_string": ja4_string
            }
        except Exception:
            return None
