"""
Threat intelligence and heuristic bot/scanner fingerprint database.
Identifies automated vulnerability scanners, scrapers, and malicious tools.
"""
from typing import Dict, Tuple

class FingerprintHeuristics:
    # Known tool fingerprints
    KNOWN_FINGERPRINTS = {
        # Python Requests / Urllib
        "b32309a26951912be7dba376398abc3b": ("Python / Requests Tool", "SUSPICIOUS", 40),
        "7271429d634a52f337f943e432dc852b": ("Python standard urllib", "SUSPICIOUS", 45),
        
        # Go HTTP Client
        "773906b0efcf2e0a24cad042f493777b": ("Golang standard http client", "SUSPICIOUS", 50),
        "9231dd93be42194ff75cb617cfd8b139": ("Go-based Mass Scanner", "MALICIOUS", 85),

        # ZGrab / Masscan / Nmap
        "0cce74b019b7dd250260bad63f469e32": ("ZGrab Scanner", "MALICIOUS", 95),
        "4a7a8d5f3083cfc0be9ff9f0eb019310": ("Automated Vulnerability Prober", "MALICIOUS", 90),

        # Headless Chrome / Puppeteer
        "b3240e4f20cdb284e3146f4b6cb908e2": ("Chrome Headless / Bot", "SUSPICIOUS", 60),

        # Standard Modern Browsers
        "66918128f1b9b03380d6824fde3fa5d5": ("Google Chrome / Chromium", "BENIGN", 5),
        "e7d705a3286e19ea42f587b344ee6865": ("Mozilla Firefox Modern", "BENIGN", 5),
        "2d1073b18d0d12d2d6f1e813f456943b": ("Apple Safari", "BENIGN", 5),
    }

    @classmethod
    def evaluate(cls, ja3_hash: str, ja4_string: str) -> Tuple[str, str, int]:
        """
        Evaluate fingerprint risk.
        Returns: (Identified_Name, Risk_Level ['BENIGN', 'SUSPICIOUS', 'MALICIOUS'], Threat_Score 0..100)
        """
        # Exact JA3 match
        if ja3_hash in cls.KNOWN_FINGERPRINTS:
            return cls.KNOWN_FINGERPRINTS[ja3_hash]

        # JA4 Heuristic rules
        # e.g., command-line tools often have very few extensions or odd cipher counts
        if ja4_string:
            parts = ja4_string.split("_")
            if len(parts) == 3:
                a_part = parts[0]
                # a_part format: t13d100800
                if len(a_part) >= 8:
                    try:
                        c_cnt = int(a_part[4:6])
                        e_cnt = int(a_part[6:8])
                        # Scanners typically send < 4 extensions and < 5 ciphers
                        if e_cnt <= 3 and c_cnt <= 4:
                            return ("Scripted / Custom Raw Client", "SUSPICIOUS", 70)
                    except ValueError:
                        pass

        return ("Unknown / Unique Client", "NEUTRAL", 15)
