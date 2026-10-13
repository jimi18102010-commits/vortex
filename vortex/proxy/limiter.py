"""Bounded per-IP token buckets with a real 60-second violation window."""
import time
from typing import Dict, Tuple


class SlidingWindowLimiter:
    def __init__(self, capacity: int = 100, refill_rate: float = 20.0,
                 ban_threshold: int = 200, max_entries: int = 65536,
                 idle_ttl: float = 300.0):
        if capacity <= 0 or refill_rate < 0 or ban_threshold <= 0 or max_entries <= 0 or idle_ttl <= 0:
            raise ValueError("Invalid rate limiter configuration")
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.ban_threshold = ban_threshold
        self.max_entries = max_entries
        self.idle_ttl = idle_ttl
        self.buckets: Dict[str, Tuple[float, float]] = {}
        self.violations: Dict[str, int] = {}
        self.violation_reset: Dict[str, float] = {}
        self._last_cleanup = time.monotonic()

    def _remove(self, ip):
        self.buckets.pop(ip, None)
        self.violations.pop(ip, None)
        self.violation_reset.pop(ip, None)

    def allow(self, ip: str, cost: float = 1.0) -> Tuple[bool, bool]:
        if cost <= 0:
            raise ValueError("cost must be positive")
        now = time.monotonic()
        if now - self._last_cleanup >= 60:
            for key, (_, last) in list(self.buckets.items()):
                if now - last > self.idle_ttl:
                    self._remove(key)
            self._last_cleanup = now
        if ip not in self.buckets:
            if len(self.buckets) >= self.max_entries:
                # Fail closed rather than evicting an active IP's rate limit.
                return False, False
            self.violation_reset[ip] = now
        if now - self.violation_reset.get(ip, now) >= 60:
            self.violations[ip] = 0
            self.violation_reset[ip] = now
        tokens, last = self.buckets.get(ip, (self.capacity, now))
        tokens = min(self.capacity, tokens + max(0.0, now - last) * self.refill_rate)
        if tokens >= cost:
            self.buckets[ip] = (tokens - cost, now)
            return True, False
        self.buckets[ip] = (tokens, now)
        violations = self.violations.get(ip, 0) + 1
        self.violations[ip] = violations
        return False, violations >= self.ban_threshold
