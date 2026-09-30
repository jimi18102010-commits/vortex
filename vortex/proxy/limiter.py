"""
Sliding Window Token Bucket Rate Limiter with Automatic L4 Escalation.
"""
import time
from typing import Dict, Tuple

class SlidingWindowLimiter:
    def __init__(self, capacity: int = 100, refill_rate: float = 20.0, ban_threshold: int = 200):
        """
        :param capacity: Max burst token capacity
        :param refill_rate: Tokens added per second
        :param ban_threshold: Violation count within a minute before escalating to kernel L4 ban
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.ban_threshold = ban_threshold

        # ip -> (tokens, last_update_time)
        self.buckets: Dict[str, Tuple[float, float]] = {}
        # ip -> violation_count
        self.violations: Dict[str, int] = {}
        # ip -> last_violation_reset
        self.violation_reset: Dict[str, float] = {}

    def allow(self, ip: str, cost: float = 1.0) -> Tuple[bool, bool]:
        """
        Check if an IP request is allowed.
        Returns: (allowed: bool, should_escalate_l4_ban: bool)
        """
        now = time.time()
        
        # 1. Reset violations older than 60s
        last_v_reset = self.violation_reset.get(ip, now)
        if now - last_v_reset > 60.0:
            self.violations[ip] = 0
            self.violation_reset[ip] = now

        # 2. Get or initialize token bucket
        tokens, last_time = self.buckets.get(ip, (self.capacity, now))
        
        # 3. Refill tokens
        elapsed = now - last_time
        tokens = min(self.capacity, tokens + (elapsed * self.refill_rate))

        if tokens >= cost:
            tokens -= cost
            self.buckets[ip] = (tokens, now)
            return True, False
        else:
            # Over limit
            self.buckets[ip] = (tokens, now)
            curr_v = self.violations.get(ip, 0) + 1
            self.violations[ip] = curr_v
            
            should_ban = curr_v >= self.ban_threshold
            return False, should_ban
