"""Docspector Process-Local In-Memory Rate Limiter (Milestone 20).

Inspect. Verify. Trust.

Provides a thread-safe, bounded sliding-window rate limiter for single-process
local/intranet/air-gapped deployments.

LIMITATION:
This limiter is process-local and is not a distributed production rate limiter.
"""

from __future__ import annotations

from collections import OrderedDict
import hashlib
import threading
import time
from typing import Tuple


class InMemoryRateLimiter:
    """Thread-safe, bounded, sliding-window rate limiter with TTL expiry."""

    def __init__(self, max_keys: int = 10000):
        self._max_keys = max_keys
        self._lock = threading.Lock()
        # Maps key -> list of float timestamps
        self._attempts: OrderedDict[str, list[float]] = OrderedDict()

    def _cleanup_expired(self, current_time: float, window_seconds: float) -> None:
        """Remove expired entries. Must be called while holding _lock."""
        expired_keys = []
        for key, timestamps in self._attempts.items():
            valid_timestamps = [t for t in timestamps if current_time - t < window_seconds]
            if not valid_timestamps:
                expired_keys.append(key)
            else:
                self._attempts[key] = valid_timestamps
        for key in expired_keys:
            self._attempts.pop(key, None)

    def is_rate_limited(
        self,
        key: str,
        max_attempts: int,
        window_seconds: float,
        current_time: float | None = None,
    ) -> tuple[bool, int, float]:
        """Check if key has exceeded max_attempts within the sliding window.

        Returns:
            (is_limited, remaining_attempts, retry_after_seconds)
        """
        now = current_time if current_time is not None else time.time()
        with self._lock:
            timestamps = self._attempts.get(key, [])
            valid_timestamps = [t for t in timestamps if now - t < window_seconds]
            self._attempts[key] = valid_timestamps

            if len(valid_timestamps) >= max_attempts:
                oldest = valid_timestamps[0]
                retry_after = max(1.0, window_seconds - (now - oldest))
                return True, 0, retry_after

            remaining = max(0, max_attempts - len(valid_timestamps))
            return False, remaining, 0.0

    def record_attempt(
        self,
        key: str,
        window_seconds: float,
        current_time: float | None = None,
    ) -> None:
        """Record an attempt against the key."""
        now = current_time if current_time is not None else time.time()
        with self._lock:
            # Enforce bounded capacity
            if len(self._attempts) >= self._max_keys:
                self._cleanup_expired(now, window_seconds)
                while len(self._attempts) >= self._max_keys:
                    self._attempts.popitem(last=False)

            timestamps = self._attempts.get(key, [])
            valid_timestamps = [t for t in timestamps if now - t < window_seconds]
            valid_timestamps.append(now)
            self._attempts[key] = valid_timestamps
            self._attempts.move_to_end(key)

    def reset(self, key: str) -> None:
        """Reset attempts for a key (e.g. on successful authentication)."""
        with self._lock:
            self._attempts.pop(key, None)

    def clear(self) -> None:
        """Reset all rate limiter state (useful for tests)."""
        with self._lock:
            self._attempts.clear()

    @staticmethod
    def hash_key(*parts: str) -> str:
        """Create a deterministic, safe, fixed-length hash key from input parts."""
        combined = ":".join(p.strip().lower() for p in parts)
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()


# Singleton instance for login rate limiting
login_rate_limiter = InMemoryRateLimiter()
