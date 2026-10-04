"""modules/cache.py — tiny thread-safe in-memory TTL cache (bounded)."""
from __future__ import annotations
import threading
import time
from collections import OrderedDict


class TTLCache:
    def __init__(self, ttl: float, max_items: int = 500):
        self.ttl, self.max_items = ttl, max_items
        self._d: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            hit = self._d.get(key)
            if not hit:
                return None
            ts, val = hit
            if time.time() - ts > self.ttl:
                del self._d[key]
                return None
            self._d.move_to_end(key)
            return val

    def set(self, key, val) -> None:
        with self._lock:
            self._d[key] = (time.time(), val)
            self._d.move_to_end(key)
            while len(self._d) > self.max_items:
                self._d.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._d.clear()
