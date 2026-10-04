"""
modules/timeouts.py — run slow, flaky sources with hard deadlines.

A source that hangs must never hang the scan: we stop waiting after `timeout` seconds and
report it as skipped. (Python can't kill a running thread, so the straggler finishes in the
background on a bounded pool; every source also has its own network timeouts.)
"""
from __future__ import annotations
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout

_pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="gt-src")


class ScanTimeout(Exception):
    user_safe = True        # message may be shown to the user as-is


def run_with_timeout(fn, timeout: float, *args, **kwargs):
    fut = _pool.submit(fn, *args, **kwargs)
    try:
        return fut.result(timeout=timeout)
    except FutTimeout:
        raise ScanTimeout(f"timed out after {int(timeout)}s")


def gather(tasks: dict) -> dict:
    """
    tasks = {name: (fn, args_tuple, timeout_seconds)}
    returns {name: {"ok": bool, "value": ..., "error": str|None}}; runs all concurrently.
    """
    start = time.time()
    futs = {n: (_pool.submit(fn, *args), timeout) for n, (fn, args, timeout) in tasks.items()}
    out = {}
    for name, (fut, timeout) in futs.items():
        remaining = max(0.05, timeout - (time.time() - start))
        try:
            out[name] = {"ok": True, "value": fut.result(timeout=remaining), "error": None}
        except FutTimeout:
            out[name] = {"ok": False, "value": None, "error": f"timed out after {int(timeout)}s"}
        except Exception as e:           # a failing source never fails the scan
            out[name] = {"ok": False, "value": None, "error": type(e).__name__}
    return out
