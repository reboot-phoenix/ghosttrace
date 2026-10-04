"""
modules/jobs.py — background scan jobs with real, step-by-step progress.

POST /scan/start  -> job_id            (returns immediately)
GET  /scan/status -> {status, steps, result|error}

In-memory (single process). Jobs expire after 15 minutes. Bounded queue + per-IP cap so a
few slow scans can't starve the server.
"""
from __future__ import annotations
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import os

JOB_TTL = 15 * 60
MAX_JOBS = 200
MAX_ACTIVE_TOTAL = 24
MAX_ACTIVE_PER_IP = 2

_pool = ThreadPoolExecutor(max_workers=int(os.environ.get("SCAN_WORKERS", "4")),
                           thread_name_prefix="gt-job")
_jobs: dict[str, dict] = {}
_lock = threading.Lock()


class Busy(Exception):
    def __init__(self, msg, code=503):
        super().__init__(msg)
        self.code = code


def _purge(now: float) -> None:
    for jid in [j for j, v in _jobs.items() if now - v["created"] > JOB_TTL]:
        del _jobs[jid]
    if len(_jobs) > MAX_JOBS:
        for jid in sorted(_jobs, key=lambda j: _jobs[j]["created"])[: len(_jobs) - MAX_JOBS]:
            if _jobs[jid]["status"] in ("done", "error"):
                del _jobs[jid]


def submit(fn, ip: str = "unknown") -> str:
    """fn(progress) -> result dict. Raises Busy when the server is saturated."""
    now = time.time()
    with _lock:
        _purge(now)
        active = [v for v in _jobs.values() if v["status"] in ("queued", "running")]
        if len(active) >= MAX_ACTIVE_TOTAL:
            raise Busy("Server is busy, try again in a minute.", 503)
        if sum(1 for v in active if v["ip"] == ip) >= MAX_ACTIVE_PER_IP:
            raise Busy("You already have scans running. Wait for them to finish.", 429)
        jid = secrets.token_urlsafe(12)
        _jobs[jid] = {"status": "queued", "steps": [], "result": None, "error": None,
                      "created": now, "ip": ip, "started": None}

    def progress(label: str) -> None:
        t = time.time()
        with _lock:
            job = _jobs.get(jid)
            if not job:
                return
            if job["steps"]:
                job["steps"][-1].update(status="done", ms=int((t - job["steps"][-1]["t0"]) * 1000))
            job["steps"].append({"label": label, "status": "running", "t0": t})

    def work():
        with _lock:
            _jobs[jid]["status"], _jobs[jid]["started"] = "running", time.time()
        try:
            res = fn(progress)
            with _lock:
                job = _jobs[jid]
                if job["steps"]:
                    job["steps"][-1].update(status="done", ms=int((time.time() - job["steps"][-1]["t0"]) * 1000))
                job["result"], job["status"] = res, "done"
        except Exception as e:
            msg = str(e) if getattr(e, "user_safe", False) else "Scan failed. Please try again."
            with _lock:
                _jobs[jid]["error"], _jobs[jid]["status"] = msg, "error"

    _pool.submit(work)
    return jid


def get(jid: str) -> dict | None:
    with _lock:
        job = _jobs.get(jid)
        if not job:
            return None
        return {
            "status": job["status"],
            "steps": [{"label": s["label"], "status": s["status"], "ms": s.get("ms")} for s in job["steps"]],
            "elapsed": int(time.time() - (job["started"] or job["created"])),
            "result": job["result"] if job["status"] == "done" else None,
            "error": job["error"],
        }
