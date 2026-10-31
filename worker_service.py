"""Long-running worker process for Hostinger or another managed Python runtime.

Run with: python worker_service.py
The HTTP API remains in main.py; this process independently drains durable scan jobs
and PostgreSQL-to-Hostinger synchronization outboxes.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal

from hostinger_database import HostingerAsyncSessionLocal
from scan_worker import process_scan_queue

logging.basicConfig(
    level=os.getenv("WORKER_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("worker_service")


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer.") from exc
    if value < minimum or value > maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}.")
    return value


async def run_worker() -> None:
    if HostingerAsyncSessionLocal is None:
        raise RuntimeError("HOSTINGER_DATABASE_URL is required to run the durable scan worker.")
    max_jobs = _bounded_int("SCAN_WORKER_MAX_JOBS", 1, 1, 10)
    poll_seconds = _bounded_int("SCAN_WORKER_POLL_SECONDS", 5, 1, 300)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            # Some managed runtimes do not expose POSIX signal handlers.
            pass

    logger.info("Durable scan worker started (max_jobs=%s, poll_seconds=%s)", max_jobs, poll_seconds)
    while not stop.is_set():
        try:
            result = await process_scan_queue(max_jobs=max_jobs)
            claimed = int(result.get("claimed_slots", 0) or 0)
            processed = int(result.get("processed", 0) or 0)
            logger.info(
                "Worker cycle complete (claimed=%s, processed=%s)",
                claimed, processed,
            )
            delay = 1 if claimed else poll_seconds
        except Exception as exc:
            logger.error("Worker cycle failed (error_type=%s)", type(exc).__name__)
            delay = min(300, poll_seconds * 2)

        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
        except asyncio.TimeoutError:
            pass

    logger.info("Durable scan worker stopped cleanly")


if __name__ == "__main__":
    asyncio.run(run_worker())
