"""Long-running worker process for the durable Hostinger scan queue.

Run with: python worker_service.py
The HTTP API remains in main.py; this process independently drains queued
website scans and the retryable PostgreSQL/Hostinger synchronization outboxes.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal

from scan_worker import ensure_scan_worker_schema, process_scan_queue


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


async def validate_worker_schema() -> None:
    """Validate every database model used by scan and reconciliation workers.

    The shared guard checks both Hostinger operational tables and PostgreSQL
    licensing/outbox tables before this process begins polling for customer work.
    Schema changes remain migration-managed; validation never mutates DDL.
    """
    await ensure_scan_worker_schema()


def _log_worker_cycle(result: dict, *, claimed: int, processed: int) -> None:
    """Log queue throughput and cross-database reconciliation health without payload data."""
    lifecycle = result.get("customer_lifecycle_sync") or {}
    identity = result.get("customer_email_identity_sync") or {}
    billing = result.get("billing_mirror_sync") or {}
    cleanup = result.get("authentication_cleanup") or {}
    logger.info(
        "Worker cycle complete "
        "(claimed=%s, processed=%s, "
        "lifecycle_processed=%s, lifecycle_deferred=%s, "
        "identity_processed=%s, identity_deferred=%s, "
        "billing_processed=%s, billing_deferred=%s, billing_discarded=%s, "
        "auth_cleanup_status=%s)",
        claimed,
        processed,
        int(lifecycle.get("processed", 0) or 0),
        int(lifecycle.get("deferred", 0) or 0),
        int(identity.get("processed", 0) or 0),
        int(identity.get("deferred", 0) or 0),
        int(billing.get("processed", 0) or 0),
        int(billing.get("deferred", 0) or 0),
        int(billing.get("discarded", 0) or 0),
        cleanup.get("status", "unknown"),
    )


async def run_worker() -> None:
    await validate_worker_schema()

    max_jobs = _bounded_int("SCAN_WORKER_MAX_JOBS", 1, 1, 10)
    poll_seconds = _bounded_int("SCAN_WORKER_POLL_SECONDS", 5, 1, 300)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            # Some managed runtimes do not expose POSIX signal handlers.
            pass

    logger.info(
        "Durable scan worker started (max_jobs=%s, poll_seconds=%s)",
        max_jobs,
        poll_seconds,
    )
    while not stop.is_set():
        try:
            result = await process_scan_queue(max_jobs=max_jobs)
            claimed = int(result.get("claimed_slots", 0) or 0)
            processed = int(result.get("processed", 0) or 0)
            _log_worker_cycle(result, claimed=claimed, processed=processed)
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
