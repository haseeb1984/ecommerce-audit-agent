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

from sqlalchemy import inspect

from hostinger_database import HostingerAsyncSessionLocal, hostinger_engine
from hostinger_models import WebsiteScanJob
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


def _missing_required_columns(required: set[str], actual: set[str]) -> list[str]:
    """Return sorted queue columns absent from the live operational schema."""
    return sorted(required - actual)


async def validate_worker_schema() -> None:
    """Fail fast when the live queue table does not match this worker's model contract.

    Schema changes remain migration-managed; the worker never mutates production DDL.
    """
    if HostingerAsyncSessionLocal is None or hostinger_engine is None:
        raise RuntimeError("HOSTINGER_DATABASE_URL is required to run the durable scan worker.")

    async with hostinger_engine.connect() as connection:
        table_names = await connection.run_sync(
            lambda sync_connection: set(inspect(sync_connection).get_table_names())
        )
        if WebsiteScanJob.__tablename__ not in table_names:
            raise RuntimeError(
                "Operational scan queue table is missing; apply the Hostinger operational schema migration."
            )
        actual_columns = await connection.run_sync(
            lambda sync_connection: {
                column["name"]
                for column in inspect(sync_connection).get_columns(WebsiteScanJob.__tablename__)
            }
        )

    required_columns = {column.name for column in WebsiteScanJob.__table__.columns}
    missing = _missing_required_columns(required_columns, actual_columns)
    if missing:
        raise RuntimeError(
            "Operational scan queue schema is incompatible; apply the latest Hostinger scan queue migration. "
            f"Missing columns: {', '.join(missing)}"
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
            logger.info(
                "Worker cycle complete (claimed=%s, processed=%s)",
                claimed,
                processed,
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
