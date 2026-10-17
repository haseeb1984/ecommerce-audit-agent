#!/usr/bin/env python3
"""Run a real concurrent quota test against the deployed audit API.

This test intentionally sends simultaneous requests to two distinct, well-known domains.
"""
import os
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE_URL = os.getenv(
    "AUDIT_BASE_URL", "https://ecommerce-audit-agent.vercel.app"
).rstrip("/")
LICENSE_KEY = os.getenv("AUDIT_TEST_LICENSE_KEY", "").strip()
TEST_DOMAINS = ("google.com", "facebook.com")


def main() -> int:
    if not LICENSE_KEY:
        print("ERROR: AUDIT_TEST_LICENSE_KEY is missing.")
        return 2

    start = threading.Barrier(2)

    def send(request_number: int) -> tuple[int, int, str]:
        query = urllib.parse.urlencode({
            "domain": TEST_DOMAINS[request_number - 1],
            "source": "live_concurrency_test",
        })
        request = urllib.request.Request(
            f"{BASE_URL}/api/v1/audit-lead?{query}",
            method="POST",
            headers={"X-License-Key": LICENSE_KEY},
        )
        try:
            start.wait(timeout=10)
            with urllib.request.urlopen(request, timeout=180) as response:
                return request_number, response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return request_number, exc.code, exc.read().decode("utf-8", "replace")
        except Exception as exc:
            return request_number, 0, f"{type(exc).__name__}: {exc}"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(send, (1, 2)))

    for number, status, body in results:
        print(f"Request {number} | Domain: {TEST_DOMAINS[number - 1]} | HTTP: {status} | Response: {body}")

    statuses = sorted(status for _, status, _ in results)
    if statuses == [200, 429]:
        print("PASS: exactly one simultaneous request succeeded and one was quota-rejected.")
        return 0

    print(f"FAIL: expected one HTTP 200 and one HTTP 429; got {statuses}.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
