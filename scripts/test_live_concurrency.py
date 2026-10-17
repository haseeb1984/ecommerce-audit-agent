#!/usr/bin/env python3
"""Run a real concurrent quota test against the deployed audit API.

Required environment:
  AUDIT_TEST_LICENSE_KEY  A dedicated, unused license with monthly quota=1.
Optional:
  AUDIT_BASE_URL          Defaults to https://ecommerce-audit-agent.vercel.app
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


def main() -> int:
    if not LICENSE_KEY:
        print("ERROR: Set AUDIT_TEST_LICENSE_KEY to a fresh, dedicated quota-1 license.")
        return 2

    start = threading.Barrier(2)

    def send(domain: str) -> tuple[str, int, str]:
        query = urllib.parse.urlencode({
            "domain": domain,
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
                return domain, response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return domain, exc.code, exc.read().decode("utf-8", "replace")
        except Exception as exc:
            return domain, 0, f"{type(exc).__name__}: {exc}"

    domains = ("concurrency-a.example", "concurrency-b.example")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(send, domains))

    for domain, status, body in results:
        print(f"Domain: {domain} | HTTP: {status} | Response: {body}")

    statuses = sorted(status for _, status, _ in results)
    if statuses == [200,  429]:
        print("PASS: exactly one concurrent request succeeded and one was quota-rejected.")
        return 0

    print(f"FAIL: expected one HTTP 200 and one HTTP 429; got {statuses}.")
    print("Use a fresh dedicated quota-1 license; do not reset a production customer's quota.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
