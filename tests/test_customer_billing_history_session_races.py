from pathlib import Path
import inspect

import pytest


def test_customer_billing_history_new_session_supersedes_old_in_flight_load():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")
    start = portal.index("async function loadBillingHistory")
    end = portal.index("async function loadApiKeys", start)
    source = portal[start:end]

    assert "const requestSessionVersion = accountSessionVersion;" in source
    assert "billingLoadingSessionVersion === requestSessionVersion" in source
    assert "const requestVersion = ++billingRequestVersion;" in source
    stale_guard = source.index(
        "if (requestVersion !== billingRequestVersion || requestSessionVersion !== accountSessionVersion) return;"
    )
    account_render = source.index('$("billingAccount").textContent')
    assert stale_guard < account_render
    assert "requestVersion === billingRequestVersion && requestSessionVersion === accountSessionVersion" in source
    assert "if (requestVersion === billingRequestVersion)" in source
    assert "billingLoadingSessionVersion = -1;" in source


def test_customer_billing_history_uses_request_generation_state():
    portal = Path("customer_portal.html").read_text(encoding="utf-8")
    assert "let billingLoadingSessionVersion = -1;" in portal
    assert "let billingRequestVersion = 0;" in portal


class _AsyncValues:
    def __init__(self, values):
        self.values = iter(values)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self.values)
        except StopIteration:
            raise StopAsyncIteration


@pytest.mark.asyncio
async def test_billing_history_union_count_merges_sorted_streams_with_duplicates():
    from main import _count_sorted_billing_event_id_union

    total = await _count_sorted_billing_event_id_union(
        _AsyncValues(["evt-1", "evt-2", "evt-4", "evt-7"]),
        _AsyncValues(["evt-2", "evt-3", "evt-4", "evt-5"]),
    )

    assert total == 6


@pytest.mark.asyncio
async def test_billing_history_union_count_handles_empty_and_disjoint_streams():
    from main import _count_sorted_billing_event_id_union

    assert await _count_sorted_billing_event_id_union(_AsyncValues([]), _AsyncValues([])) == 0
    assert await _count_sorted_billing_event_id_union(
        _AsyncValues(["a", "c"]), _AsyncValues(["b", "d"])
    ) == 4

def test_billing_history_count_uses_separate_database_streams():
    from main import account_billing_history

    source = inspect.getsource(account_billing_history)
    assert "await db.stream_scalars(" in source
    assert "await operational_db.stream_scalars(" in source
    assert "_count_sorted_billing_event_id_union" in source
    assert "_billing_history_event_count_query" not in source

