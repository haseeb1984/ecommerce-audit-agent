"""Shared retry policy for durable cross-database outboxes."""


def outbox_retry_delay_seconds(attempts: int | None) -> int:
    """Return capped exponential retry delay shared by all cross-database outboxes.

    Persisted attempt counters are integers. Reject malformed values rather than
    silently truncating floats or accepting booleans as retry counts.
    """
    if attempts is None:
        normalized_attempts = 0
    elif isinstance(attempts, bool) or not isinstance(attempts, int):
        raise ValueError("Outbox retry attempts must be an integer.")
    else:
        normalized_attempts = max(0, attempts)
    # attempts is incremented before scheduling a retry: attempt 1 is
    # therefore the first retry and must receive the 30-second base delay.
    retry_exponent = min(max(normalized_attempts - 1, 0), 7)
    return min(3600, 30 * (2 ** retry_exponent))


def next_outbox_attempt_count(attempts: int | None) -> int:
    """Increment a persisted retry counter without coercing malformed values."""
    outbox_retry_delay_seconds(attempts)  # Validate the persisted representation first.
    return (0 if attempts is None else attempts) + 1
