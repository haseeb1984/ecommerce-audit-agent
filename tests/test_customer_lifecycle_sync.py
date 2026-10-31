from scan_worker import _lifecycle_action_applies


def test_stale_suspend_event_is_ignored_after_license_reactivation():
    assert not _lifecycle_action_applies("suspend", True)


def test_stale_reactivate_event_is_ignored_after_license_suspension():
    assert not _lifecycle_action_applies("reactivate", False)


def test_current_suspend_event_applies_only_to_inactive_license():
    assert _lifecycle_action_applies("suspend", False)
    assert not _lifecycle_action_applies("suspend", None)


def test_current_reactivate_event_applies_only_to_active_license():
    assert _lifecycle_action_applies("reactivate", True)
    assert not _lifecycle_action_applies("reactivate", None)


def test_explicit_session_revocation_is_independent_of_license_state():
    assert _lifecycle_action_applies("revoke_sessions", True)
    assert _lifecycle_action_applies("revoke_sessions", False)
    assert _lifecycle_action_applies("revoke_sessions", None)
