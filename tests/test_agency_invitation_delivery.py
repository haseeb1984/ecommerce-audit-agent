import inspect

import main


def test_agency_invitation_smtp_delivery_runs_in_worker_thread():
    source = inspect.getsource(main.invite_business_agency_team_member)
    delivery = source.index("await asyncio.to_thread(")
    sender = source.index("_send_agency_invitation_email", delivery)
    failure_handler = source.index("except Exception as exc:", sender)

    assert delivery < sender < failure_handler
    assert "member.status = \"delivery_failed\"" in source[failure_handler:]
    assert "member.invitation_token_hash = None" in source[failure_handler:]
    assert "member.invitation_expires_at = None" in source[failure_handler:]


def test_agency_invitation_email_failure_does_not_leave_a_usable_token():
    source = inspect.getsource(main.invite_business_agency_team_member)
    failure_handler = source.index("except Exception as exc:", source.index("_send_agency_invitation_email"))

    failure_path = source[failure_handler:]
    assert "member.status = \"delivery_failed\"" in failure_path
    assert "member.invitation_token_hash = None" in failure_path
    assert "member.invitation_expires_at = None" in failure_path
    assert "await operational_db.commit()" in failure_path
