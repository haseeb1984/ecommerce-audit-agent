"""Regression checks for agency suspension and OTP/session lock ordering."""

import inspect


def _endpoint(path):
    import main

    return next(
        route.endpoint
        for route in main.app.routes
        if getattr(route, "path", None) == path
    )


def test_agency_team_verification_locks_agency_before_challenge():
    source = inspect.getsource(_endpoint("/api/v1/agency/team/auth/verify-code"))
    candidate_read = source.index("candidate = await operational_db.scalar")
    agency_lock = source.index("AgencyAccount.id == candidate.agency_id")
    challenge_lock = source.index("AgencyTeamLoginChallenge.id == candidate.id")
    session_insert = source.index("operational_db.add(AgencyTeamSession")
    assert candidate_read < agency_lock < challenge_lock < session_insert
    assert ".with_for_update()" in source[agency_lock:challenge_lock]


def test_agency_team_code_issuance_serializes_with_admin_suspension():
    request_source = inspect.getsource(_endpoint("/api/v1/agency/team/auth/request-code"))
    admin_source = inspect.getsource(_endpoint("/api/v1/admin/agencies/{agency_id}"))
    agency_lock = request_source.index("AgencyAccount.id == candidate.agency_id")
    challenge_read = request_source.index("AgencyTeamLoginChallenge.email == email")
    admin_agency_lock = admin_source.index("AgencyAccount.id == agency_id")
    admin_challenge_revoke = admin_source.index("AgencyTeamLoginChallenge.agency_id == agency.id")
    assert agency_lock < challenge_read
    assert ".with_for_update()" in request_source[agency_lock:challenge_read]
    assert admin_agency_lock < admin_challenge_revoke
