"""Admin WordPress disconnect lock-order regression contracts."""

import inspect

import main


def test_admin_wordpress_disconnect_locks_canonical_license_before_site():
    source = inspect.getsource(main.admin_unlink_client_wordpress_site)
    auth = source.index("_require_admin_key(request)")
    license_lock = source.index("SoftwareLicense.id == license_id")
    site_lock = source.index("select(WordPressInstallation)")
    challenge_revoke = source.index("update(WordPressSiteLinkChallenge)")
    operational_commit = source.index("await operational_db.commit()")
    audit_log = source.index("_write_admin_log(db")

    assert auth < license_lock < site_lock < challenge_revoke < operational_commit < audit_log
    assert ".with_for_update()" in source[license_lock:site_lock]
    assert "WordPressSiteLinkChallenge.license_key == client.license_key" in source[challenge_revoke:operational_commit]
    assert "WordPressSiteLinkChallenge.consumed_at.is_(None)" in source[challenge_revoke:operational_commit]
    assert ".values(consumed_at=now)" in source[challenge_revoke:operational_commit]


def test_admin_wordpress_disconnect_requires_reason_and_site_scope():
    source = inspect.getsource(main.admin_unlink_client_wordpress_site)
    assert "reason = payload.reason.strip()" in source
    assert "if not reason:" in source
    assert "WordPressInstallation.license_key == client.license_key" in source
    assert "WordPressInstallation.site_url == site_url" in source
