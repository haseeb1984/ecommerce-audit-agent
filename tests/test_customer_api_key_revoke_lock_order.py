import inspect


def test_customer_api_key_revocation_uses_license_then_key_lock_order():
    import main

    source = inspect.getsource(main.revoke_account_api_key)
    auth_dependency = source.index("verify_customer_account_for_management")
    license_lock = source.index("SoftwareLicense.id == license_obj.id")
    key_lock = source.index("APIKey.id == key_id")
    delete_key = source.index("delete(APIKey)")
    commit = source.index("await db.commit()")

    assert auth_dependency < license_lock < key_lock < delete_key < commit
    assert ".with_for_update()" in source[license_lock:key_lock]
    assert ".with_for_update()" in source[key_lock:delete_key]
    assert "APIKey.license_id == client.id" in source[key_lock:delete_key]


def test_customer_api_key_revocation_is_tenant_scoped_and_rolls_back_missing_key():
    import inspect
    import main

    source = inspect.getsource(main.revoke_account_api_key)
    key_lookup = source.index("select(APIKey)")
    missing_key = source.index("if item is None:")
    delete_key = source.index("delete(APIKey)")

    assert "APIKey.id == key_id" in source[key_lookup:missing_key]
    assert "APIKey.license_id == client.id" in source[key_lookup:missing_key]
    assert "await db.rollback()" in source[missing_key:delete_key]
    assert 'detail="API key not found for this account."' in source[missing_key:delete_key]
