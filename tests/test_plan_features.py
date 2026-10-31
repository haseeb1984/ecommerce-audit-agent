from plan_features import plan_features


def test_starter_has_standard_audits_only():
    assert plan_features("starter") == {
        "standard_audits": True,
        "conversion_dossier": False,
        "white_label_branding": False,
        "direct_api_access": False,
    }


def test_pro_unlocks_conversion_dossier_but_not_white_label_or_direct_api():
    assert plan_features("pro") == {
        "standard_audits": True,
        "conversion_dossier": True,
        "white_label_branding": False,
        "direct_api_access": False,
    }


def test_business_unlocks_all_configured_features():
    assert all(plan_features("business").values())


def test_only_the_three_configured_package_names_are_recognized():
    for legacy_alias in ("agency", "agency_pro", "enterprise", "whitelabel", "white_label"):
        assert not any(plan_features(legacy_alias).values())


def test_unknown_tiers_fail_closed_and_missing_tier_keeps_legacy_starter_default():
    assert plan_features(None)["standard_audits"] is True
    assert not any(plan_features(""))
    assert not any(plan_features("unknown-plan"))
