from plan_features import plan_features


def test_starter_has_only_standard_audits():
    assert plan_features("starter") == {
        "standard_audits": True,
        "conversion_dossier": False,
        "white_label_branding": False,
        "direct_api_access": False,
    }


def test_agency_and_pro_unlock_dossier_only():
    for tier in ("agency", "pro", "agency_pro"):
        features = plan_features(tier)
        assert features["standard_audits"] is True
        assert features["conversion_dossier"] is True
        assert features["white_label_branding"] is False
        assert features["direct_api_access"] is False


def test_whitelabel_aliases_unlock_enterprise_features():
    for tier in ("whitelabel", "white_label", "enterprise"):
        features = plan_features(tier)
        assert all(features.values())


def test_unknown_or_missing_tiers_fail_closed():
    for tier in ("", None, "premium-plus", "unknown"):
        assert plan_features(tier) == {
            "standard_audits": False,
            "conversion_dossier": False,
            "white_label_branding": False,
            "direct_api_access": False,
        }
