from pathlib import Path


def test_wordpress_shared_credential_dashboard_is_capability_gated():
    source = Path("wordpress/ai-ecommerce-audit-bridge/ai-ecommerce-audit-bridge.php").read_text()
    assert "apply_filters('aieab_dashboard_capability', 'manage_options')" in source
    assert source.count("current_user_can(self::dashboard_capability())") == 2
    assert "You do not have permission to access this site audit account." in source
    assert "You are not allowed to use this site audit account." in source


def test_wordpress_dashboard_capability_filter_fails_back_to_manage_options():
    source = Path("wordpress/ai-ecommerce-audit-bridge/ai-ecommerce-audit-bridge.php").read_text()
    assert "is_string($capability) && trim($capability) !== '' ? trim($capability) : 'manage_options'" in source
