from pathlib import Path


def test_wordpress_dashboard_capability_is_configurable_and_defaults_to_admin():
    source = Path(
        "wordpress-plugin/ecommerce-audit-agent/ecommerce-audit-agent.php"
    ).read_text()
    assert "apply_filters('eaa_wp_dashboard_capability', 'manage_options')" in source
    assert "is_string($capability) && '' !== trim($capability) ? trim($capability) : 'manage_options'" in source
    assert "eaa_wp_dashboard_capability()," in source
    assert "current_user_can(eaa_wp_dashboard_capability())" in source
    assert "current_user_can('manage_options')" not in source


def test_wordpress_state_changing_handlers_use_the_same_capability_gate():
    source = Path(
        "wordpress-plugin/ecommerce-audit-agent/ecommerce-audit-agent.php"
    ).read_text()
    assert source.count("current_user_can(eaa_wp_dashboard_capability())") >= 9
    assert "wp_verify_nonce" in source
