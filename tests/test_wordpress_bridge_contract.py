from pathlib import Path


def test_wordpress_shared_credential_dashboard_is_capability_gated():
    source = Path("wordpress/ai-ecommerce-audit-bridge/ai-ecommerce-audit-bridge.php").read_text()
    assert "apply_filters('aieab_dashboard_capability', 'manage_options')" in source
    assert source.count("current_user_can(self::dashboard_capability())") >= 2
    assert "You do not have permission to access this site audit account." in source
    assert "You are not allowed to use this site audit account." in source


def test_wordpress_dashboard_capability_filter_fails_back_to_manage_options():
    source = Path("wordpress/ai-ecommerce-audit-bridge/ai-ecommerce-audit-bridge.php").read_text()
    assert "is_string($capability) && trim($capability) !== '' ? trim($capability) : 'manage_options'" in source


def test_wordpress_white_label_form_is_plan_gated_and_rechecks_on_submit():
    source = Path("wordpress/ai-ecommerce-audit-bridge/ai-ecommerce-audit-bridge.php").read_text()
    assert "self::ACTION_SAVE_BRANDING" in source
    assert "($features['white_label_branding'] ?? false) === true" in source
    assert "wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['aieab_branding_nonce']))" in source
    assert "self::api_request('PUT', '/api/v1/account/branding'" in source
    assert "wp_parse_url($logo_url, PHP_URL_SCHEME) !== 'https'" in source
    assert "!preg_match('/^#[0-9A-F]{6}$/'" in source


def test_wordpress_api_request_preserves_license_header_with_json_content_type():
    source = Path("wordpress/ai-ecommerce-audit-bridge/ai-ecommerce-audit-bridge.php").read_text()
    assert "$request_args['headers'] = array_merge(" in source
    assert "$defaults['headers']" in source
    assert "isset($args['headers']) && is_array($args['headers']) ? $args['headers'] : []" in source


def test_wordpress_identity_linking_is_admin_only_nonce_protected_and_server_side():
    source = Path("wordpress/ai-ecommerce-audit-bridge/ai-ecommerce-audit-bridge.php").read_text()
    assert "ACTION_LINK_SITE" in source
    assert "admin_post_' . self::ACTION_LINK_SITE" in source
    assert "current_user_can('manage_options')" in source
    assert "wp_verify_nonce" in source
    assert "'/api/v1/account/wordpress-link/claim'" in source
    assert "'site_url' => home_url('/')" in source
    assert "'wp_user_id' => (int) $user->ID" in source
    assert "wp_get_current_user()" in source
    assert "ACTION_UNLINK_SITE" in source
    assert "'/api/v1/account/wordpress-link?site_url='" in source
