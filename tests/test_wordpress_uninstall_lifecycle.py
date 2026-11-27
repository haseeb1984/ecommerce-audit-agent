from pathlib import Path


UNINSTALL = Path(
    "wordpress-plugin/ecommerce-audit-agent/uninstall.php"
).read_text(encoding="utf-8")


def test_agency_plugin_uninstall_revokes_separate_site_credential():
    assert "!empty($settings['agency_site_token'])" in UNINSTALL
    assert "X-Agency-Site-Token" in UNINSTALL
    assert "/api/v1/integrations/wordpress/agency/sites/disconnect" in UNINSTALL
    assert "agency_token = openssl_decrypt(" in UNINSTALL
    assert "hash('sha256', wp_salt('auth'), true)" in UNINSTALL
    assert UNINSTALL.index("agency/sites/disconnect") < UNINSTALL.index("delete_option('eaa_wp_settings')")


def test_agency_uninstall_request_keeps_transport_restrictions():
    agency_disconnect = UNINSTALL[
        UNINSTALL.index("agency/sites/disconnect"):
        UNINSTALL.index("if (is_array($settings) && !empty($settings['site_id'])")
    ]
    assert "'timeout' => 8" in agency_disconnect
    assert "'redirection' => 0" in agency_disconnect
    assert "'reject_unsafe_urls' => true" in agency_disconnect
    assert "'sslverify' => true" in agency_disconnect
    assert "'https' === strtolower" in UNINSTALL


def test_standard_wordpress_uninstall_disconnect_is_preserved():
    assert "/api/v1/integrations/wordpress/sites/disconnect" in UNINSTALL
    assert "'X-License-Key' => $license" in UNINSTALL
    assert "'X-WordPress-Site-ID' => sanitize_text_field($settings['site_id'])" in UNINSTALL


def test_uninstall_retains_local_credentials_when_remote_disconnect_fails():
    assert "$disconnect_failed = false;" in UNINSTALL
    assert "is_wp_error($response) ? 0" in UNINSTALL
    assert "$response_code < 200 || $response_code >= 300" in UNINSTALL
    assert "if (!$disconnect_failed)" in UNINSTALL
    assert UNINSTALL.index("if (!$disconnect_failed)") < UNINSTALL.index("delete_option('eaa_wp_settings')")


def test_encrypted_standard_license_fails_closed_without_openssl():
    encrypted_branch = UNINSTALL[
        UNINSTALL.index("if (0 === strpos($stored, 'eaa2:'))", UNINSTALL.index("$stored = (string) $settings['license_key']")):
        UNINSTALL.index("$api_base =", UNINSTALL.index("$stored = (string) $settings['license_key']"))
    ]
    assert "$license = false;" in encrypted_branch
    assert "if (function_exists('openssl_decrypt'))" in encrypted_branch


def test_uninstall_only_treats_exact_disconnect_not_found_as_idempotent_success():
    assert "$eaa_is_already_disconnected = static function ($response, $expected_detail)" in UNINSTALL
    assert "is_wp_error($response) || 404 !== (int) wp_remote_retrieve_response_code($response)" in UNINSTALL
    assert "is_array($body) && isset($body['detail']) && $expected_detail === $body['detail']" in UNINSTALL
    assert "$eaa_is_already_disconnected($response, 'Agency WordPress connection not found.')" in UNINSTALL
    assert "$eaa_is_already_disconnected($response, 'WordPress site connection not found.')" in UNINSTALL
    assert UNINSTALL.count("$eaa_is_already_disconnected($response,") == 2


PLUGIN = Path(
    "wordpress-plugin/ecommerce-audit-agent/ecommerce-audit-agent.php"
).read_text(encoding="utf-8")


def test_runtime_disconnect_only_accepts_exact_idempotent_404_responses():
    helper = PLUGIN[
        PLUGIN.index("function eaa_wp_is_already_disconnected"):
        PLUGIN.index("function eaa_wp_disconnect_site")
    ]
    assert "if (!is_wp_error($response))" in helper
    assert "404 === (int) $error_data['status']" in helper
    assert "$expected_detail === $response->get_error_message()" in helper


def test_standard_and_agency_runtime_disconnects_retain_credentials_on_generic_404():
    disconnect = PLUGIN[
        PLUGIN.index("function eaa_wp_disconnect_site"):
        PLUGIN.index("add_action('admin_menu'")
    ]
    assert "!eaa_wp_is_already_disconnected($response, 'Agency WordPress connection not found.')" in disconnect
    assert "!eaa_wp_is_already_disconnected($response, 'WordPress site connection not found.')" in disconnect
    assert disconnect.count("if (is_wp_error($response) &&") == 2
    assert disconnect.index("return $response;") < disconnect.index("unset($settings['agency_site_token']")
    assert disconnect.index("return $response;", disconnect.index("unset($settings['agency_site_token']")) < disconnect.index("unset($settings['site_id']")
