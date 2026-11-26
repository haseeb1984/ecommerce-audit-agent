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


def test_uninstall_treats_only_expected_site_not_found_404_as_idempotent_success():
    # A generic 404 (for example, a missing route or stale API base) must fail
    # closed so the only local revocation credential is not discarded.
    assert "$eaa_is_already_disconnected = static function" in UNINSTALL
    assert "Agency WordPress connection not found." in UNINSTALL
    assert "WordPress site connection not found." in UNINSTALL
    assert UNINSTALL.count("$eaa_is_already_disconnected($response,") == 2
    assert "json_decode((string) wp_remote_retrieve_body($response), true)" in UNINSTALL

def test_uninstall_only_treats_exact_disconnect_not_found_as_idempotent_success():
    assert "$eaa_is_already_disconnected = static function ($response, $expected_detail)" in UNINSTALL
    assert "is_wp_error($response) || 404 !== (int) wp_remote_retrieve_response_code($response)" in UNINSTALL
    assert "is_array($body) && isset($body['detail']) && $expected_detail === $body['detail']" in UNINSTALL
    assert "$eaa_is_already_disconnected($response, 'Agency WordPress connection not found.')" in UNINSTALL
    assert "$eaa_is_already_disconnected($response, 'WordPress site connection not found.')" in UNINSTALL
    assert UNINSTALL.count("$eaa_is_already_disconnected($response,") == 2
