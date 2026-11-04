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
