from pathlib import Path


PLUGIN = Path(
    "wordpress-plugin/ecommerce-audit-agent/ecommerce-audit-agent.php"
).read_text(encoding="utf-8")
UNINSTALL = Path(
    "wordpress-plugin/ecommerce-audit-agent/uninstall.php"
).read_text(encoding="utf-8")


def test_wordpress_api_base_requires_https_host_without_credentials_or_query():
    validator = PLUGIN[
        PLUGIN.index("function eaa_wp_is_valid_api_base"):
        PLUGIN.index("function eaa_wp_api_base")
    ]

    assert "wp_parse_url($value)" in validator
    assert "array_key_exists('user', $parts)" in validator
    assert "array_key_exists('pass', $parts)" in validator
    assert "array_key_exists('query', $parts)" in validator
    assert "array_key_exists('fragment', $parts)" in validator
    assert "wp_http_validate_url($value)" in validator
    assert "'https' === strtolower" in validator
    assert "strpos($value, '\\\\')" in validator


def test_wordpress_api_base_allows_reverse_proxy_path_prefixes():
    validator = PLUGIN[
        PLUGIN.index("function eaa_wp_is_valid_api_base"):
        PLUGIN.index("function eaa_wp_api_base")
    ]

    # A self-hosted reverse proxy may mount the API below a path prefix.
    assert "array_key_exists('path', $parts)" not in validator
    assert "isset($parts['path'])" not in validator


def test_saved_and_persisted_api_bases_share_the_same_validator():
    api_base = PLUGIN[
        PLUGIN.index("function eaa_wp_api_base"):
        PLUGIN.index("function eaa_wp_api_request")
    ]
    save_handler = PLUGIN[
        PLUGIN.index("function eaa_wp_handle_save_settings"):
        PLUGIN.index("add_action('admin_post_eaa_save_white_label'")
    ]

    assert "eaa_wp_is_valid_api_base($base)" in api_base
    assert "return EAA_WP_DEFAULT_API;" in api_base
    assert "eaa_wp_is_valid_api_base($api_base)" in save_handler


def test_uninstall_uses_equivalent_api_base_validation_before_both_disconnects():
    assert "$eaa_is_valid_api_base = static function ($value)" in UNINSTALL
    assert UNINSTALL.count("!$eaa_is_valid_api_base($api_base)") == 2
    assert "array_key_exists('query', $parts)" in UNINSTALL
    assert "array_key_exists('fragment', $parts)" in UNINSTALL
    assert "array_key_exists('user', $parts)" in UNINSTALL
    assert "array_key_exists('pass', $parts)" in UNINSTALL
