<?php
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$settings = get_option('eaa_wp_settings', array());
if (is_array($settings) && !empty($settings['site_id']) && !empty($settings['license_key'])) {
    $stored = (string) $settings['license_key'];
    $license = $stored;
    if (0 === strpos($stored, 'eaa2:') && function_exists('openssl_decrypt')) {
        $packed = base64_decode(substr($stored, 5), true);
        if (false !== $packed && strlen($packed) > 28) {
            $license = openssl_decrypt(
                substr($packed, 28),
                'aes-256-gcm',
                hash('sha256', wp_salt('auth'), true),
                OPENSSL_RAW_DATA,
                substr($packed, 0, 12),
                substr($packed, 12, 16)
            );
        } else {
            $license = false;
        }
    }
    $api_base = !empty($settings['api_base']) ? untrailingslashit(esc_url_raw($settings['api_base'])) : 'https://ecommerce-audit-agent.vercel.app';
    if (is_string($license) && '' !== $license && wp_http_validate_url($api_base) &&
        'https' === strtolower((string) wp_parse_url($api_base, PHP_URL_SCHEME))) {
        wp_safe_remote_post($api_base . '/api/v1/integrations/wordpress/sites/disconnect', array(
            'timeout' => 8,
            'redirection' => 0,
            'reject_unsafe_urls' => true,
            'sslverify' => true,
            'headers' => array(
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
                'X-License-Key' => $license,
                'X-WordPress-Site-ID' => sanitize_text_field($settings['site_id']),
            ),
            'body' => wp_json_encode(array('site_id' => sanitize_text_field($settings['site_id']))),
        ));
    }
}
delete_option('eaa_wp_settings');
