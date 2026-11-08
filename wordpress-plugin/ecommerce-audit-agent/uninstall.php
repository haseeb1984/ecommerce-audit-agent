<?php
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$settings = get_option('eaa_wp_settings', array());
$disconnect_failed = false;
$eaa_is_valid_api_base = static function ($value) {
    if (!is_string($value) || '' === trim($value) || false !== strpos($value, '\\')) {
        return false;
    }
    $parts = wp_parse_url(trim($value));
    return is_array($parts) && !empty($parts['host']) &&
        !array_key_exists('user', $parts) && !array_key_exists('pass', $parts) &&
        !array_key_exists('query', $parts) && !array_key_exists('fragment', $parts) &&
        wp_http_validate_url(trim($value)) &&
        'https' === strtolower((string) ($parts['scheme'] ?? ''));
};

if (is_array($settings) && !empty($settings['agency_site_token'])) {
    // Agency client sites use a separate revocable credential, not the owner's license key.
    // Never discard the only local copy until the SaaS confirms that it was revoked.
    $stored = (string) $settings['agency_site_token'];
    $agency_token = $stored;
    if (0 === strpos($stored, 'eaa2:')) {
        if (function_exists('openssl_decrypt')) {
            $packed = base64_decode(substr($stored, 5), true);
            if (false !== $packed && strlen($packed) > 28) {
                $agency_token = openssl_decrypt(
                    substr($packed, 28),
                    'aes-256-gcm',
                    hash('sha256', wp_salt('auth'), true),
                    OPENSSL_RAW_DATA,
                    substr($packed, 0, 12),
                    substr($packed, 12, 16)
                );
            } else {
                $agency_token = false;
            }
        } else {
            $agency_token = false;
        }
    }
    $api_base = !empty($settings['api_base']) ? untrailingslashit(esc_url_raw($settings['api_base'])) : 'https://ecommerce-audit-agent.vercel.app';
    if (!is_string($agency_token) || '' === $agency_token || !$eaa_is_valid_api_base($api_base)) {
        $disconnect_failed = true;
    } else {
        $response = wp_safe_remote_post($api_base . '/api/v1/integrations/wordpress/agency/sites/disconnect', array(
            'timeout' => 8,
            'redirection' => 0,
            'reject_unsafe_urls' => true,
            'sslverify' => true,
            'headers' => array(
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
                'X-Agency-Site-Token' => $agency_token,
            ),
            'body' => wp_json_encode(array()),
        ));
        $response_code = is_wp_error($response) ? 0 : (int) wp_remote_retrieve_response_code($response);
        if ($response_code < 200 || $response_code >= 300) {
            $disconnect_failed = true;
        }
    }
}

if (is_array($settings) && !empty($settings['site_id']) && !empty($settings['license_key'])) {
    $stored = (string) $settings['license_key'];
    $license = $stored;
    if (0 === strpos($stored, 'eaa2:')) {
        if (function_exists('openssl_decrypt')) {
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
        } else {
            // Do not send an encrypted value as though it were a license key.
            $license = false;
        }
    }
    $api_base = !empty($settings['api_base']) ? untrailingslashit(esc_url_raw($settings['api_base'])) : 'https://ecommerce-audit-agent.vercel.app';
    if (!is_string($license) || '' === $license || !$eaa_is_valid_api_base($api_base)) {
        $disconnect_failed = true;
    } else {
        $response = wp_safe_remote_post($api_base . '/api/v1/integrations/wordpress/sites/disconnect', array(
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
        $response_code = is_wp_error($response) ? 0 : (int) wp_remote_retrieve_response_code($response);
        if ($response_code < 200 || $response_code >= 300) {
            $disconnect_failed = true;
        }
    }
}

// A failed remote revocation must not strand an active SaaS connection by deleting
// its only credential. Reinstalling the plugin preserves the settings so disconnect
// can be retried; successful or unnecessary disconnects still clean up normally.
if (!$disconnect_failed) {
    delete_option('eaa_wp_settings');
}
