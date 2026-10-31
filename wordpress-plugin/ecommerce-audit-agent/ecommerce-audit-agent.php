<?php
/**
 * Plugin Name: Ecommerce Audit Agent
 * Plugin URI: https://ecommerce-audit-agent.vercel.app/
 * Description: Connect your WordPress or WooCommerce store to Ecommerce Audit Agent, monitor your SaaS license, run audits, and retrieve saved reports.
 * Version: 1.0.0
 * Requires at least: 6.2
 * Requires PHP: 7.4
 * Author: Ecommerce Audit Agent
 * License: GPL-2.0-or-later
 * Text Domain: ecommerce-audit-agent
 */

if (!defined('ABSPATH')) {
    exit;
}

define('EAA_WP_VERSION', '1.0.0');
define('EAA_WP_OPTION', 'eaa_wp_settings');
define('EAA_WP_DEFAULT_API', 'https://ecommerce-audit-agent.vercel.app');

function eaa_wp_settings() {
    $settings = get_option(EAA_WP_OPTION, array());
    return is_array($settings) ? $settings : array();
}

function eaa_wp_encrypt_license($plain) {
    if (!function_exists('openssl_encrypt') || !function_exists('random_bytes')) {
        return new WP_Error('eaa_crypto_unavailable', __('This server needs OpenSSL and a secure random source to store the license safely.', 'ecommerce-audit-agent'));
    }
    try {
        $iv = random_bytes(12);
        $tag = '';
        $key = hash('sha256', wp_salt('auth'), true);
        $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if (false === $cipher || 16 !== strlen($tag)) {
            return new WP_Error('eaa_crypto_failed', __('The license key could not be encrypted.', 'ecommerce-audit-agent'));
        }
        return 'eaa2:' . base64_encode($iv . $tag . $cipher);
    } catch (Throwable $error) {
        return new WP_Error('eaa_crypto_failed', __('The license key could not be encrypted.', 'ecommerce-audit-agent'));
    }
}

function eaa_wp_decrypt_license($stored) {
    $stored = (string) $stored;
    if (0 !== strpos($stored, 'eaa2:')) {
        return $stored; // Backward compatibility for an older plain-text option.
    }
    if (!function_exists('openssl_decrypt')) {
        return new WP_Error('eaa_crypto_unavailable', __('OpenSSL is required to read the saved license key.', 'ecommerce-audit-agent'));
    }
    $packed = base64_decode(substr($stored, 5), true);
    if (false === $packed || strlen($packed) <= 28) {
        return new WP_Error('eaa_crypto_invalid', __('The saved license credential is damaged. Re-enter your license key.', 'ecommerce-audit-agent'));
    }
    $key = hash('sha256', wp_salt('auth'), true);
    $plain = openssl_decrypt(
        substr($packed, 28),
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        substr($packed, 0, 12),
        substr($packed, 12, 16)
    );
    if (false === $plain || '' === $plain) {
        return new WP_Error('eaa_crypto_invalid', __('The saved license credential cannot be decrypted. Re-enter your license key.', 'ecommerce-audit-agent'));
    }
    return $plain;
}

function eaa_wp_api_base() {
    $settings = eaa_wp_settings();
    $base = isset($settings['api_base']) ? untrailingslashit(esc_url_raw($settings['api_base'])) : EAA_WP_DEFAULT_API;
    if (!$base || !wp_http_validate_url($base) || 'https' !== strtolower((string) wp_parse_url($base, PHP_URL_SCHEME))) {
        return EAA_WP_DEFAULT_API;
    }
    return $base;
}

function eaa_wp_api_request($path, $method = 'GET', $body = null, $timeout = 25) {
    $settings = eaa_wp_settings();
    $license_key = isset($settings['license_key']) ? eaa_wp_decrypt_license($settings['license_key']) : '';
    if (is_wp_error($license_key)) {
        return $license_key;
    }
    $license_key = trim((string) $license_key);
    // Upgrade an older plaintext option to authenticated encryption on first use.
    if ('' !== $license_key && 0 !== strpos((string) ($settings['license_key'] ?? ''), 'eaa2:')) {
        $encrypted = eaa_wp_encrypt_license($license_key);
        if (is_wp_error($encrypted)) {
            return $encrypted;
        }
        $settings['license_key'] = $encrypted;
        update_option(EAA_WP_OPTION, $settings, false);
    }
    if ('' === $license_key) {
        return new WP_Error('eaa_missing_license', __('Enter your SaaS license key to connect this site.', 'ecommerce-audit-agent'));
    }
    $url = eaa_wp_api_base() . '/' . ltrim($path, '/');
    $args = array(
        'method' => strtoupper($method),
        'timeout' => max(5, min(60, (int) $timeout)),
        'redirection' => 0,
        'reject_unsafe_urls' => true,
        'sslverify' => true,
        'headers' => array(
            'Accept' => 'application/json, application/pdf',
            'X-License-Key' => $license_key,
            'User-Agent' => 'EcommerceAuditAgentWordPress/' . EAA_WP_VERSION,
        ),
    );
    if (!empty($settings['site_id'])) {
        $args['headers']['X-WordPress-Site-ID'] = sanitize_text_field($settings['site_id']);
    }
    if (null !== $body) {
        $args['headers']['Content-Type'] = 'application/json';
        $args['body'] = wp_json_encode($body);
    }
    $response = wp_safe_remote_request($url, $args);
    if (is_wp_error($response)) {
        return new WP_Error('eaa_connection_error', __('Could not connect to Ecommerce Audit Agent. Check the API URL and your server outbound HTTPS access.', 'ecommerce-audit-agent'));
    }
    $code = (int) wp_remote_retrieve_response_code($response);
    if ($code < 200 || $code >= 300) {
        $raw = wp_remote_retrieve_body($response);
        $decoded = json_decode($raw, true);
        $message = is_array($decoded) && !empty($decoded['detail']) && is_string($decoded['detail'])
            ? sanitize_text_field($decoded['detail'])
            : sprintf(__('The SaaS API returned HTTP %d.', 'ecommerce-audit-agent'), $code);
        return new WP_Error('eaa_api_error', $message, array('status' => $code));
    }
    return $response;
}

function eaa_wp_agency_api_request($path, $method = 'GET', $body = null, $token = '', $header = 'X-Agency-Site-Token') {
    $token = trim((string) $token);
    if ('' === $token || strlen($token) > 200) {
        return new WP_Error('eaa_agency_token_missing', __('An agency connection token is required.', 'ecommerce-audit-agent'));
    }
    $url = eaa_wp_api_base() . '/' . ltrim($path, '/');
    $args = array(
        'method' => strtoupper($method),
        'timeout' => 25,
        'redirection' => 0,
        'reject_unsafe_urls' => true,
        'sslverify' => true,
        'headers' => array(
            'Accept' => 'application/json',
            $header => $token,
            'User-Agent' => 'EcommerceAuditAgentWordPress/' . EAA_WP_VERSION,
        ),
    );
    if (null !== $body) {
        $args['headers']['Content-Type'] = 'application/json';
        $args['body'] = wp_json_encode($body);
    }
    $response = wp_safe_remote_request($url, $args);
    if (is_wp_error($response)) {
        return new WP_Error('eaa_agency_connection_error', __('Could not connect securely to the agency SaaS API.', 'ecommerce-audit-agent'));
    }
    $code = (int) wp_remote_retrieve_response_code($response);
    if ($code < 200 || $code >= 300) {
        $decoded = json_decode(wp_remote_retrieve_body($response), true);
        $message = is_array($decoded) && !empty($decoded['detail']) && is_string($decoded['detail'])
            ? sanitize_text_field($decoded['detail'])
            : sprintf(__('The agency SaaS API returned HTTP %d.', 'ecommerce-audit-agent'), $code);
        return new WP_Error('eaa_agency_api_error', $message, array('status' => $code));
    }
    return $response;
}

function eaa_wp_register_agency_site($one_time_token) {
    $payload = array(
        'site_url' => home_url('/'),
        'admin_email' => get_option('admin_email'),
        'wordpress_version' => get_bloginfo('version'),
        'woocommerce_version' => defined('WC_VERSION') ? WC_VERSION : '',
        'plugin_version' => EAA_WP_VERSION,
    );
    $response = eaa_wp_agency_api_request(
        '/api/v1/integrations/wordpress/agency/sites/register',
        'POST',
        $payload,
        $one_time_token,
        'X-Agency-Connect-Token'
    );
    if (is_wp_error($response)) {
        return $response;
    }
    $data = eaa_wp_json($response);
    if (empty($data['site_id']) || empty($data['agency_site_token'])) {
        return new WP_Error('eaa_agency_registration_invalid', __('The agency API did not return a complete site credential.', 'ecommerce-audit-agent'));
    }
    $encrypted = eaa_wp_encrypt_license(sanitize_text_field($data['agency_site_token']));
    if (is_wp_error($encrypted)) {
        return $encrypted;
    }
    $settings = eaa_wp_settings();
    $settings['agency_site_token'] = $encrypted;
    $settings['agency_site_id'] = sanitize_text_field($data['site_id']);
    $settings['agency_workspace_id'] = sanitize_text_field($data['workspace_id']);
    $settings['agency_workspace_name'] = sanitize_text_field($data['workspace_name']);
    $settings['agency_site_url'] = esc_url_raw($data['site_url']);
    $settings['agency_connected_at'] = sanitize_text_field($data['connected_at']);
    $settings['connection_error'] = '';
    update_option(EAA_WP_OPTION, $settings, false);
    return $data;
}

function eaa_wp_json($response) {
    $decoded = json_decode(wp_remote_retrieve_body($response), true);
    return is_array($decoded) ? $decoded : array();
}

function eaa_wp_register_site() {
    $payload = array(
        'site_url' => home_url('/'),
        'admin_email' => get_option('admin_email'),
        'wordpress_version' => get_bloginfo('version'),
        'woocommerce_version' => defined('WC_VERSION') ? WC_VERSION : '',
        'plugin_version' => EAA_WP_VERSION,
    );
    $response = eaa_wp_api_request('/api/v1/integrations/wordpress/sites/register', 'POST', $payload);
    if (is_wp_error($response)) {
        return $response;
    }
    $data = eaa_wp_json($response);
    if (empty($data['site_id'])) {
        return new WP_Error('eaa_invalid_registration', __('The SaaS API did not return a site connection identifier.', 'ecommerce-audit-agent'));
    }
    $settings = eaa_wp_settings();
    $settings['site_id'] = sanitize_text_field($data['site_id']);
    $settings['connected_at'] = isset($data['connected_at']) ? sanitize_text_field($data['connected_at']) : current_time('mysql', true);
    $settings['connection_error'] = '';
    update_option(EAA_WP_OPTION, $settings, false);
    return $data;
}

function eaa_wp_disconnect_site() {
    $settings = eaa_wp_settings();
    if (!empty($settings['agency_site_token'])) {
        $token = eaa_wp_decrypt_license($settings['agency_site_token']);
        if (is_wp_error($token)) {
            return $token;
        }
        $response = eaa_wp_agency_api_request('/api/v1/integrations/wordpress/agency/sites/disconnect', 'POST', array(), $token);
        if (is_wp_error($response)) {
            $error_data = $response->get_error_data();
            $http_status = is_array($error_data) && isset($error_data['status']) ? (int) $error_data['status'] : 0;
            if (404 !== $http_status) return $response;
        }
        unset($settings['agency_site_token'], $settings['agency_site_id'], $settings['agency_workspace_id'],
              $settings['agency_workspace_name'], $settings['agency_site_url'], $settings['agency_connected_at']);
        update_option(EAA_WP_OPTION, $settings, false);
        return true;
    }
    $settings = eaa_wp_settings();
    if (empty($settings['site_id'])) {
        return true;
    }
    $response = eaa_wp_api_request('/api/v1/integrations/wordpress/sites/disconnect', 'POST', array(
        'site_id' => sanitize_text_field($settings['site_id']),
    ));
    if (is_wp_error($response)) {
        $error_data = $response->get_error_data();
        $http_status = is_array($error_data) && isset($error_data['status']) ? (int) $error_data['status'] : 0;
        // A 404 means the remote installation is already disconnected.
        if (404 !== $http_status) {
            return $response;
        }
    }
    unset($settings['site_id'], $settings['connected_at'], $settings['last_status']);
    update_option(EAA_WP_OPTION, $settings, false);
    return true;
}

add_action('admin_menu', function () {
    add_menu_page(
        __('Ecommerce Audit Agent', 'ecommerce-audit-agent'),
        __('Ecommerce Audit', 'ecommerce-audit-agent'),
        'manage_options',
        'ecommerce-audit-agent',
        'eaa_wp_render_admin_page',
        'dashicons-chart-area',
        58
    );
});

function eaa_wp_sync_site_status() {
    $settings = eaa_wp_settings();
    if (empty($settings['license_key']) || empty($settings['site_id'])) {
        return;
    }
    $response = eaa_wp_api_request('/api/v1/integrations/wordpress/sites/status?site_id=' . rawurlencode($settings['site_id']));
    $settings['last_sync'] = time();
    if (is_wp_error($response)) {
        $error_data = $response->get_error_data();
        $http_status = is_array($error_data) && isset($error_data['status']) ? (int) $error_data['status'] : 0;
        if (404 === $http_status) {
            // The SaaS customer portal can disconnect this site remotely.
            unset($settings['site_id'], $settings['connected_at'], $settings['last_status']);
            $settings['connection_error'] = __('This site was disconnected from your SaaS account. Save settings to connect it again.', 'ecommerce-audit-agent');
        } else {
            $settings['connection_error'] = $response->get_error_message();
        }
    } else {
        $settings['connection_error'] = '';
        $settings['last_status'] = eaa_wp_json($response);
    }
    update_option(EAA_WP_OPTION, $settings, false);
}

add_action('eaa_wp_scheduled_status_sync', 'eaa_wp_sync_site_status');
register_activation_hook(__FILE__, function () {
    if (!wp_next_scheduled('eaa_wp_scheduled_status_sync')) {
        wp_schedule_event(time() + 300, 'twicedaily', 'eaa_wp_scheduled_status_sync');
    }
    $settings = eaa_wp_settings();
    if (!empty($settings['license_key'])) {
        $registration = eaa_wp_register_site();
        if (is_wp_error($registration)) {
            $settings = eaa_wp_settings();
            $settings['connection_error'] = $registration->get_error_message();
            update_option(EAA_WP_OPTION, $settings, false);
        }
    }
});
register_deactivation_hook(__FILE__, function () {
    $timestamp = wp_next_scheduled('eaa_wp_scheduled_status_sync');
    if ($timestamp) {
        wp_unschedule_event($timestamp, 'eaa_wp_scheduled_status_sync');
    }
});
add_action('admin_init', function () {
    if (!wp_next_scheduled('eaa_wp_scheduled_status_sync')) {
        wp_schedule_event(time() + 300, 'twicedaily', 'eaa_wp_scheduled_status_sync');
    }
});

add_action('admin_post_eaa_connect_agency_site', 'eaa_wp_handle_connect_agency_site');
function eaa_wp_handle_connect_agency_site() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to manage this integration.', 'ecommerce-audit-agent'), 403);
    }
    check_admin_referer('eaa_connect_agency_site');
    $token = isset($_POST['agency_connect_token']) ? sanitize_text_field(wp_unslash($_POST['agency_connect_token'])) : '';
    if (strlen($token) < 32 || strlen($token) > 200) {
        wp_safe_redirect(add_query_arg(array('page' => 'ecommerce-audit-agent', 'eaa_notice' => 'agency_connect_failed'), admin_url('admin.php')));
        exit;
    }
    $result = eaa_wp_register_agency_site($token);
    if (is_wp_error($result)) {
        $settings = eaa_wp_settings();
        $settings['connection_error'] = $result->get_error_message();
        update_option(EAA_WP_OPTION, $settings, false);
        wp_safe_redirect(add_query_arg(array('page' => 'ecommerce-audit-agent', 'eaa_notice' => 'agency_connect_failed'), admin_url('admin.php')));
        exit;
    }
    wp_safe_redirect(add_query_arg(array('page' => 'ecommerce-audit-agent', 'eaa_notice' => 'agency_connected'), admin_url('admin.php')));
    exit;
}

add_action('admin_post_eaa_save_settings', 'eaa_wp_handle_save_settings');
function eaa_wp_handle_save_settings() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to manage this integration.', 'ecommerce-audit-agent'), 403);
    }
    check_admin_referer('eaa_save_settings');
    $settings = eaa_wp_settings();
    $license_input = isset($_POST['license_key']) ? sanitize_text_field(wp_unslash($_POST['license_key'])) : '';
    $stored_license = isset($settings['license_key']) ? (string) $settings['license_key'] : '';
    $license = '' !== trim($license_input) ? trim($license_input) : eaa_wp_decrypt_license($stored_license);
    if (is_wp_error($license)) {
        $settings['connection_error'] = $license->get_error_message();
        update_option(EAA_WP_OPTION, $settings, false);
        wp_safe_redirect(add_query_arg(array('page' => 'ecommerce-audit-agent', 'eaa_notice' => 'connection_failed'), admin_url('admin.php')));
        exit;
    }
    $api_base = isset($_POST['api_base']) ? esc_url_raw(trim(wp_unslash($_POST['api_base']))) : EAA_WP_DEFAULT_API;
    $scheme = strtolower((string) wp_parse_url($api_base, PHP_URL_SCHEME));
    if (!$api_base || !wp_http_validate_url($api_base) || 'https' !== $scheme) {
        $settings['connection_error'] = __('The API URL must be a valid HTTPS URL.', 'ecommerce-audit-agent');
        update_option(EAA_WP_OPTION, $settings, false);
        wp_safe_redirect(add_query_arg(array('page' => 'ecommerce-audit-agent', 'eaa_notice' => 'invalid_url'), admin_url('admin.php')));
        exit;
    }

    // A site registration belongs to both the saved license and API endpoint.
    // Retire the old remote registration before replacing either credential so
    // license changes cannot leave orphaned active WordPress installations.
    $old_license = '' !== $stored_license ? eaa_wp_decrypt_license($stored_license) : '';
    if (is_wp_error($old_license)) {
        $settings['connection_error'] = $old_license->get_error_message();
        update_option(EAA_WP_OPTION, $settings, false);
        wp_safe_redirect(add_query_arg(array('page' => 'ecommerce-audit-agent', 'eaa_notice' => 'connection_failed'), admin_url('admin.php')));
        exit;
    }
    $old_api_base = isset($settings['api_base']) ? untrailingslashit((string) $settings['api_base']) : EAA_WP_DEFAULT_API;
    $new_api_base = untrailingslashit($api_base);
    $registration_identity_changed = !hash_equals((string) $old_license, (string) $license)
        || !hash_equals($old_api_base, $new_api_base);
    if (!empty($settings['site_id']) && $registration_identity_changed) {
        $disconnect = eaa_wp_disconnect_site();
        if (is_wp_error($disconnect)) {
            $settings = eaa_wp_settings();
            $settings['connection_error'] = __('The previous WordPress connection could not be retired. Settings were not changed; retry after restoring API connectivity.', 'ecommerce-audit-agent');
            update_option(EAA_WP_OPTION, $settings, false);
            wp_safe_redirect(add_query_arg(array('page' => 'ecommerce-audit-agent', 'eaa_notice' => 'disconnect_failed'), admin_url('admin.php')));
            exit;
        }
        $settings = eaa_wp_settings();
    }
    if ('' !== trim($license_input)) {
        $encrypted_license = eaa_wp_encrypt_license($license);
        if (is_wp_error($encrypted_license)) {
            $settings['connection_error'] = $encrypted_license->get_error_message();
            update_option(EAA_WP_OPTION, $settings, false);
            wp_safe_redirect(add_query_arg(array('page' => 'ecommerce-audit-agent', 'eaa_notice' => 'connection_failed'), admin_url('admin.php')));
            exit;
        }
        $settings['license_key'] = $encrypted_license;
    } elseif ('' === trim((string) $license)) {
        $settings['license_key'] = '';
    }
    $settings['api_base'] = untrailingslashit($api_base);
    $settings['brand_name'] = isset($_POST['brand_name']) ? sanitize_text_field(wp_unslash($_POST['brand_name'])) : '';
    $settings['brand_color'] = isset($_POST['brand_color']) ? sanitize_hex_color(wp_unslash($_POST['brand_color'])) : '';
    $settings['connection_error'] = '';
    update_option(EAA_WP_OPTION, $settings, false);
    if ('' !== $license) {
        $result = eaa_wp_register_site();
        if (is_wp_error($result)) {
            $settings = eaa_wp_settings();
            $settings['connection_error'] = $result->get_error_message();
            update_option(EAA_WP_OPTION, $settings, false);
            wp_safe_redirect(add_query_arg(array('page' => 'ecommerce-audit-agent', 'eaa_notice' => 'connection_failed'), admin_url('admin.php')));
            exit;
        }
    } else {
        unset($settings['site_id'], $settings['connected_at']);
        update_option(EAA_WP_OPTION, $settings, false);
    }
    wp_safe_redirect(add_query_arg(array('page' => 'ecommerce-audit-agent', 'eaa_notice' => 'saved'), admin_url('admin.php')));
    exit;
}

add_action('admin_post_eaa_save_white_label', 'eaa_wp_handle_save_white_label');
function eaa_wp_handle_save_white_label() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to manage this integration.', 'ecommerce-audit-agent'), 403);
    }
    check_admin_referer('eaa_save_white_label');
    $brand_name = isset($_POST['white_label_brand_name']) ? sanitize_text_field(wp_unslash($_POST['white_label_brand_name'])) : '';
    $logo_url = isset($_POST['white_label_logo_url']) ? esc_url_raw(trim(wp_unslash($_POST['white_label_logo_url']))) : '';
    $primary_color = isset($_POST['white_label_primary_color']) ? sanitize_hex_color(wp_unslash($_POST['white_label_primary_color'])) : '';
    if ('' === trim($brand_name) || !$primary_color || ('' !== $logo_url && 'https' !== strtolower((string) wp_parse_url($logo_url, PHP_URL_SCHEME)))) {
        wp_safe_redirect(add_query_arg(array('page' => 'ecommerce-audit-agent', 'eaa_notice' => 'branding_invalid'), admin_url('admin.php')));
        exit;
    }
    $result = eaa_wp_api_request('/api/v1/account/branding', 'PUT', array(
        'brand_name' => $brand_name,
        'logo_url' => '' !== $logo_url ? $logo_url : null,
        'primary_color' => $primary_color,
    ));
    $notice = is_wp_error($result) ? 'branding_failed' : 'branding_saved';
    wp_safe_redirect(add_query_arg(array('page' => 'ecommerce-audit-agent', 'eaa_notice' => $notice), admin_url('admin.php')));
    exit;
}

add_action('admin_post_eaa_disconnect_site', 'eaa_wp_handle_disconnect');
function eaa_wp_handle_disconnect() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to manage this integration.', 'ecommerce-audit-agent'), 403);
    }
    check_admin_referer('eaa_disconnect_site');
    $result = eaa_wp_disconnect_site();
    $notice = is_wp_error($result) ? 'disconnect_failed' : 'disconnected';
    wp_safe_redirect(add_query_arg(array('page' => 'ecommerce-audit-agent', 'eaa_notice' => $notice), admin_url('admin.php')));
    exit;
}

add_action('admin_post_eaa_run_audit', 'eaa_wp_handle_run_audit');
function eaa_wp_handle_run_audit() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to run audits.', 'ecommerce-audit-agent'), 403);
    }
    check_admin_referer('eaa_run_audit');
    $settings = eaa_wp_settings();
    if (empty($settings['site_id'])) {
        wp_die(esc_html__('Connect a valid license before running an audit.', 'ecommerce-audit-agent'), 400);
    }
    $domain = isset($_POST['domain']) ? esc_url_raw(trim(wp_unslash($_POST['domain']))) : '';
    if (!$domain || !wp_http_validate_url($domain) || !in_array(strtolower((string) wp_parse_url($domain, PHP_URL_SCHEME)), array('http', 'https'), true)) {
        wp_die(esc_html__('Enter a valid public website URL.', 'ecommerce-audit-agent'), 422);
    }
    $response = eaa_wp_api_request('/api/v1/comprehensive-audit?domain=' . rawurlencode($domain), 'POST', null, 60);
    if (is_wp_error($response)) {
        wp_die(esc_html($response->get_error_message()), 502);
    }
    $type = strtolower((string) wp_remote_retrieve_header($response, 'content-type'));
    $pdf = wp_remote_retrieve_body($response);
    if (false === strpos($type, 'application/pdf') || 0 !== strpos($pdf, '%PDF-') || strlen($pdf) > 20 * MB_IN_BYTES) {
        wp_die(esc_html__('The audit service did not return a valid PDF report. Please try again.', 'ecommerce-audit-agent'), 502);
    }
    nocache_headers();
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="ecommerce-audit-' . gmdate('Ymd-His') . '.pdf"');
    header('X-Content-Type-Options: nosniff');
    header('Content-Length: ' . strlen($pdf));
    echo $pdf; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- validated PDF bytes.
    exit;
}

add_action('admin_post_eaa_download_report', 'eaa_wp_handle_download_report');
function eaa_wp_handle_download_report() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to download reports.', 'ecommerce-audit-agent'), 403);
    }
    $report_id = isset($_GET['report_id']) ? absint($_GET['report_id']) : 0;
    check_admin_referer('eaa_download_report_' . $report_id);
    if (!$report_id) {
        wp_die(esc_html__('Invalid report identifier.', 'ecommerce-audit-agent'), 422);
    }
    $response = eaa_wp_api_request('/api/v1/reports/' . $report_id . '/pdf', 'GET', null, 60);
    if (is_wp_error($response)) {
        wp_die(esc_html($response->get_error_message()), 502);
    }
    $type = strtolower((string) wp_remote_retrieve_header($response, 'content-type'));
    $pdf = wp_remote_retrieve_body($response);
    if (false === strpos($type, 'application/pdf') || 0 !== strpos($pdf, '%PDF-') || strlen($pdf) > 20 * MB_IN_BYTES) {
        wp_die(esc_html__('The report service did not return a valid PDF.', 'ecommerce-audit-agent'), 502);
    }
    nocache_headers();
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="ecommerce-audit-report-' . $report_id . '.pdf"');
    header('X-Content-Type-Options: nosniff');
    header('Content-Length: ' . strlen($pdf));
    echo $pdf; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- validated PDF bytes.
    exit;
}

add_action('admin_post_eaa_open_billing', 'eaa_wp_handle_open_billing');
function eaa_wp_handle_open_billing() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to manage billing.', 'ecommerce-audit-agent'), 403);
    }
    check_admin_referer('eaa_open_billing');
    $response = eaa_wp_api_request('/api/v1/account/billing-portal', 'POST', array());
    if (is_wp_error($response)) {
        wp_die(esc_html($response->get_error_message()), 502);
    }
    $data = eaa_wp_json($response);
    $url = isset($data['portal_url']) ? esc_url_raw($data['portal_url']) : '';
    $host = strtolower((string) wp_parse_url($url, PHP_URL_HOST));
    if ('https' !== strtolower((string) wp_parse_url($url, PHP_URL_SCHEME)) || !preg_match('/(^|\.)paddle\.com$/', $host)) {
        wp_die(esc_html__('The billing provider returned an invalid portal URL.', 'ecommerce-audit-agent'), 502);
    }
    wp_redirect($url, 303); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- HTTPS Paddle URL is allowlisted above.
    exit;
}

function eaa_wp_render_admin_page() {
    if (!current_user_can('manage_options')) {
        return;
    }
    $settings = eaa_wp_settings();
    $notice = isset($_GET['eaa_notice']) ? sanitize_key(wp_unslash($_GET['eaa_notice'])) : '';
    $usage = null;
    $reports = array();
    $billing = null;
    $branding = null;
    $error = isset($settings['connection_error']) ? $settings['connection_error'] : '';
    if (!empty($settings['site_id']) && '' === $error) {
        $status_response = eaa_wp_api_request('/api/v1/integrations/wordpress/sites/status?site_id=' . rawurlencode($settings['site_id']));
        if (!is_wp_error($status_response)) {
            $settings['last_status'] = eaa_wp_json($status_response);
            $settings['connection_error'] = '';
            update_option(EAA_WP_OPTION, $settings, false);
        } else {
            $error_data = $status_response->get_error_data();
            $http_status = is_array($error_data) && isset($error_data['status']) ? (int) $error_data['status'] : 0;
            if (404 === $http_status) {
                // Reflect a customer-portal disconnect immediately when the
                // administrator opens this screen, not only on the next cron.
                unset($settings['site_id'], $settings['connected_at'], $settings['last_status']);
                $settings['connection_error'] = __('This site was disconnected from your SaaS account. Save settings to connect it again.', 'ecommerce-audit-agent');
                update_option(EAA_WP_OPTION, $settings, false);
                $error = $settings['connection_error'];
            } else {
                $error = $status_response->get_error_message();
            }
        }
        $usage_response = eaa_wp_api_request('/api/v1/account/usage');
        if (!is_wp_error($usage_response)) {
            $usage = eaa_wp_json($usage_response);
        }
        if (is_array($usage) && !empty($usage['features']['white_label_branding'])) {
            $branding_response = eaa_wp_api_request('/api/v1/account/branding');
            if (!is_wp_error($branding_response)) {
                $branding = eaa_wp_json($branding_response);
            }
        }
        $billing_response = eaa_wp_api_request('/api/v1/account/billing-history?limit=5&offset=0');
        if (!is_wp_error($billing_response)) {
            $billing = eaa_wp_json($billing_response);
        }
        $report_response = eaa_wp_api_request('/api/v1/reports?limit=10&offset=0');
        if (!is_wp_error($report_response)) {
            $report_data = eaa_wp_json($report_response);
            $reports = isset($report_data['reports']) && is_array($report_data['reports']) ? $report_data['reports'] : array();
        }
    }
    $connected = !empty($settings['site_id']) && '' === $error;
    $brand = !empty($settings['brand_name']) ? $settings['brand_name'] : __('Ecommerce Audit Agent', 'ecommerce-audit-agent');
    $color = !empty($settings['brand_color']) ? $settings['brand_color'] : '#1d4ed8';
    ?>
    <div class="wrap">
        <h1><?php echo esc_html($brand); ?></h1>
        <?php if ('saved' === $notice) : ?><div class="notice notice-success is-dismissible"><p><?php esc_html_e('Settings saved and site connected.', 'ecommerce-audit-agent'); ?></p></div><?php endif; ?>
        <?php if ('disconnected' === $notice) : ?><div class="notice notice-success is-dismissible"><p><?php esc_html_e('WordPress site disconnected. Your SaaS license and reports remain intact.', 'ecommerce-audit-agent'); ?></p></div><?php endif; ?>
        <?php if ('' !== $error) : ?><div class="notice notice-error"><p><?php echo esc_html($error); ?></p></div><?php endif; ?>
        <?php if ('invalid_url' === $notice) : ?><div class="notice notice-error"><p><?php esc_html_e('The API URL must use HTTPS.', 'ecommerce-audit-agent'); ?></p></div><?php endif; ?>
        <?php if ('branding_saved' === $notice) : ?><div class="notice notice-success is-dismissible"><p><?php esc_html_e('White-label branding saved to your SaaS account.', 'ecommerce-audit-agent'); ?></p></div><?php endif; ?>
        <?php if ('branding_failed' === $notice || 'branding_invalid' === $notice) : ?><div class="notice notice-error"><p><?php esc_html_e('White-label branding could not be saved. Check your plan eligibility and HTTPS logo URL.', 'ecommerce-audit-agent'); ?></p></div><?php endif; ?>
        <?php if ('connection_failed' === $notice || 'disconnect_failed' === $notice) : ?><div class="notice notice-error"><p><?php esc_html_e('The SaaS connection action could not be completed. Review the connection message and retry.', 'ecommerce-audit-agent'); ?></p></div><?php endif; ?>
        <style>
            .eaa-wrap{max-width:1100px}.eaa-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;margin:18px 0}.eaa-card{background:#fff;border:1px solid #dcdcde;border-radius:8px;padding:18px}.eaa-card h2{margin-top:0}.eaa-stat{font-size:28px;font-weight:700}.eaa-primary{background:<?php echo esc_attr($color); ?>!important;border-color:<?php echo esc_attr($color); ?>!important}
        </style>
        <div class="eaa-wrap">
            <div class="eaa-grid">
                <div class="eaa-card">
                    <h2><?php esc_html_e('SaaS connection', 'ecommerce-audit-agent'); ?></h2>
                    <p><strong><?php echo $connected ? esc_html__('Connected', 'ecommerce-audit-agent') : esc_html__('Not connected', 'ecommerce-audit-agent'); ?></strong></p>
                    <?php if ($connected) : ?>
                        <p><?php esc_html_e('Site:', 'ecommerce-audit-agent'); ?> <?php echo esc_html(home_url('/')); ?></p>
                        <p><?php esc_html_e('WordPress site ID:', 'ecommerce-audit-agent'); ?> <code><?php echo esc_html($settings['site_id']); ?></code></p>
                        <?php if (!empty($settings['last_status']['license']['entitlement_state'])) : ?><p><?php esc_html_e('SaaS entitlement:', 'ecommerce-audit-agent'); ?> <strong><?php echo esc_html($settings['last_status']['license']['entitlement_state']); ?></strong></p><?php endif; ?>
                    <?php if (!empty($settings['last_status']['license']['expires_at'])) : ?><p><?php esc_html_e('License expiry:', 'ecommerce-audit-agent'); ?> <?php echo esc_html((string) $settings['last_status']['license']['expires_at']); ?></p><?php endif; ?>
                    <?php if (!empty($settings['last_sync'])) : ?><p class="description"><?php esc_html_e('Last status synchronization:', 'ecommerce-audit-agent'); ?> <?php echo esc_html(wp_date(get_option('date_format') . ' ' . get_option('time_format'), (int) $settings['last_sync'])); ?></p><?php endif; ?>
                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                            <input type="hidden" name="action" value="eaa_disconnect_site">
                            <?php wp_nonce_field('eaa_disconnect_site'); ?>
                            <?php submit_button(__('Disconnect site', 'ecommerce-audit-agent'), 'secondary', 'submit', false); ?>
                        </form>
                    <?php else : ?>
                        <p><?php esc_html_e('Enter your license key below to securely link this installation.', 'ecommerce-audit-agent'); ?></p>
                    <?php endif; ?>
                </div>
                <div class="eaa-card">
                    <h2><?php esc_html_e('Monthly audit usage', 'ecommerce-audit-agent'); ?></h2>
                    <?php if (is_array($usage)) : ?>
                        <div class="eaa-stat"><?php echo esc_html((string) ($usage['used'] ?? 0)); ?> / <?php echo esc_html((string) ($usage['monthly_limit'] ?? 0)); ?></div>
                        <p><?php echo esc_html((string) ($usage['remaining'] ?? 0)); ?> <?php esc_html_e('audits remaining', 'ecommerce-audit-agent'); ?></p>
                        <?php if (!empty($usage['features']) && is_array($usage['features'])) : ?><p><?php esc_html_e('Included features:', 'ecommerce-audit-agent'); ?> <?php echo esc_html(implode(', ', array_keys(array_filter($usage['features'])))); ?></p><?php endif; ?>
                        <p><?php esc_html_e('Plan:', 'ecommerce-audit-agent'); ?> <?php echo esc_html((string) ($usage['plan_label'] ?? $usage['tier'] ?? '—')); ?> · <?php echo esc_html((string) ($usage['entitlement_state'] ?? 'unknown')); ?></p>
                    <?php else : ?><p><?php esc_html_e('Connect your license to view quota and entitlement information.', 'ecommerce-audit-agent'); ?></p><?php endif; ?>
                </div>
            </div>
            <div class="eaa-card">
                <h2><?php esc_html_e('Run a store audit', 'ecommerce-audit-agent'); ?></h2>
                <p><?php esc_html_e('The audit uses your SaaS plan quota. The PDF is streamed to your browser and is not stored in the public WordPress uploads directory.', 'ecommerce-audit-agent'); ?></p>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="eaa_run_audit">
                    <?php wp_nonce_field('eaa_run_audit'); ?>
                    <label for="eaa-domain"><strong><?php esc_html_e('Store URL', 'ecommerce-audit-agent'); ?></strong></label><br>
                    <input id="eaa-domain" name="domain" type="url" class="regular-text" placeholder="https://example.com" required>
                    <?php submit_button(__('Run audit and download PDF', 'ecommerce-audit-agent'), 'primary eaa-primary', 'submit', false, array('disabled' => !$connected)); ?>
                </form>
            </div>
            <div class="eaa-card" style="margin-top:16px">
                <h2><?php esc_html_e('Subscription and billing', 'ecommerce-audit-agent'); ?></h2>
                <?php if (is_array($billing)) : ?>
                    <p><?php esc_html_e('Plan:', 'ecommerce-audit-agent'); ?> <strong><?php echo esc_html((string) ($billing['account']['tier'] ?? '—')); ?></strong> · <?php esc_html_e('Billing period ends:', 'ecommerce-audit-agent'); ?> <?php echo esc_html((string) ($billing['account']['billing_period_ends_at'] ?? '—')); ?></p>
                    <?php if (!empty($billing['attention_items'])) : ?><p><?php esc_html_e('Billing events requiring attention:', 'ecommerce-audit-agent'); ?> <?php echo esc_html((string) count($billing['attention_items'])); ?></p><?php endif; ?>
                    <?php if (!empty($billing['items']) && is_array($billing['items'])) : ?>
                        <table class="widefat striped"><thead><tr><th><?php esc_html_e('Event', 'ecommerce-audit-agent'); ?></th><th><?php esc_html_e('Status', 'ecommerce-audit-agent'); ?></th><th><?php esc_html_e('Subscription', 'ecommerce-audit-agent'); ?></th><th><?php esc_html_e('Updated', 'ecommerce-audit-agent'); ?></th></tr></thead><tbody>
                        <?php foreach (array_slice($billing['items'], 0, 5) as $event) : ?>
                            <tr><td><?php echo esc_html((string) ($event['event_id'] ?? '—')); ?></td><td><?php echo esc_html((string) ($event['status'] ?? 'unknown')); ?></td><td><?php echo esc_html((string) ($event['subscription_id'] ?? '—')); ?></td><td><?php echo esc_html((string) ($event['updated_at'] ?? '—')); ?></td></tr>
                        <?php endforeach; ?>
                        </tbody></table>
                    <?php endif; ?>
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <input type="hidden" name="action" value="eaa_open_billing">
                        <?php wp_nonce_field('eaa_open_billing'); ?>
                        <?php submit_button(__('Manage subscription and payment methods', 'ecommerce-audit-agent'), 'secondary', 'submit', false); ?>
                    </form>
                <?php else : ?><p><?php esc_html_e('Billing information is unavailable until the SaaS billing provider is configured.', 'ecommerce-audit-agent'); ?></p><?php endif; ?>
            </div>
            <div class="eaa-card" style="margin-top:16px">
                <h2><?php esc_html_e('Recent saved reports', 'ecommerce-audit-agent'); ?></h2>
                <?php if ($reports) : ?>
                    <table class="widefat striped"><thead><tr><th><?php esc_html_e('Store', 'ecommerce-audit-agent'); ?></th><th><?php esc_html_e('Findings', 'ecommerce-audit-agent'); ?></th><th><?php esc_html_e('Created', 'ecommerce-audit-agent'); ?></th><th><?php esc_html_e('Download', 'ecommerce-audit-agent'); ?></th></tr></thead><tbody>
                    <?php foreach ($reports as $report) : $id = absint($report['id'] ?? 0); ?>
                        <tr><td><?php echo esc_html((string) ($report['domain'] ?? '—')); ?></td><td><?php echo esc_html((string) ($report['finding_count'] ?? 0)); ?></td><td><?php echo esc_html((string) ($report['created_at'] ?? '—')); ?></td><td><?php if ($id) : ?><a class="button button-small" href="<?php echo esc_url(wp_nonce_url(add_query_arg(array('action' => 'eaa_download_report', 'report_id' => $id), admin_url('admin-post.php')), 'eaa_download_report_' . $id)); ?>"><?php esc_html_e('Download PDF', 'ecommerce-audit-agent'); ?></a><?php endif; ?></td></tr>
                    <?php endforeach; ?>
                    </tbody></table>
                <?php else : ?><p><?php esc_html_e('No saved reports are available for this license yet.', 'ecommerce-audit-agent'); ?></p><?php endif; ?>
            </div>
            <?php if (is_array($usage) && !empty($usage['features']['white_label_branding'])) : ?>
            <div class="eaa-card" style="margin-top:16px">
                <h2><?php esc_html_e('White-label branding', 'ecommerce-audit-agent'); ?></h2>
                <p><?php esc_html_e('Configure the customer-facing brand identity for your eligible SaaS plan.', 'ecommerce-audit-agent'); ?></p>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="eaa_save_white_label">
                    <?php wp_nonce_field('eaa_save_white_label'); ?>
                    <table class="form-table"><tbody>
                        <tr><th><label for="eaa-white-brand"><?php esc_html_e('Brand name', 'ecommerce-audit-agent'); ?></label></th><td><input id="eaa-white-brand" name="white_label_brand_name" type="text" class="regular-text" maxlength="100" required value="<?php echo esc_attr((string) ($branding['brand_name'] ?? '')); ?>"></td></tr>
                        <tr><th><label for="eaa-white-logo"><?php esc_html_e('Logo URL (HTTPS)', 'ecommerce-audit-agent'); ?></label></th><td><input id="eaa-white-logo" name="white_label_logo_url" type="url" class="regular-text" value="<?php echo esc_attr((string) ($branding['logo_url'] ?? '')); ?>"></td></tr>
                        <tr><th><label for="eaa-white-color"><?php esc_html_e('Primary color', 'ecommerce-audit-agent'); ?></label></th><td><input id="eaa-white-color" name="white_label_primary_color" type="color" value="<?php echo esc_attr((string) ($branding['primary_color'] ?? '#155a8a')); ?>"></td></tr>
                    </tbody></table>
                    <?php submit_button(__('Save white-label branding', 'ecommerce-audit-agent')); ?>
                </form>
            </div>
            <?php endif; ?>
            <div class="eaa-card" style="margin-top:16px">
                <h2><?php esc_html_e('Connection and branding settings', 'ecommerce-audit-agent'); ?></h2>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="eaa_save_settings">
                    <?php wp_nonce_field('eaa_save_settings'); ?>
                    <table class="form-table"><tbody>
                        <tr><th><label for="eaa-license"><?php esc_html_e('SaaS license key', 'ecommerce-audit-agent'); ?></label></th><td><input id="eaa-license" name="license_key" type="password" class="regular-text" autocomplete="new-password" value="" placeholder="<?php echo !empty($settings['license_key']) ? esc_attr__('Saved license key — enter a new key only to replace it', 'ecommerce-audit-agent') : esc_attr__('Paste your SaaS license key', 'ecommerce-audit-agent'); ?>" <?php echo empty($settings['license_key']) ? 'required' : ''; ?>></td></tr>
                        <tr><th><label for="eaa-api"><?php esc_html_e('API base URL', 'ecommerce-audit-agent'); ?></label></th><td><input id="eaa-api" name="api_base" type="url" class="regular-text" value="<?php echo esc_attr(eaa_wp_api_base()); ?>" required><p class="description"><?php esc_html_e('HTTPS only. Keep the default unless your SaaS instance is self-hosted.', 'ecommerce-audit-agent'); ?></p></td></tr>
                        <tr><th><label for="eaa-brand"><?php esc_html_e('Admin display name', 'ecommerce-audit-agent'); ?></label></th><td><input id="eaa-brand" name="brand_name" type="text" class="regular-text" maxlength="100" value="<?php echo esc_attr((string) ($settings['brand_name'] ?? '')); ?>"></td></tr>
                        <tr><th><label for="eaa-color"><?php esc_html_e('Admin accent color', 'ecommerce-audit-agent'); ?></label></th><td><input id="eaa-color" name="brand_color" type="color" value="<?php echo esc_attr((string) ($settings['brand_color'] ?? '#1d4ed8')); ?>"></td></tr>
                    </tbody></table>
                    <?php submit_button(__('Save and connect', 'ecommerce-audit-agent'), 'primary eaa-primary'); ?>
                </form>
            </div>
            <p class="description"><?php esc_html_e('Your license key is stored in the WordPress options database and sent only from your server to the configured HTTPS SaaS API. It is never rendered into public-page HTML.', 'ecommerce-audit-agent'); ?></p>
        </div>
    </div>
    <?php
}
