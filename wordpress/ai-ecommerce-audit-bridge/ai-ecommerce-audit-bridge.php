<?php
/**
 * Plugin Name: AI Ecommerce Audit SaaS Bridge
 * Description: Authenticated WordPress dashboard bridge to the Ecommerce Audit Agent API.
 * Version: 0.1.0
 * Requires PHP: 8.0
 * License: GPL-2.0-or-later
 * Text Domain: ai-ecommerce-audit-bridge
 */

if (!defined('ABSPATH')) {
    exit;
}

final class AI_Ecommerce_Audit_Bridge {
    private const OPTION = 'aieab_settings';
    private const ACTION_AUDIT = 'aieab_run_audit';
    private const ACTION_SAVE_BRANDING = 'aieab_save_branding';

    public static function boot(): void {
        add_action('admin_menu', [self::class, 'add_settings_page']);
        add_action('admin_init', [self::class, 'register_settings']);
        add_shortcode('ai_ecommerce_audit_dashboard', [self::class, 'render_dashboard']);
        add_action('admin_post_' . self::ACTION_AUDIT, [self::class, 'handle_audit']);
        add_action('admin_post_' . self::ACTION_SAVE_BRANDING, [self::class, 'handle_save_branding']);
    }

    /**
     * The integration uses one site-level credential, so only trusted site operators
     * may view account usage or spend audit quota by default. Site owners can
     * deliberately grant another capability through the documented filter.
     */
    private static function dashboard_capability(): string {
        $capability = apply_filters('aieab_dashboard_capability', 'manage_options');
        return is_string($capability) && trim($capability) !== '' ? trim($capability) : 'manage_options';
    }

    private static function settings(): array {
        $value = get_option(self::OPTION, []);
        return is_array($value) ? $value : [];
    }

    public static function add_settings_page(): void {
        add_options_page(
            __('Ecommerce Audit Bridge', 'ai-ecommerce-audit-bridge'),
            __('Ecommerce Audit Bridge', 'ai-ecommerce-audit-bridge'),
            'manage_options',
            'ai-ecommerce-audit-bridge',
            [self::class, 'render_settings_page']
        );
    }

    public static function register_settings(): void {
        register_setting('aieab_settings_group', self::OPTION, [
            'type' => 'array',
            'sanitize_callback' => [self::class, 'sanitize_settings'],
            'default' => [],
        ]);
    }

    public static function sanitize_settings($input): array {
        if (!is_array($input)) {
            return [];
        }
        $base = isset($input['api_base_url']) ? esc_url_raw(trim((string) $input['api_base_url'])) : '';
        $base = untrailingslashit($base);
        if ($base !== '' && (wp_parse_url($base, PHP_URL_SCHEME) !== 'https' || !wp_parse_url($base, PHP_URL_HOST))) {
            add_settings_error(self::OPTION, 'aieab_https_required', __('API base URL must be a valid HTTPS URL.', 'ai-ecommerce-audit-bridge'));
            $base = '';
        }
        $license = isset($input['license_key']) ? sanitize_text_field(trim((string) $input['license_key'])) : '';
        if (strlen($license) > 512) {
            $license = '';
            add_settings_error(self::OPTION, 'aieab_license_too_long', __('License credential is too long.', 'ai-ecommerce-audit-bridge'));
        }
        return ['api_base_url' => $base, 'license_key' => $license];
    }

    public static function render_settings_page(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to manage this integration.', 'ai-ecommerce-audit-bridge'));
        }
        $settings = self::settings();
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Ecommerce Audit SaaS Bridge', 'ai-ecommerce-audit-bridge'); ?></h1>
            <?php settings_errors(self::OPTION); ?>
            <p><?php echo esc_html__('Credentials are stored server-side in WordPress options and are never rendered into the dashboard page.', 'ai-ecommerce-audit-bridge'); ?></p>
            <form method="post" action="options.php">
                <?php settings_fields('aieab_settings_group'); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="aieab-api-base"><?php echo esc_html__('API base URL', 'ai-ecommerce-audit-bridge'); ?></label></th>
                        <td><input id="aieab-api-base" class="regular-text" type="url" name="<?php echo esc_attr(self::OPTION); ?>[api_base_url]" value="<?php echo esc_attr($settings['api_base_url'] ?? ''); ?>" placeholder="https://api.example.com" required /></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="aieab-license"><?php echo esc_html__('License/API credential', 'ai-ecommerce-audit-bridge'); ?></label></th>
                        <td><input id="aieab-license" class="regular-text" type="password" autocomplete="new-password" name="<?php echo esc_attr(self::OPTION); ?>[license_key]" value="<?php echo esc_attr($settings['license_key'] ?? ''); ?>" required /></td>
                    </tr>
                </table>
                <?php submit_button(__('Save API settings', 'ai-ecommerce-audit-bridge')); ?>
            </form>
            <p><?php echo esc_html__('Add the [ai_ecommerce_audit_dashboard] shortcode to a page restricted to signed-in customers. Billing and plan assignment remain controlled by the backend Paddle integration.', 'ai-ecommerce-audit-bridge'); ?></p>
        </div>
        <?php
    }

    private static function configured(): bool {
        $s = self::settings();
        return !empty($s['api_base_url']) && !empty($s['license_key'])
            && wp_parse_url($s['api_base_url'], PHP_URL_SCHEME) === 'https';
    }

    private static function api_request(string $method, string $path, array $args = []) {
        $settings = self::settings();
        if (!self::configured()) {
            return new WP_Error('aieab_not_configured', __('The audit API has not been configured.', 'ai-ecommerce-audit-bridge'));
        }
        $url = $settings['api_base_url'] . $path;
        $defaults = [
            'method' => $method,
            'timeout' => 45,
            'redirection' => 0,
            'reject_unsafe_urls' => true,
            'headers' => [
                'Accept' => 'application/json, application/pdf',
                'X-License-Key' => $settings['license_key'],
            ],
        ];
        $request_args = array_merge($defaults, $args);
        // Preserve the license credential when a caller adds Content-Type or
        // other request-specific headers; array_merge alone replaces this map.
        $request_args['headers'] = array_merge(
            $defaults['headers'],
            isset($args['headers']) && is_array($args['headers']) ? $args['headers'] : []
        );
        $response = wp_remote_request($url, $request_args);
        if (is_wp_error($response)) {
            return new WP_Error('aieab_api_unavailable', __('The audit service could not be reached. Please try again later.', 'ai-ecommerce-audit-bridge'));
        }
        $status = (int) wp_remote_retrieve_response_code($response);
        if ($status < 200 || $status >= 300) {
            $message = $status === 401 || $status === 403
                ? __('The configured license was not accepted. Contact your administrator.', 'ai-ecommerce-audit-bridge')
                : ($status === 429
                    ? __('Your audit quota or rate limit has been reached. Please try again later.', 'ai-ecommerce-audit-bridge')
                    : __('The audit service returned an error. Please try again later.', 'ai-ecommerce-audit-bridge'));
            return new WP_Error('aieab_api_error', $message, ['status' => $status]);
        }
        return $response;
    }

    public static function render_dashboard(): string {
        if (!is_user_logged_in()) {
            return '<p>' . esc_html__('Please sign in to access your audit dashboard.', 'ai-ecommerce-audit-bridge') . '</p>';
        }
        if (!current_user_can(self::dashboard_capability())) {
            return '<p>' . esc_html__('You do not have permission to access this site audit account. Please contact your site administrator.', 'ai-ecommerce-audit-bridge') . '</p>';
        }
        if (!self::configured()) {
            return current_user_can('manage_options')
                ? '<p>' . esc_html__('Configure the Ecommerce Audit Bridge in Settings first.', 'ai-ecommerce-audit-bridge') . '</p>'
                : '<p>' . esc_html__('The audit dashboard is not available yet. Please contact support.', 'ai-ecommerce-audit-bridge') . '</p>';
        }

        $usage = self::api_request('GET', '/api/v1/account/usage');
        $branding_response = self::api_request('GET', '/api/v1/account/branding');
        $branding = [];
        if (!is_wp_error($branding_response)) {
            $branding_data = json_decode(wp_remote_retrieve_body($branding_response), true);
            if (is_array($branding_data)) {
                $branding = $branding_data;
            }
        }
        $notice = isset($_GET['aieab_branding_saved']) && sanitize_text_field(wp_unslash($_GET['aieab_branding_saved'])) === '1'
            ? '<p role="status">' . esc_html__('White-label branding settings saved.', 'ai-ecommerce-audit-bridge') . '</p>'
            : '';
        $can_run_audit = false;
        $can_manage_branding = false;
        $usage_markup = '<p>' . esc_html__('Usage information is temporarily unavailable.', 'ai-ecommerce-audit-bridge') . '</p>';
        if (!is_wp_error($usage)) {
            $data = json_decode(wp_remote_retrieve_body($usage), true);
            if (is_array($data)) {
                $features = isset($data['features']) && is_array($data['features']) ? $data['features'] : [];
                $can_manage_branding = ($data['entitlement_state'] ?? '') === 'active'
                    && ($features['white_label_branding'] ?? false) === true;
                // Missing feature metadata must fail closed in the customer interface.
                $can_run_audit = ($data['entitlement_state'] ?? '') === 'active'
                    && ($features['standard_audits'] ?? false) === true
                    && isset($data['remaining']) && is_numeric($data['remaining'])
                    && (int) $data['remaining'] > 0;
                $used = isset($data['consumed']) && is_numeric($data['consumed']) ? max(0, (int) $data['consumed']) : (isset($data['used']) && is_numeric($data['used']) ? max(0, (int) $data['used']) : null);
                $limit = isset($data['monthly_limit']) && is_numeric($data['monthly_limit']) ? max(0, (int) $data['monthly_limit']) : null;
                if ($used !== null && $limit !== null) {
                    $percent = $limit > 0 ? min(100, (int) floor(($used / $limit) * 100)) : 0;
                    $usage_markup = '<p><strong>' . esc_html(sprintf(__('%1$d of %2$d monthly audits used', 'ai-ecommerce-audit-bridge'), $used, $limit)) . '</strong></p>'
                        . '<progress max="100" value="' . esc_attr((string) $percent) . '" aria-label="' . esc_attr__('Monthly audit usage', 'ai-ecommerce-audit-bridge') . '">' . esc_html((string) $percent) . '%</progress>';
                } else {
                    $usage_markup = '<p>' . esc_html__('Usage details are unavailable. Audit submission is disabled until account status can be verified.', 'ai-ecommerce-audit-bridge') . '</p>';
                }
                $feature_labels = [
                    'standard_audits' => __('Standard website audits', 'ai-ecommerce-audit-bridge'),
                    'conversion_dossier' => __('Conversion opportunity dossier', 'ai-ecommerce-audit-bridge'),
                    'white_label_branding' => __('White-label branding', 'ai-ecommerce-audit-bridge'),
                    'direct_api_access' => __('Direct API access', 'ai-ecommerce-audit-bridge'),
                ];
                $usage_markup .= '<h3>' . esc_html__('Included plan features', 'ai-ecommerce-audit-bridge') . '</h3><ul>';
                foreach ($feature_labels as $feature_key => $feature_label) {
                    $included = ($features[$feature_key] ?? false) === true;
                    $usage_markup .= '<li>' . esc_html($feature_label) . ': <strong>'
                        . esc_html($included ? __('Included', 'ai-ecommerce-audit-bridge') : __('Not included', 'ai-ecommerce-audit-bridge'))
                        . '</strong></li>';
                }
                $usage_markup .= '</ul>';
                if (!$can_run_audit) {
                    $usage_markup .= '<p role="status">' . esc_html__('Audits are unavailable because the account is inactive, the plan is not entitled, the quota is exhausted, or entitlement status could not be verified.', 'ai-ecommerce-audit-bridge') . '</p>';
                }
            }
        } else {
            $notice = '<p role="status">' . esc_html($usage->get_error_message()) . '</p>';
        }

        ob_start();
        ?>
        <section class="aieab-dashboard">
            <h2><?php echo esc_html__('Ecommerce audit dashboard', 'ai-ecommerce-audit-bridge'); ?></h2>
            <?php echo wp_kses_post($notice); ?>
            <div class="aieab-usage"><?php echo wp_kses_post($usage_markup); ?></div>
            <?php if ($can_manage_branding) : ?>
                <section class="aieab-branding">
                    <h3><?php echo esc_html__('White-label branding settings', 'ai-ecommerce-audit-bridge'); ?></h3>
                    <p><?php echo esc_html__('These settings are saved to your SaaS account. They do not yet change existing PDF reports.', 'ai-ecommerce-audit-bridge'); ?></p>
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <input type="hidden" name="action" value="<?php echo esc_attr(self::ACTION_SAVE_BRANDING); ?>" />
                        <?php wp_nonce_field(self::ACTION_SAVE_BRANDING, 'aieab_branding_nonce'); ?>
                        <label for="aieab-brand-name"><?php echo esc_html__('Brand name', 'ai-ecommerce-audit-bridge'); ?></label>
                        <input id="aieab-brand-name" name="brand_name" type="text" maxlength="100" value="<?php echo esc_attr((string) ($branding['brand_name'] ?? '')); ?>" required />
                        <label for="aieab-brand-logo"><?php echo esc_html__('Logo URL (HTTPS)', 'ai-ecommerce-audit-bridge'); ?></label>
                        <input id="aieab-brand-logo" name="logo_url" type="url" maxlength="2048" value="<?php echo esc_attr((string) ($branding['logo_url'] ?? '')); ?>" placeholder="https://example.com/logo.png" />
                        <label for="aieab-brand-color"><?php echo esc_html__('Primary color', 'ai-ecommerce-audit-bridge'); ?></label>
                        <input id="aieab-brand-color" name="primary_color" type="text" pattern="#[0-9A-Fa-f]{6}" maxlength="7" value="<?php echo esc_attr((string) ($branding['primary_color'] ?? '#155a8a')); ?>" required />
                        <button type="submit"><?php echo esc_html__('Save branding settings', 'ai-ecommerce-audit-bridge'); ?></button>
                    </form>
                </section>
            <?php endif; ?>
            <?php if ($can_run_audit) : ?>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="<?php echo esc_attr(self::ACTION_AUDIT); ?>" />
                    <?php wp_nonce_field(self::ACTION_AUDIT, 'aieab_nonce'); ?>
                    <label for="aieab-domain"><?php echo esc_html__('Public store URL', 'ai-ecommerce-audit-bridge'); ?></label>
                    <input id="aieab-domain" name="domain" type="url" inputmode="url" maxlength="2048" placeholder="https://example.com" required />
                    <button type="submit"><?php echo esc_html__('Run audit and download PDF', 'ai-ecommerce-audit-bridge'); ?></button>
                </form>
            <?php endif; ?>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    public static function handle_save_branding(): void {
        if (!is_user_logged_in()) {
            auth_redirect();
            exit;
        }
        if (!current_user_can(self::dashboard_capability())) {
            wp_die(esc_html__('You are not allowed to manage this site audit account.', 'ai-ecommerce-audit-bridge'), '', ['response' => 403]);
        }
        if (!isset($_POST['aieab_branding_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['aieab_branding_nonce'])), self::ACTION_SAVE_BRANDING)) {
            wp_die(esc_html__('The form expired. Refresh the page and try again.', 'ai-ecommerce-audit-bridge'), '', ['response' => 403]);
        }
        if (!self::configured()) {
            wp_die(esc_html__('The audit service is not configured.', 'ai-ecommerce-audit-bridge'), '', ['response' => 503]);
        }

        // Enforce entitlement on the server; hiding the form is not authorization.
        $usage = self::api_request('GET', '/api/v1/account/usage');
        if (is_wp_error($usage)) {
            wp_die(esc_html($usage->get_error_message()), '', ['response' => 502]);
        }
        $usage_data = json_decode(wp_remote_retrieve_body($usage), true);
        $features = is_array($usage_data) && isset($usage_data['features']) && is_array($usage_data['features']) ? $usage_data['features'] : [];
        if (!is_array($usage_data) || ($usage_data['entitlement_state'] ?? '') !== 'active'
            || ($features['white_label_branding'] ?? false) !== true) {
            wp_die(esc_html__('White-label branding is not included in this account plan.', 'ai-ecommerce-audit-bridge'), '', ['response' => 403]);
        }

        $brand_name = isset($_POST['brand_name']) ? sanitize_text_field(wp_unslash($_POST['brand_name'])) : '';
        $logo_url = isset($_POST['logo_url']) ? trim((string) wp_unslash($_POST['logo_url'])) : '';
        $primary_color = isset($_POST['primary_color']) ? strtoupper(sanitize_text_field(wp_unslash($_POST['primary_color']))) : '';
        if ($brand_name === '' || strlen($brand_name) > 100
            || ($logo_url !== '' && (strlen($logo_url) > 2048 || wp_parse_url($logo_url, PHP_URL_SCHEME) !== 'https'
                || !wp_parse_url($logo_url, PHP_URL_HOST) || filter_var($logo_url, FILTER_VALIDATE_URL) === false))
            || !preg_match('/^#[0-9A-F]{6}$/', $primary_color)) {
            wp_die(esc_html__('Enter a brand name, a valid HTTPS logo URL (optional), and a six-digit hex color.', 'ai-ecommerce-audit-bridge'), '', ['response' => 422]);
        }

        $saved = self::api_request('PUT', '/api/v1/account/branding', [
            'headers' => ['Content-Type' => 'application/json'],
            'body' => wp_json_encode([
                'brand_name' => $brand_name,
                'logo_url' => $logo_url !== '' ? esc_url_raw($logo_url, ['https']) : null,
                'primary_color' => $primary_color,
            ]),
        ]);
        if (is_wp_error($saved)) {
            wp_die(esc_html($saved->get_error_message()), '', ['response' => 502]);
        }
        $redirect = wp_get_referer();
        if (!$redirect) {
            $redirect = home_url('/');
        }
        wp_safe_redirect(add_query_arg('aieab_branding_saved', '1', $redirect));
        exit;
    }

    public static function handle_audit(): void {
        if (!is_user_logged_in()) {
            auth_redirect();
            exit;
        }
        if (!current_user_can(self::dashboard_capability())) {
            wp_die(esc_html__('You are not allowed to use this site audit account.', 'ai-ecommerce-audit-bridge'), '', ['response' => 403]);
        }
        if (!isset($_POST['aieab_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['aieab_nonce'])), self::ACTION_AUDIT)) {
            wp_die(esc_html__('The form expired. Refresh the page and try again.', 'ai-ecommerce-audit-bridge'), '', ['response' => 403]);
        }
        if (!self::configured()) {
            wp_die(esc_html__('The audit service is not configured.', 'ai-ecommerce-audit-bridge'), '', ['response' => 503]);
        }
        $raw = isset($_POST['domain']) ? trim((string) wp_unslash($_POST['domain'])) : '';
        $domain = esc_url_raw($raw, ['http', 'https']);
        $parts = $domain ? wp_parse_url($domain) : false;
        if (!$parts || empty($parts['host']) || !in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true)
            || filter_var($domain, FILTER_VALIDATE_URL) === false) {
            wp_die(esc_html__('Enter a valid public HTTP or HTTPS store URL.', 'ai-ecommerce-audit-bridge'), '', ['response' => 422]);
        }

        // Re-check entitlements on submission; hiding the form is not an authorization boundary.
        $usage = self::api_request('GET', '/api/v1/account/usage');
        if (is_wp_error($usage)) {
            wp_die(esc_html($usage->get_error_message()), '', ['response' => 502]);
        }
        $usage_data = json_decode(wp_remote_retrieve_body($usage), true);
        $features = is_array($usage_data) && isset($usage_data['features']) && is_array($usage_data['features']) ? $usage_data['features'] : [];
        if (!is_array($usage_data) || ($usage_data['entitlement_state'] ?? '') !== 'active'
            || ($features['standard_audits'] ?? false) !== true
            || !isset($usage_data['remaining']) || !is_numeric($usage_data['remaining'])
            || (int) $usage_data['remaining'] <= 0) {
            wp_die(esc_html__('The account is not currently entitled to run an audit or its quota is exhausted. Refresh the dashboard or contact support.', 'ai-ecommerce-audit-bridge'), '', ['response' => 403]);
        }

        $response = self::api_request('POST', '/api/v1/comprehensive-audit?domain=' . rawurlencode($domain), [
            'headers' => [
                'Accept' => 'application/pdf',
                'X-License-Key' => self::settings()['license_key'],
            ],
            'timeout' => 120,
            'body' => '',
        ]);
        if (is_wp_error($response)) {
            wp_die(esc_html($response->get_error_message()), '', ['response' => 502]);
        }
        $content_type = strtolower((string) wp_remote_retrieve_header($response, 'content-type'));
        $body = wp_remote_retrieve_body($response);
        if (strpos($content_type, 'application/pdf') === false || strncmp($body, '%PDF-', 5) !== 0) {
            wp_die(esc_html__('The audit completed without a valid PDF response. Please contact support.', 'ai-ecommerce-audit-bridge'), '', ['response' => 502]);
        }

        nocache_headers();
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="ecommerce-audit-' . gmdate('Y-m-d-His') . '.pdf"');
        header('X-Content-Type-Options: nosniff');
        header('Content-Length: ' . strlen($body));
        echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- validated PDF bytes from configured HTTPS API.
        exit;
    }
}

AI_Ecommerce_Audit_Bridge::boot();
