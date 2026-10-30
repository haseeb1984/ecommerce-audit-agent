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
    private const ACTION_LINK_SITE = 'aieab_link_wordpress_site';
    private const ACTION_UNLINK_SITE = 'aieab_unlink_wordpress_site';

    public static function boot(): void {
        add_action('admin_menu', [self::class, 'add_settings_page']);
        add_action('admin_init', [self::class, 'register_settings']);
        add_shortcode('ai_ecommerce_audit_dashboard', [self::class, 'render_dashboard']);
        add_action('admin_post_' . self::ACTION_AUDIT, [self::class, 'handle_audit']);
        add_action('admin_post_' . self::ACTION_SAVE_BRANDING, [self::class, 'handle_save_branding']);
        add_action('admin_post_' . self::ACTION_LINK_SITE, [self::class, 'handle_link_wordpress_site']);
        add_action('admin_post_' . self::ACTION_UNLINK_SITE, [self::class, 'handle_unlink_wordpress_site']);
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

            <hr />
            <?php if (isset($_GET['aieab_site_linked']) && sanitize_text_field(wp_unslash($_GET['aieab_site_linked'])) === '1') : ?><div class="notice notice-success"><p><?php echo esc_html__('WordPress site linked successfully.', 'ai-ecommerce-audit-bridge'); ?></p></div><?php endif; ?>
            <?php if (isset($_GET['aieab_site_unlinked']) && sanitize_text_field(wp_unslash($_GET['aieab_site_unlinked'])) === '1') : ?><div class="notice notice-success"><p><?php echo esc_html__('WordPress site unlinked successfully.', 'ai-ecommerce-audit-bridge'); ?></p></div><?php endif; ?>
            <h2><?php echo esc_html__('WordPress customer identity link', 'ai-ecommerce-audit-bridge'); ?></h2>
            <p><?php echo esc_html__('A customer generates a one-time code in the SaaS account portal, then a trusted WordPress administrator redeems it for this site and their current WordPress user. Codes expire after 10 minutes and can be used once.', 'ai-ecommerce-audit-bridge'); ?></p>
            <?php
            if (self::configured()) {
                $site_url = home_url('/');
                $link_response = self::api_request('GET', '/api/v1/account/wordpress-link?site_url=' . rawurlencode($site_url));
                if (!is_wp_error($link_response)) {
                    $link_data = json_decode(wp_remote_retrieve_body($link_response), true);
                    $links = is_array($link_data) && isset($link_data['links']) && is_array($link_data['links']) ? $link_data['links'] : [];
                    foreach ($links as $link) {
                        if (($link['site_url'] ?? '') === $site_url) {
                            echo '<p><strong>' . esc_html__('Connected site:', 'ai-ecommerce-audit-bridge') . '</strong> ' . esc_html($site_url) . '</p>';
                            echo '<p>' . esc_html(sprintf(__('Linked WordPress user: %1$s (ID %2$d)', 'ai-ecommerce-audit-bridge'), (string) ($link['wp_user_login'] ?? ''), (int) ($link['wp_user_id'] ?? 0))) . '</p>';
                            ?>
                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                <input type="hidden" name="action" value="<?php echo esc_attr(self::ACTION_UNLINK_SITE); ?>">
                                <?php wp_nonce_field(self::ACTION_UNLINK_SITE, 'aieab_unlink_nonce'); ?>
                                <?php submit_button(__('Unlink this WordPress site', 'ai-ecommerce-audit-bridge'), 'secondary'); ?>
                            </form>
                            <?php
                            break;
                        }
                    }
                    if (empty($links) || !array_filter($links, static function ($link) use ($site_url) { return ($link['site_url'] ?? '') === $site_url; })) {
                        echo '<p>' . esc_html__('This WordPress site is not linked to the configured SaaS license.', 'ai-ecommerce-audit-bridge') . '</p>';
                    }
                } else {
                    echo '<p>' . esc_html__('WordPress link status is temporarily unavailable. Save valid API settings and retry.', 'ai-ecommerce-audit-bridge') . '</p>';
                }
                ?>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="<?php echo esc_attr(self::ACTION_LINK_SITE); ?>">
                    <?php wp_nonce_field(self::ACTION_LINK_SITE, 'aieab_link_nonce'); ?>
                    <label for="aieab-link-token"><?php echo esc_html__('One-time code from the SaaS account portal', 'ai-ecommerce-audit-bridge'); ?></label>
                    <input id="aieab-link-token" class="regular-text" type="password" name="link_token" autocomplete="off" minlength="32" maxlength="128" required>
                    <?php submit_button(__('Link this site and current WordPress user', 'ai-ecommerce-audit-bridge')); ?>
                </form>
            <?php } else { ?>
                <p><?php echo esc_html__('Save the HTTPS API URL and license credential before linking a site.', 'ai-ecommerce-audit-bridge'); ?></p>
            <?php } ?>
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


    public static function handle_link_wordpress_site(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Only a site administrator can link this WordPress site.', 'ai-ecommerce-audit-bridge'), '', ['response' => 403]);
        }
        if (!isset($_POST['aieab_link_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['aieab_link_nonce'])), self::ACTION_LINK_SITE)) {
            wp_die(esc_html__('The form expired. Refresh the page and try again.', 'ai-ecommerce-audit-bridge'), '', ['response' => 403]);
        }
        if (!self::configured()) {
            wp_die(esc_html__('The audit API is not configured.', 'ai-ecommerce-audit-bridge'), '', ['response' => 503]);
        }
        $token = isset($_POST['link_token']) ? trim((string) wp_unslash($_POST['link_token'])) : '';
        if (strlen($token) < 32 || strlen($token) > 128) {
            wp_die(esc_html__('Enter the one-time code generated in the SaaS account portal.', 'ai-ecommerce-audit-bridge'), '', ['response' => 422]);
        }
        $user = wp_get_current_user();
        if (!$user || !$user->exists() || (int) $user->ID < 1 || !is_email($user->user_email)) {
            wp_die(esc_html__('The current WordPress administrator profile is incomplete.', 'ai-ecommerce-audit-bridge'), '', ['response' => 422]);
        }
        $result = self::api_request('POST', '/api/v1/account/wordpress-link/claim', [
            'headers' => ['Content-Type' => 'application/json'],
            'body' => wp_json_encode([
                'token' => $token,
                'site_url' => home_url('/'),
                'wp_user_id' => (int) $user->ID,
                'wp_user_login' => (string) $user->user_login,
                'wp_user_email' => (string) $user->user_email,
            ]),
        ]);
        if (is_wp_error($result)) {
            wp_die(esc_html($result->get_error_message()), '', ['response' => 400]);
        }
        wp_safe_redirect(add_query_arg('aieab_site_linked', '1', admin_url('options-general.php?page=ai-ecommerce-audit-bridge')));
        exit;
    }

    public static function handle_unlink_wordpress_site(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Only a site administrator can unlink this WordPress site.', 'ai-ecommerce-audit-bridge'), '', ['response' => 403]);
        }
        if (!isset($_POST['aieab_unlink_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['aieab_unlink_nonce'])), self::ACTION_UNLINK_SITE)) {
            wp_die(esc_html__('The form expired. Refresh the page and try again.', 'ai-ecommerce-audit-bridge'), '', ['response' => 403]);
        }
        if (!self::configured()) {
            wp_die(esc_html__('The audit API is not configured.', 'ai-ecommerce-audit-bridge'), '', ['response' => 503]);
        }
        $result = self::api_request('DELETE', '/api/v1/account/wordpress-link?site_url=' . rawurlencode(home_url('/')));
        if (is_wp_error($result)) {
            wp_die(esc_html($result->get_error_message()), '', ['response' => 502]);
        }
        wp_safe_redirect(add_query_arg('aieab_site_unlinked', '1', admin_url('options-general.php?page=ai-ecommerce-audit-bridge')));
        exit;
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
