<?php
/**
 * Theme bootstrap, public catalogue proxy, and contact/checkout handlers.
 *
 * @package EcommerceAuditAgent
 */

if (!defined('ABSPATH')) {
    exit;
}

define('EAA_THEME_VERSION', '1.0.0');
define('EAA_THEME_DEFAULT_API', 'https://ecommerce-audit-agent.vercel.app');

function eaa_theme_page_url($slug) {
    $page = get_page_by_path(sanitize_title($slug), OBJECT, 'page');
    return $page instanceof WP_Post ? get_permalink($page) : home_url('/' . trim($slug, '/') . '/');
}

function eaa_theme_fallback_menu($args = array()) {
    $class = !empty($args['menu_class']) ? sanitize_html_class($args['menu_class']) : 'menu';
    echo '<ul class="' . esc_attr($class) . '">';
    wp_list_pages(array('title_li' => '', 'depth' => 1, 'sort_column' => 'menu_order,post_title'));
    echo '</ul>';
}

function eaa_theme_meta_description() {
    if (is_admin() || is_feed()) {
        return;
    }
    if (is_front_page()) {
        $description = __('Evidence-based ecommerce website audits, technical and customer-experience insights, and practical findings for store owners and agencies.', 'ecommerce-audit-agent');
    } elseif (is_singular()) {
        $post = get_queried_object();
        $description = has_excerpt($post) ? get_the_excerpt($post) : wp_strip_all_tags(strip_shortcodes($post->post_content));
    } else {
        return;
    }
    $description = trim(preg_replace('/\s+/', ' ', $description));
    if ($description !== '') {
        echo '<meta name="description" content="' . esc_attr(wp_html_excerpt($description, 158, '…')) . '">' . "\n";
    }
}
add_action('wp_head', 'eaa_theme_meta_description', 2);

function eaa_theme_setup() {
    load_theme_textdomain('ecommerce-audit-agent', get_template_directory() . '/languages');
    add_theme_support('title-tag');
    add_theme_support('automatic-feed-links');
    add_theme_support('post-thumbnails');
    add_theme_support('custom-logo', array('height' => 64, 'width' => 280, 'flex-height' => true, 'flex-width' => true));
    add_theme_support('html5', array('search-form', 'comment-form', 'comment-list', 'gallery', 'caption', 'style', 'script'));
    add_theme_support('responsive-embeds');
    add_theme_support('wp-block-styles');
    add_theme_support('align-wide');
    register_nav_menus(array(
        'primary' => __('Primary navigation', 'ecommerce-audit-agent'),
        'footer' => __('Footer navigation', 'ecommerce-audit-agent'),
    ));
}
add_action('after_setup_theme', 'eaa_theme_setup');

function eaa_theme_api_base() {
    $value = get_option('eaa_theme_api_base', EAA_THEME_DEFAULT_API);
    $value = esc_url_raw(trim((string) $value));
    $parts = wp_parse_url($value);
    if (!$parts || empty($parts['scheme']) || strtolower($parts['scheme']) !== 'https' || empty($parts['host']) || !empty($parts['user']) || !empty($parts['pass']) || !empty($parts['query']) || !empty($parts['fragment'])) {
        return EAA_THEME_DEFAULT_API;
    }
    return untrailingslashit($value);
}

function eaa_theme_enqueue_assets() {
    wp_enqueue_style('eaa-theme-style', get_stylesheet_uri(), array(), EAA_THEME_VERSION);
    wp_enqueue_script('eaa-theme-site', get_template_directory_uri() . '/assets/site.js', array(), EAA_THEME_VERSION, true);
    wp_localize_script('eaa-theme-site', 'EAA_SITE', array(
        'plansUrl' => esc_url_raw(rest_url('eaa/v1/plans')),
        'checkoutAction' => esc_url_raw(admin_url('admin-post.php')),
        'checkoutNonce' => wp_create_nonce('eaa_checkout'),
        'contactStatus' => isset($_GET['contact']) ? sanitize_key(wp_unslash($_GET['contact'])) : '',
    ));
}
add_action('wp_enqueue_scripts', 'eaa_theme_enqueue_assets');

function eaa_theme_register_api_routes() {
    register_rest_route('eaa/v1', '/plans', array(
        'methods' => WP_REST_Server::READABLE,
        'callback' => 'eaa_theme_proxy_plans',
        'permission_callback' => '__return_true',
    ));
}
add_action('rest_api_init', 'eaa_theme_register_api_routes');

function eaa_theme_proxy_plans() {
    $response = wp_remote_get(eaa_theme_api_base() . '/api/v1/billing/plans', array(
        'timeout' => 18,
        'redirection' => 0,
        'headers' => array('Accept' => 'application/json', 'Cache-Control' => 'no-cache'),
    ));
    if (is_wp_error($response)) {
        return new WP_Error('eaa_catalogue_unavailable', __('The live package catalogue is temporarily unavailable.', 'ecommerce-audit-agent'), array('status' => 503));
    }
    $status = (int) wp_remote_retrieve_response_code($response);
    $payload = json_decode(wp_remote_retrieve_body($response), true);
    if ($status !== 200 || !is_array($payload) || !isset($payload['plans']) || !is_array($payload['plans'])) {
        return new WP_Error('eaa_catalogue_invalid', __('The package catalogue could not be verified. Please try again later.', 'ecommerce-audit-agent'), array('status' => 503));
    }
    $plans = array();
    $feature_keys = array('standard_audits', 'conversion_dossier', 'white_label_branding', 'agency_management', 'direct_api_access');
    foreach ($payload['plans'] as $plan) {
        if (!is_array($plan)) {
            continue;
        }
        $tier = strtolower(sanitize_key((string) ($plan['tier'] ?? '')));
        if (!in_array($tier, array('starter', 'pro', 'business'), true)) {
            continue;
        }
        $features = array();
        foreach ($feature_keys as $feature_key) {
            $features[$feature_key] = !empty($plan['features'][$feature_key]);
        }
        $safe_plan = array(
            'tier' => $tier,
            'label' => sanitize_text_field((string) ($plan['label'] ?? ucfirst($tier))),
            'monthly_audit_allowance' => max(0, absint($plan['monthly_audit_allowance'] ?? 0)),
            'max_concurrent_audits' => max(0, absint($plan['max_concurrent_audits'] ?? 0)),
            'features' => $features,
            'price' => null,
        );
        if (isset($plan['price']) && is_array($plan['price'])) {
            $currency = strtoupper(sanitize_text_field((string) ($plan['price']['currency_code'] ?? '')));
            $amount = $plan['price']['amount_minor'] ?? null;
            if (preg_match('/^[A-Z]{3}$/', $currency) && is_numeric($amount) && (float) $amount >= 0) {
                $interval = sanitize_key((string) ($plan['price']['billing_cycle_interval'] ?? ''));
                $safe_plan['price'] = array(
                    'currency_code' => $currency,
                    'amount_minor' => (string) $amount,
                    'billing_cycle_interval' => in_array($interval, array('day', 'week', 'month', 'year'), true) ? $interval : null,
                    'billing_cycle_frequency' => max(1, absint($plan['price']['billing_cycle_frequency'] ?? 1)),
                );
            }
        }
        $plans[] = $safe_plan;
    }
    $result = new WP_REST_Response(array('plans' => $plans), 200);
    $result->header('Cache-Control', 'no-store, private');
    $result->header('Pragma', 'no-cache');
    return $result;
}

function eaa_theme_checkout_handler() {
    if (strtoupper($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        wp_die(esc_html__('Invalid request method.', 'ecommerce-audit-agent'), '', array('response' => 405));
    }
    check_admin_referer('eaa_checkout');
    $tier = sanitize_key(wp_unslash($_POST['tier'] ?? ''));
    $email = sanitize_email(wp_unslash($_POST['email'] ?? ''));
    if (!in_array($tier, array('starter', 'pro', 'business'), true) || !is_email($email) || strlen($email) > 254) {
        wp_die(esc_html__('Enter a valid account email and choose a supported package.', 'ecommerce-audit-agent'), '', array('response' => 422));
    }
    $response = wp_remote_post(eaa_theme_api_base() . '/api/v1/billing/checkout', array(
        'timeout' => 22,
        'redirection' => 0,
        'headers' => array('Content-Type' => 'application/json', 'Accept' => 'application/json'),
        'body' => wp_json_encode(array('tier' => $tier, 'email' => $email)),
    ));
    if (is_wp_error($response)) {
        wp_die(esc_html__('Secure checkout is temporarily unavailable. Please try again later.', 'ecommerce-audit-agent'), '', array('response' => 502));
    }
    $status = (int) wp_remote_retrieve_response_code($response);
    $payload = json_decode(wp_remote_retrieve_body($response), true);
    $checkout_url = is_array($payload) ? (string) ($payload['checkout_url'] ?? '') : '';
    $parts = wp_parse_url($checkout_url);
    $host = strtolower((string) ($parts['host'] ?? ''));
    $valid_host = ($host === 'paddle.com' || (strlen($host) > 11 && substr($host, -11) === '.paddle.com'));
    if ($status < 200 || $status >= 300 || empty($parts['scheme']) || strtolower($parts['scheme']) !== 'https' || !$valid_host || !empty($parts['user']) || !empty($parts['pass'])) {
        wp_die(esc_html__('The secure checkout destination could not be verified. No payment has been started.', 'ecommerce-audit-agent'), '', array('response' => 502));
    }
    wp_redirect(esc_url_raw($checkout_url), 303, 'Ecommerce Audit Agent');
    exit;
}
add_action('admin_post_eaa_checkout', 'eaa_theme_checkout_handler');
add_action('admin_post_nopriv_eaa_checkout', 'eaa_theme_checkout_handler');

function eaa_theme_contact_handler() {
    if (strtoupper($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        wp_die(esc_html__('Invalid request method.', 'ecommerce-audit-agent'), '', array('response' => 405));
    }
    check_admin_referer('eaa_contact');
    if (!empty($_POST['website_url'] ?? '')) {
        wp_die(esc_html__('Your message could not be accepted.', 'ecommerce-audit-agent'), '', array('response' => 400));
    }
    $name = sanitize_text_field(wp_unslash($_POST['name'] ?? ''));
    $email = sanitize_email(wp_unslash($_POST['email'] ?? ''));
    $subject = sanitize_text_field(wp_unslash($_POST['subject'] ?? ''));
    $message = sanitize_textarea_field(wp_unslash($_POST['message'] ?? ''));
    if ($name === '' || !is_email($email) || strlen($email) > 254 || $subject === '' || strlen($message) < 15 || strlen($message) > 6000) {
        wp_die(esc_html__('Please complete every field with a valid email and a message between 15 and 6,000 characters.', 'ecommerce-audit-agent'), '', array('response' => 422));
    }
    $rate_key = 'eaa_contact_' . hash('sha256', strtolower($email));
    if (get_transient($rate_key)) {
        wp_die(esc_html__('A message from this email was submitted recently. Please wait before sending another.', 'ecommerce-audit-agent'), '', array('response' => 429));
    }
    $recipient = sanitize_email(get_option('eaa_theme_support_email', get_option('admin_email')));
    if (!is_email($recipient)) {
        wp_die(esc_html__('The website administrator email is not configured. Please use the site administrator contact.', 'ecommerce-audit-agent'), '', array('response' => 503));
    }
    $mail_subject = sprintf('[%s] %s', wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES), $subject);
    $mail_body = "Name: {$name}\nEmail: {$email}\n\n{$message}";
    $sent = wp_mail($recipient, $mail_subject, $mail_body, array('Reply-To: ' . $name . ' <' . $email . '>'));
    if (!$sent) {
        wp_die(esc_html__('Your message could not be sent right now. Please try again later.', 'ecommerce-audit-agent'), '', array('response' => 503));
    }
    set_transient($rate_key, 1, 45);
    $referer = wp_get_referer();
    $target = $referer ? remove_query_arg('contact', $referer) : home_url('/contact/');
    wp_safe_redirect(add_query_arg('contact', 'sent', $target));
    exit;
}
add_action('admin_post_eaa_contact', 'eaa_theme_contact_handler');
add_action('admin_post_nopriv_eaa_contact', 'eaa_theme_contact_handler');

function eaa_theme_pricing_shortcode() {
    ob_start();
    ?>
    <div class="pricing-intro">
      <p><?php esc_html_e('Compare the live Starter, Pro and Business catalogue. Allowances, concurrency and feature access are supplied by the SaaS package catalogue; prices are verified by Paddle at checkout.', 'ecommerce-audit-agent'); ?></p>
    </div>
    <div class="pricing-email">
      <label for="eaa-checkout-email"><?php esc_html_e('Customer account email', 'ecommerce-audit-agent'); ?></label>
      <input id="eaa-checkout-email" type="email" maxlength="254" autocomplete="email" placeholder="you@example.com" required>
      <p class="muted"><?php esc_html_e('One verified email owns one customer license. Existing customers should sign in to manage their current subscription.', 'ecommerce-audit-agent'); ?></p>
    </div>
    <div id="eaa-plans" class="pricing-grid" aria-live="polite">
      <article class="plan-card"><h3><?php esc_html_e('Loading packages…', 'ecommerce-audit-agent'); ?></h3><p class="muted"><?php esc_html_e('Retrieving the live package catalogue.', 'ecommerce-audit-agent'); ?></p></article>
    </div>
    <p id="eaa-plans-status" class="plan-status" role="status" aria-live="polite"></p>
    <div class="compare-wrap">
      <table class="compare-table"><thead id="eaa-compare-head"><tr><th><?php esc_html_e('Capability', 'ecommerce-audit-agent'); ?></th><th><?php esc_html_e('Loading catalogue…', 'ecommerce-audit-agent'); ?></th></tr></thead><tbody id="eaa-compare-body"></tbody></table>
    </div>
    <p class="muted"><?php esc_html_e('Regional price overrides and applicable taxes may change the final checkout total. The final amount is shown by Paddle before payment. If the live catalogue cannot be verified, no estimated price is displayed.', 'ecommerce-audit-agent'); ?></p>
    <?php
    return ob_get_clean();
}
add_shortcode('eaa_pricing', 'eaa_theme_pricing_shortcode');

function eaa_theme_contact_shortcode() {
    $status = isset($_GET['contact']) ? sanitize_key(wp_unslash($_GET['contact'])) : '';
    ob_start();
    ?>
    <div class="contact-layout">
      <div>
        <span class="card-kicker"><?php esc_html_e('Talk to our team', 'ecommerce-audit-agent'); ?></span>
        <h2><?php esc_html_e('Tell us what you are trying to improve.', 'ecommerce-audit-agent'); ?></h2>
        <p class="muted"><?php esc_html_e('Use this form for product questions, account support and business enquiries. Do not include passwords, license keys, payment details or other secrets.', 'ecommerce-audit-agent'); ?></p>
        <p><strong><?php esc_html_e('Support email', 'ecommerce-audit-agent'); ?>:</strong> <?php echo esc_html(get_option('eaa_theme_support_email', get_option('admin_email'))); ?></p>
      </div>
      <form class="contact-form" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <?php if ($status === 'sent') : ?><p class="form-message" role="status"><?php esc_html_e('Thank you. Your message has been sent.', 'ecommerce-audit-agent'); ?></p><?php endif; ?>
        <input type="hidden" name="action" value="eaa_contact">
        <?php wp_nonce_field('eaa_contact'); ?>
        <div class="honeypot" aria-hidden="true"><label for="eaa-website-url">Leave this field empty</label><input id="eaa-website-url" name="website_url" type="text" tabindex="-1" autocomplete="off"></div>
        <div class="field"><label for="eaa-contact-name"><?php esc_html_e('Your name', 'ecommerce-audit-agent'); ?></label><input id="eaa-contact-name" name="name" type="text" maxlength="120" autocomplete="name" required></div>
        <div class="field"><label for="eaa-contact-email"><?php esc_html_e('Email address', 'ecommerce-audit-agent'); ?></label><input id="eaa-contact-email" name="email" type="email" maxlength="254" autocomplete="email" required></div>
        <div class="field"><label for="eaa-contact-subject"><?php esc_html_e('Subject', 'ecommerce-audit-agent'); ?></label><input id="eaa-contact-subject" name="subject" type="text" maxlength="160" required></div>
        <div class="field"><label for="eaa-contact-message"><?php esc_html_e('How can we help?', 'ecommerce-audit-agent'); ?></label><textarea id="eaa-contact-message" name="message" minlength="15" maxlength="6000" required></textarea></div>
        <button class="button" type="submit"><?php esc_html_e('Send message', 'ecommerce-audit-agent'); ?></button>
      </form>
    </div>
    <?php
    return ob_get_clean();
}
add_shortcode('eaa_contact_form', 'eaa_theme_contact_shortcode');

function eaa_theme_default_pages() {
    return array(
        'home' => array('Home', '[eaa_home_intro]'),
        'features' => array('Features', '<p>Evidence-led ecommerce website reviews help teams understand technical SEO, page structure, accessibility signals, mobile experience, performance indicators, security headers, trust cues and conversion-flow observations.</p><h2>Actionable findings</h2><p>Review findings with severity, status, evidence references and recommended next steps. A missing signal is not treated as proof of a defect, and checks that could not be completed remain clearly identified.</p><h2>Built for different teams</h2><ul><li>Store owners can inspect their own ecommerce website and audit history.</li><li>Pro customers can use supported white-label settings.</li><li>Business agencies can organize client workspaces and team access under the agency entitlement.</li></ul><p>Actual access is controlled by your package and the SaaS account permissions.</p>'),
        'how-it-works' => array('How It Works', '<ol><li><strong>Choose your package.</strong> Review the current allowances and features in the live catalogue.</li><li><strong>Connect your store.</strong> Submit the public HTTPS website URL through your customer account or supported WordPress integration.</li><li><strong>Run an audit.</strong> The service performs bounded checks and reports the pages and signals it could inspect.</li><li><strong>Review evidence.</strong> Use the findings and limitations to prioritize a practical improvement plan.</li></ol><p>Audit coverage is bounded and does not replace a manual security, accessibility, legal or platform review.</p>'),
        'pricing' => array('Pricing', '[eaa_pricing]'),
        'about' => array('About', '<p>Ecommerce Audit Agent is a software service for evidence-based ecommerce website reviews. It brings technical and customer-experience signals into one structured workflow for store owners and agencies.</p><h2>Our approach</h2><p>We distinguish observed evidence from inferred risk, disclose checks that were not completed and avoid promising rankings, revenue gains, compliance or security outcomes.</p>'),
        'contact' => array('Contact', '[eaa_contact_form]'),
        'faq' => array('FAQ', '<h2>Does an audit guarantee higher rankings or sales?</h2><p>No. An audit reports observations and recommendations. Search rankings, conversion rates and revenue depend on many factors outside the service.</p><h2>Does the audit prove a site is secure?</h2><p>No. Automated checks cover a bounded set of public signals and do not constitute penetration testing or a security certification.</p><h2>Can I connect more than one store?</h2><p>Individual customer licenses are tied to one active ecommerce website. Business agency accounts use separately entitled client workspaces.</p><h2>Where can I see current prices?</h2><p>The pricing page retrieves the active package catalogue. Paddle displays the final verified checkout amount before payment.</p><h2>How do I get support?</h2><p>Use the contact form or the support email configured by the site administrator.</p>'),
        'privacy-policy' => array('Privacy Policy', '<div class="notice"><strong>Publication review required:</strong> replace every bracketed placeholder and have this policy reviewed for your actual business, providers, data flows and applicable law before relying on it.</div><p><strong>Effective date:</strong> [EFFECTIVE DATE]</p><p><strong>Legal entity:</strong> [LEGAL ENTITY NAME]</p><p><strong>Contact:</strong> [PRIVACY CONTACT EMAIL]</p><h2>Information handled</h2><p>Describe the account, website, audit, usage, support, billing and technical information your service actually collects. Identify each category, purpose and retention period.</p><h2>Providers and international transfers</h2><p>List the processors and infrastructure providers actually used, the purposes for which they process information, and any applicable international transfer safeguards.</p><h2>Choices and rights</h2><p>Describe the privacy rights and request process that apply in each jurisdiction where you operate.</p><h2>Retention and security</h2><p>Specify actual retention periods and technical/organizational measures. Do not claim a certification or guarantee unless independently verified.</p><h2>Contact</h2><p>[LEGAL ENTITY NAME], [POSTAL ADDRESS], [PRIVACY CONTACT EMAIL]</p>'),
        'terms-of-service' => array('Terms of Service', '<div class="notice"><strong>Legal review required:</strong> this is a content framework, not final legal advice. Complete the placeholders and have counsel review it before publication as binding terms.</div><p><strong>Provider:</strong> [LEGAL ENTITY NAME]</p><p><strong>Effective date:</strong> [EFFECTIVE DATE]</p><h2>Service description</h2><p>Describe the SaaS features, supported integrations, package limits and material service restrictions.</p><h2>Accounts and acceptable use</h2><p>Set out account eligibility, credential responsibilities, permitted use, prohibited activity and suspension grounds.</p><h2>Audits and recommendations</h2><p>Explain that audit coverage is bounded, findings are informational, and no search ranking, sales, security or compliance outcome is guaranteed.</p><h2>Billing and cancellation</h2><p>Describe the actual billing provider, renewal, cancellation, taxes, refunds and customer support process consistently with the configured checkout terms.</p><h2>Liability and governing law</h2><p>[INSERT COUNSEL-APPROVED LIABILITY TERMS AND GOVERNING JURISDICTION]</p><h2>Contact</h2><p>[LEGAL ENTITY NAME], [POSTAL ADDRESS], [LEGAL CONTACT EMAIL]</p>'),
        'cookie-policy' => array('Cookie Policy', '<div class="notice"><strong>Configuration required:</strong> document only the cookies and similar technologies actually used by the active WordPress theme, plugins, analytics and payment flows. Add a consent manager if required by the laws that apply to your visitors.</div><h2>What cookies are used?</h2><p>[LIST EACH COOKIE OR TECHNOLOGY, ITS PROVIDER, PURPOSE, CATEGORY AND DURATION AFTER INVENTORY]</p><h2>Managing preferences</h2><p>Explain how visitors can manage optional cookies and how browser controls affect site functionality.</p><h2>Contact</h2><p>[PRIVACY CONTACT EMAIL]</p>'),
        'refund-cancellation' => array('Refund & Cancellation Policy', '<div class="notice"><strong>Business policy required:</strong> confirm this page against the live Paddle configuration, checkout terms and applicable consumer law before publication.</div><h2>Subscriptions</h2><p>[DESCRIBE BILLING INTERVALS, RENEWAL, CANCELLATION EFFECTIVE DATE AND ACCESS AFTER CANCELLATION]</p><h2>Refund requests</h2><p>[INSERT THE ACTUAL REFUND ELIGIBILITY, REQUEST WINDOW, EXCLUSIONS AND PROCESS]</p><h2>How to cancel or request help</h2><p>[INSERT THE VERIFIED CUSTOMER BILLING PORTAL URL OR SUPPORT PROCESS]</p><h2>Contact</h2><p>[BILLING SUPPORT EMAIL]</p>'),
        'disclaimer' => array('Disclaimer', '<p>Ecommerce Audit Agent provides automated website observations and recommendations for informational purposes. Checks are bounded by the pages, content, network responses and tools available during an audit.</p><p>Results are not legal, financial, cybersecurity, accessibility or search-engine advice. No audit guarantees rankings, revenue, conversion improvements, complete security, WCAG conformance or search indexing. Verify material findings independently and consult qualified professionals where appropriate.</p><p>Replace or supplement this text with counsel-approved terms for [LEGAL ENTITY NAME] and [GOVERNING JURISDICTION].</p>'),
        'security' => array('Security', '<p>The service uses bounded public-site checks and authenticated account workflows. The scope and outcome of an individual audit depend on the checks that completed and the evidence returned.</p><h2>Responsible disclosure</h2><p>Report a suspected vulnerability to [SECURITY CONTACT EMAIL]. Do not include passwords, live credentials, customer data or exploit payloads in an initial report. Replace this placeholder with a monitored security contact before publication.</p><h2>Scope and limitations</h2><p>This page does not claim penetration testing, certification, or that any website is hack-proof.</p>'),
        'help-center' => array('Help Center', '<h2>Getting started</h2><p>Create or access your customer account, choose the package that matches your intended use, and connect the ecommerce website you are authorized to review.</p><h2>WordPress connection</h2><p>Install the official Ecommerce Audit Agent plugin from your SaaS customer portal or the service plugin endpoint. Enter the license credential or use the supported one-time identity/agency connection flow. Keep credentials private.</p><h2>Audit results</h2><p>Review the status, evidence and limitations shown with each finding. A not-tested result is not a pass.</p><h2>Billing</h2><p>Use your customer account billing controls to manage the subscription through the payment provider.</p><p>For account-specific help, use the Contact page.</p>'),
        'integrations' => array('Integrations', '<h2>WordPress and WooCommerce</h2><p>The official WordPress plugin connects an authorized WordPress installation to the SaaS service, reports supported site metadata and exposes license-scoped audit and report workflows. WooCommerce is detected as integration metadata; it is not required for core plugin operation.</p><h2>Business API</h2><p>Direct API access is a Business package capability. Use the authenticated API documentation and credentials supplied through your account. Never publish API keys in browser code.</p><h2>Payment processing</h2><p>Checkout and subscription management are handed to the configured Paddle flow. The final amount and applicable taxes are shown by the payment provider.</p>')
    );
}

function eaa_theme_create_default_pages() {
    $pages = eaa_theme_default_pages();
    $page_ids = array();
    foreach ($pages as $slug => $page) {
        $existing = get_page_by_path($slug, OBJECT, 'page');
        if ($existing instanceof WP_Post) {
            $page_ids[$slug] = $existing->ID;
            continue;
        }
        $content = $page[1];
        if ($slug === 'home') {
            $content = '';
        }
        $id = wp_insert_post(array(
            'post_type' => 'page',
            'post_status' => 'publish',
            'post_title' => $page[0],
            'post_name' => $slug,
            'post_content' => $content,
            'comment_status' => 'closed',
            'ping_status' => 'closed',
        ), true);
        if (!is_wp_error($id)) {
            $page_ids[$slug] = (int) $id;
        }
    }
    if (!empty($page_ids['home'])) {
        update_option('show_on_front', 'page');
        update_option('page_on_front', $page_ids['home']);
    }
    if (!empty($page_ids['privacy-policy'])) {
        update_option('wp_page_for_privacy_policy', $page_ids['privacy-policy']);
    }
    $menu_name = 'Ecommerce Audit Agent';
    $menu = wp_get_nav_menu_object($menu_name);
    $menu_id = $menu ? (int) $menu->term_id : wp_create_nav_menu($menu_name);
    if (!is_wp_error($menu_id) && $menu_id) {
        $menu_pages = array('features', 'how-it-works', 'pricing', 'about', 'contact');
        foreach ($menu_pages as $slug) {
            if (!empty($page_ids[$slug])) {
                $already = wp_get_nav_menu_items($menu_id);
                $exists = false;
                foreach ((array) $already as $item) {
                    if ((int) $item->object_id === (int) $page_ids[$slug]) {
                        $exists = true;
                        break;
                    }
                }
                if (!$exists) {
                    wp_update_nav_menu_item($menu_id, 0, array(
                        'menu-item-object-id' => $page_ids[$slug],
                        'menu-item-object' => 'page',
                        'menu-item-type' => 'post_type',
                        'menu-item-status' => 'publish',
                    ));
                }
            }
        }
        $locations = get_theme_mod('nav_menu_locations', array());
        $locations['primary'] = $menu_id;
        $locations['footer'] = $menu_id;
        set_theme_mod('nav_menu_locations', $locations);
    }
}
add_action('after_switch_theme', 'eaa_theme_create_default_pages');

function eaa_theme_admin_menu() {
    add_theme_page(__('EAA Website Settings', 'ecommerce-audit-agent'), __('EAA Website Settings', 'ecommerce-audit-agent'), 'manage_options', 'eaa-theme-settings', 'eaa_theme_settings_page');
}
add_action('admin_menu', 'eaa_theme_admin_menu');

function eaa_theme_register_settings() {
    register_setting('eaa_theme_settings', 'eaa_theme_api_base', array(
        'type' => 'string',
        'sanitize_callback' => function ($value) {
            $value = esc_url_raw(trim((string) $value));
            $parts = wp_parse_url($value);
            if (!$parts || strtolower((string) ($parts['scheme'] ?? '')) !== 'https' || empty($parts['host']) || !empty($parts['user']) || !empty($parts['pass']) || !empty($parts['query']) || !empty($parts['fragment'])) {
                return EAA_THEME_DEFAULT_API;
            }
            return untrailingslashit($value);
        },
        'default' => EAA_THEME_DEFAULT_API,
    ));
    register_setting('eaa_theme_settings', 'eaa_theme_support_email', array('type' => 'string', 'sanitize_callback' => 'sanitize_email', 'default' => get_option('admin_email')));
}
add_action('admin_init', 'eaa_theme_register_settings');

function eaa_theme_settings_page() {
    if (!current_user_can('manage_options')) {
        return;
    }
    ?>
    <div class="wrap">
      <h1><?php esc_html_e('Ecommerce Audit Agent website settings', 'ecommerce-audit-agent'); ?></h1>
      <p><?php esc_html_e('These settings configure the public WordPress marketing site. SaaS accounts, licenses, audits and customer files remain managed by their existing backend systems; this theme does not copy those records into WordPress tables.', 'ecommerce-audit-agent'); ?></p>
      <form method="post" action="options.php">
        <?php settings_fields('eaa_theme_settings'); ?>
        <table class="form-table" role="presentation">
          <tr><th scope="row"><label for="eaa_theme_api_base"><?php esc_html_e('SaaS API base URL', 'ecommerce-audit-agent'); ?></label></th><td><input class="regular-text" type="url" id="eaa_theme_api_base" name="eaa_theme_api_base" value="<?php echo esc_attr(eaa_theme_api_base()); ?>" required><p class="description"><?php esc_html_e('Must be an HTTPS origin. Defaults to the existing Ecommerce Audit Agent deployment.', 'ecommerce-audit-agent'); ?></p></td></tr>
          <tr><th scope="row"><label for="eaa_theme_support_email"><?php esc_html_e('Public support email', 'ecommerce-audit-agent'); ?></label></th><td><input class="regular-text" type="email" id="eaa_theme_support_email" name="eaa_theme_support_email" value="<?php echo esc_attr(get_option('eaa_theme_support_email', get_option('admin_email'))); ?>"><p class="description"><?php esc_html_e('Contact form delivery still uses the WordPress administrator mailbox until SMTP is configured.', 'ecommerce-audit-agent'); ?></p></td></tr>
        </table>
        <?php submit_button(); ?>
      </form>
      <h2><?php esc_html_e('Before publishing legal pages', 'ecommerce-audit-agent'); ?></h2>
      <p><?php esc_html_e('Complete the bracketed legal entity, postal address, effective date, governing jurisdiction, privacy/security contacts, cookie inventory and refund rules. The generated legal pages are clearly marked for review and are not legal advice.', 'ecommerce-audit-agent'); ?></p>
    </div>
    <?php
}
