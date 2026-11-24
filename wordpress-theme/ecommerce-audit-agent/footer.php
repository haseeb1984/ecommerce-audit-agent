<?php
/**
 * Site footer.
 *
 * @package EcommerceAuditAgent
 */
$support_email = get_option('eaa_theme_support_email', get_option('admin_email'));
?>
<footer class="site-footer">
  <div class="wrap">
    <div class="footer-grid">
      <div>
        <h2><?php echo esc_html(get_bloginfo('name') ?: 'Ecommerce Audit Agent'); ?></h2>
        <p><?php esc_html_e('Evidence-based ecommerce audit insights for store owners and agencies. Findings are bounded by the checks and evidence available during each audit.', 'ecommerce-audit-agent'); ?></p>
        <?php if (is_email($support_email)) : ?><p><a href="<?php echo esc_url('mailto:' . sanitize_email($support_email)); ?>"><?php echo esc_html($support_email); ?></a></p><?php endif; ?>
      </div>
      <div>
        <h3><?php esc_html_e('Explore', 'ecommerce-audit-agent'); ?></h3>
        <?php wp_nav_menu(array('theme_location' => 'footer', 'container' => false, 'fallback_cb' => 'eaa_theme_fallback_menu', 'menu_class' => 'footer-menu', 'depth' => 1)); ?>
      </div>
      <div>
        <h3><?php esc_html_e('Policies & support', 'ecommerce-audit-agent'); ?></h3>
        <ul>
          <?php foreach (array('faq' => 'FAQ', 'help-center' => 'Help Center', 'privacy-policy' => 'Privacy Policy', 'terms-of-service' => 'Terms of Service', 'cookie-policy' => 'Cookie Policy', 'refund-cancellation' => 'Refund & Cancellation') as $slug => $label) : ?>
            <li><a href="<?php echo esc_url(eaa_theme_page_url($slug)); ?>"><?php echo esc_html($label); ?></a></li>
          <?php endforeach; ?>
        </ul>
      </div>
    </div>
    <div class="footer-bottom">
      <span>&copy; <?php echo esc_html(gmdate('Y')); ?> <?php echo esc_html(get_bloginfo('name')); ?></span>
      <span><?php esc_html_e('Audit findings are informational and do not guarantee rankings, revenue, security or compliance outcomes.', 'ecommerce-audit-agent'); ?></span>
    </div>
  </div>
</footer>
<?php wp_footer(); ?>
</body>
</html>
