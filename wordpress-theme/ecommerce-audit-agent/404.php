<?php
/**
 * Not-found page.
 *
 * @package EcommerceAuditAgent
 */
get_header();
?>
<main id="main-content" class="page-main">
  <div class="wrap">
    <div class="page-heading">
      <span class="card-kicker">404</span>
      <h1><?php esc_html_e('We could not find that page.', 'ecommerce-audit-agent'); ?></h1>
      <p><?php esc_html_e('The address may have changed or the page may no longer be available.', 'ecommerce-audit-agent'); ?></p>
      <p style="margin-top:24px"><a class="button" href="<?php echo esc_url(home_url('/')); ?>"><?php esc_html_e('Return to home', 'ecommerce-audit-agent'); ?></a></p>
    </div>
  </div>
</main>
<?php get_footer(); ?>
