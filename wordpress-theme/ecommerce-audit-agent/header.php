<?php
/**
 * Site header.
 *
 * @package EcommerceAuditAgent
 */
?><!doctype html>
<html <?php language_attributes(); ?>>
<head>
  <meta charset="<?php bloginfo('charset'); ?>">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php wp_head(); ?>
</head>
<body <?php body_class(); ?>>
<?php wp_body_open(); ?>
<a class="screen-reader-text" href="#main-content"><?php esc_html_e('Skip to content', 'ecommerce-audit-agent'); ?></a>
<header class="site-header">
  <div class="wrap site-nav">
    <div class="site-brand">
      <?php if (has_custom_logo()) : ?>
        <?php the_custom_logo(); ?>
      <?php else : ?>
        <a class="site-brand" href="<?php echo esc_url(home_url('/')); ?>"><?php echo esc_html(get_bloginfo('name') ?: 'Ecommerce Audit Agent'); ?></a>
      <?php endif; ?>
    </div>
    <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="eaa-primary-menu"><?php esc_html_e('Menu', 'ecommerce-audit-agent'); ?></button>
    <nav class="primary-nav" id="eaa-primary-menu" aria-label="<?php esc_attr_e('Primary navigation', 'ecommerce-audit-agent'); ?>">
      <?php
      wp_nav_menu(array(
          'theme_location' => 'primary',
          'container' => false,
          'fallback_cb' => 'eaa_theme_fallback_menu',
          'menu_class' => 'menu',
          'depth' => 1,
      ));
      ?>
    </nav>
    <a class="nav-cta" href="<?php echo esc_url(eaa_theme_api_base() . '/app'); ?>"><?php esc_html_e('Customer login', 'ecommerce-audit-agent'); ?></a>
  </div>
</header>
