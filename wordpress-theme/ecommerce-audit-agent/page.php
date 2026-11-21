<?php
/**
 * Standard content page.
 *
 * @package EcommerceAuditAgent
 */
get_header();
?>
<main id="main-content" class="page-main">
  <div class="wrap">
    <?php if (have_posts()) : while (have_posts()) : the_post(); ?>
      <header class="page-heading">
        <span class="card-kicker"><?php esc_html_e('Ecommerce Audit Agent', 'ecommerce-audit-agent'); ?></span>
        <h1><?php the_title(); ?></h1>
        <?php if (has_excerpt()) : ?><p><?php echo esc_html(get_the_excerpt()); ?></p><?php endif; ?>
      </header>
      <article <?php post_class('prose'); ?>>
        <?php the_content(); ?>
      </article>
    <?php endwhile; else : ?>
      <div class="page-heading"><h1><?php esc_html_e('Page not found', 'ecommerce-audit-agent'); ?></h1></div>
    <?php endif; ?>
  </div>
</main>
<?php get_footer(); ?>
