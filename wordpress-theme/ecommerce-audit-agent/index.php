<?php
/**
 * Fallback template.
 *
 * @package EcommerceAuditAgent
 */
get_header();
?>
<main class="page-main">
  <div class="wrap">
    <?php if (have_posts()) : while (have_posts()) : the_post(); ?>
      <article <?php post_class('prose'); ?>>
        <div class="page-heading"><h1><?php the_title(); ?></h1></div>
        <?php the_content(); ?>
      </article>
    <?php endwhile; else : ?>
      <div class="page-heading"><h1><?php esc_html_e('Nothing found', 'ecommerce-audit-agent'); ?></h1></div>
    <?php endif; ?>
  </div>
</main>
<?php get_footer(); ?>
