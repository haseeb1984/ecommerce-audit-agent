<?php
/**
 * Public home page.
 *
 * @package EcommerceAuditAgent
 */
get_header();
?>
<main id="main-content">
  <section class="hero">
    <div class="wrap hero-grid">
      <div>
        <span class="eyebrow"><?php esc_html_e('Evidence-led ecommerce insights', 'ecommerce-audit-agent'); ?></span>
        <h1><?php esc_html_e('Find what is holding your ecommerce store back.', 'ecommerce-audit-agent'); ?></h1>
        <p><?php esc_html_e('Run structured website audits, uncover technical and customer-experience issues, and turn evidence-backed findings into a practical improvement plan.', 'ecommerce-audit-agent'); ?></p>
        <div class="hero-actions">
          <a class="button" href="<?php echo esc_url(eaa_theme_page_url('pricing')); ?>"><?php esc_html_e('Compare packages', 'ecommerce-audit-agent'); ?></a>
          <a class="button button-secondary" href="https://ecommerce-audit-agent.vercel.app/app"><?php esc_html_e('Customer sign in', 'ecommerce-audit-agent'); ?></a>
        </div>
      </div>
      <aside class="hero-proof">
        <strong><?php esc_html_e('A clearer view of your store', 'ecommerce-audit-agent'); ?></strong>
        <ul>
          <li><?php esc_html_e('Technical SEO and ecommerce structure signals', 'ecommerce-audit-agent'); ?></li>
          <li><?php esc_html_e('Mobile, accessibility and performance observations', 'ecommerce-audit-agent'); ?></li>
          <li><?php esc_html_e('Evidence references, status and disclosed limitations', 'ecommerce-audit-agent'); ?></li>
        </ul>
      </aside>
    </div>
  </section>

  <section class="section">
    <div class="wrap">
      <div class="section-heading">
        <span class="card-kicker"><?php esc_html_e('What you can review', 'ecommerce-audit-agent'); ?></span>
        <h2><?php esc_html_e('More than a surface-level website check', 'ecommerce-audit-agent'); ?></h2>
        <p><?php esc_html_e('Bring important storefront signals into one structured audit workflow without presenting unverified observations as guarantees.', 'ecommerce-audit-agent'); ?></p>
      </div>
      <div class="card-grid">
        <article class="info-card"><span class="card-kicker"><?php esc_html_e('Discover', 'ecommerce-audit-agent'); ?></span><h3><?php esc_html_e('Technical foundations', 'ecommerce-audit-agent'); ?></h3><p><?php esc_html_e('Review page metadata, crawl signals, canonical hints, structured data, transport and selected security headers.', 'ecommerce-audit-agent'); ?></p></article>
        <article class="info-card"><span class="card-kicker"><?php esc_html_e('Understand', 'ecommerce-audit-agent'); ?></span><h3><?php esc_html_e('Customer experience', 'ecommerce-audit-agent'); ?></h3><p><?php esc_html_e('Inspect mobile layout signals, accessibility review cues, trust information and visible conversion paths.', 'ecommerce-audit-agent'); ?></p></article>
        <article class="info-card"><span class="card-kicker"><?php esc_html_e('Prioritize', 'ecommerce-audit-agent'); ?></span><h3><?php esc_html_e('Evidence-backed actions', 'ecommerce-audit-agent'); ?></h3><p><?php esc_html_e('Use finding status, evidence references and remediation guidance to decide what deserves attention first.', 'ecommerce-audit-agent'); ?></p></article>
      </div>
    </div>
  </section>

  <section class="section section-soft">
    <div class="wrap split">
      <div>
        <span class="card-kicker"><?php esc_html_e('A transparent process', 'ecommerce-audit-agent'); ?></span>
        <h2><?php esc_html_e('Know what was checked—and what was not.', 'ecommerce-audit-agent'); ?></h2>
        <p><?php esc_html_e('Audits use bounded page and signal coverage. Results distinguish observed evidence from manual-review suggestions and checks that could not be completed.', 'ecommerce-audit-agent'); ?></p>
        <a class="button button-secondary" href="<?php echo esc_url(eaa_theme_page_url('how-it-works')); ?>"><?php esc_html_e('See how it works', 'ecommerce-audit-agent'); ?></a>
      </div>
      <div class="metric-row">
        <div class="metric"><strong><?php esc_html_e('Evidence', 'ecommerce-audit-agent'); ?></strong><span><?php esc_html_e('Findings tied to observable signals', 'ecommerce-audit-agent'); ?></span></div>
        <div class="metric"><strong><?php esc_html_e('Coverage', 'ecommerce-audit-agent'); ?></strong><span><?php esc_html_e('Inspected pages and disclosed limits', 'ecommerce-audit-agent'); ?></span></div>
        <div class="metric"><strong><?php esc_html_e('Action', 'ecommerce-audit-agent'); ?></strong><span><?php esc_html_e('Practical next steps for your team', 'ecommerce-audit-agent'); ?></span></div>
      </div>
    </div>
  </section>

  <section class="section">
    <div class="wrap">
      <div class="section-heading">
        <span class="card-kicker"><?php esc_html_e('Choose your workflow', 'ecommerce-audit-agent'); ?></span>
        <h2><?php esc_html_e('For store owners, growing teams and agencies', 'ecommerce-audit-agent'); ?></h2>
        <p><?php esc_html_e('Starter, Pro and Business packages have different allowances and entitlements. The live catalogue determines current availability.', 'ecommerce-audit-agent'); ?></p>
      </div>
      <div class="card-grid">
        <article class="info-card"><h3><?php esc_html_e('Starter', 'ecommerce-audit-agent'); ?></h3><p><?php esc_html_e('For an individual store owner reviewing one connected ecommerce website.', 'ecommerce-audit-agent'); ?></p></article>
        <article class="info-card"><h3><?php esc_html_e('Pro', 'ecommerce-audit-agent'); ?></h3><p><?php esc_html_e('For growing ecommerce teams that need higher audit capacity and supported white-label branding.', 'ecommerce-audit-agent'); ?></p></article>
        <article class="info-card"><h3><?php esc_html_e('Business', 'ecommerce-audit-agent'); ?></h3><p><?php esc_html_e('For agencies using client workspaces, team access and supported direct API capabilities.', 'ecommerce-audit-agent'); ?></p></article>
      </div>
      <p style="text-align:center;margin-top:28px"><a class="button" href="<?php echo esc_url(eaa_theme_page_url('pricing')); ?>"><?php esc_html_e('View live package catalogue', 'ecommerce-audit-agent'); ?></a></p>
    </div>
  </section>
</main>
<?php get_footer(); ?>
