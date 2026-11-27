# WordPress plugin database setup

This is the agreed database contract for the customer WordPress plugin and the marketing site at audit.juncsys.com.

## One existing WordPress database

The WordPress installation already has its own Hostinger MySQL database. The Ecommerce Audit Agent plugin uses that same database through WordPress's global `$wpdb` connection and the active `$wpdb->prefix`. It must not create, request, or connect to a second database.

## Plugin-owned custom tables

The plugin is responsible for creating and upgrading its own custom tables automatically with WordPress's `dbDelta()` API. The schema version is tracked in a WordPress option so activation and upgrades can apply additive schema changes safely. The site owner installs/activates the plugin in wp-admin; no phpMyAdmin import, SQL file, or separate manual migration is part of WordPress plugin installation.

Plugin deactivation must not drop tables. Uninstall behavior must preserve customer data unless a clearly documented and explicitly selected data-removal policy says otherwise.

## Keep SaaS databases separate

- **WordPress Hostinger database:** WordPress core tables plus the plugin's custom tables, all under the existing WordPress database and prefix.
- **Hostinger SaaS operational MySQL:** SaaS customer/account, queue, billing mirror, WordPress registry and private-report metadata. Its schema baseline is `migrations/hostinger_operational_schema.sql`.
- **Supabase PostgreSQL:** canonical licenses and audit-engine data.

The backend migration `migrations/20261031_wordpress_sites.sql` is for the Hostinger SaaS operational database. It creates the backend's WordPress-site registry; it is not intended for the WordPress database and must not be imported into WordPress.

## Existing marketing site

The theme at `wordpress-theme/ecommerce-audit-agent/` creates pages and menus using WordPress APIs and stores its configuration in WordPress options. It does not provision databases. The customer integration plugin is separately installed where a WordPress/WooCommerce store is to be connected to the SaaS.
