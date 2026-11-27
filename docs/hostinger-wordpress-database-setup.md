# Hostinger WordPress database setup

## One existing MySQL database — no new database

The SaaS runs its operational tables inside the **same existing Hostinger MySQL database used by the WordPress installation**. Do not create a second Hostinger database. The backend's `HOSTINGER_DATABASE_URL` must connect to that existing WordPress database, using a MySQL user with the required table privileges.

The Supabase PostgreSQL database remains separate and unchanged; it continues to own canonical licenses and audit-engine data. Thus the architecture has one existing Hostinger/MySQL database shared by WordPress and SaaS operational tables, plus the existing Supabase/PostgreSQL database.

## SaaS operational tables

The SaaS operational schema is defined by `migrations/hostinger_operational_schema.sql` and the applicable Hostinger/MySQL incremental migrations. These tables are created in the existing WordPress database alongside the WordPress tables. The SaaS backend accesses them through its Hostinger MySQL connection; it does not create or connect to another physical database.

Apply the reviewed baseline and only the required forward migrations to the existing WordPress database during the approved release procedure. Do not import PostgreSQL migrations into MySQL. Back up the existing WordPress database first, inspect its current schema, and avoid replaying incremental migrations already represented in the fresh baseline.

## WordPress plugin ownership

The customer WordPress plugin continues to use WordPress's global `$wpdb` connection and active `$wpdb->prefix` for any plugin-owned tables. Plugin-owned tables, if/when defined, must be created/upgraded by `dbDelta()`; the plugin must not create another database or connect directly to the SaaS operational tables. Deactivation must preserve plugin data, and uninstall must follow the documented retention policy.

The SaaS operational schema is **not** a plugin-owned schema and must not be created by plugin activation. Its migration files are applied to the existing WordPress database by the approved SaaS database setup procedure.

## Existing marketing site

The theme at `wordpress-theme/ecommerce-audit-agent/` creates pages and menus using WordPress APIs and stores its configuration in WordPress options. It does not create databases or provision SaaS operational tables.