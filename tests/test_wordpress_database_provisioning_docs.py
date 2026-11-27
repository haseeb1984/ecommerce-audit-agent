from pathlib import Path


def test_saas_operational_tables_share_existing_hostinger_wordpress_database():
    integration = Path("docs/wordpress-integration.md").read_text(encoding="utf-8")
    runbook = Path("docs/hostinger-wordpress-database-setup.md").read_text(encoding="utf-8")
    rollout = Path("docs/database-integrations-rollout.md").read_text(encoding="utf-8")

    assert "same existing Hostinger MySQL database used by the WordPress installation" in integration
    assert "Do not provision a separate Hostinger database" in integration
    assert "same existing WordPress database" in runbook
    assert "must point to that existing WordPress database" in runbook
    assert "same existing Hostinger MySQL database used by WordPress" in rollout
    assert "no new Hostinger database is provisioned" in rollout


def test_saas_operational_schema_is_not_created_by_wordpress_plugin_activation():
    runbook = Path("docs/hostinger-wordpress-database-setup.md").read_text(encoding="utf-8")
    integration = Path("docs/wordpress-integration.md").read_text(encoding="utf-8")

    assert "not a plugin-owned schema" in runbook
    assert "must not be created by plugin activation" in runbook
    assert "not plugin-activation migrations" in integration
    assert "HOSTINGER_DATABASE_URL" in integration
    assert "migrations/hostinger_operational_schema.sql" in integration


def test_supabase_remains_the_only_separate_saas_database():
    runbook = Path("docs/hostinger-wordpress-database-setup.md").read_text(encoding="utf-8")
    assert "Supabase PostgreSQL database remains separate" in runbook
    assert "Do not create a second Hostinger database" in runbook
