from pathlib import Path


def test_wordpress_integration_documents_plugin_owned_tables_in_existing_wp_database():
    doc = Path("docs/wordpress-integration.md").read_text(encoding="utf-8")
    assert "existing Hostinger MySQL database" in doc
    assert "dbDelta()" in doc
    assert "No separate database" in doc
    assert "No manual SQL migration" in doc
    assert "migrations/20261031_wordpress_sites.sql" in doc
    assert "not a migration for the customer's WordPress database" in doc


def test_wordpress_database_runbook_does_not_instruct_separate_wp_database_creation():
    doc = Path("docs/hostinger-wordpress-database-setup.md").read_text(encoding="utf-8")
    assert "same database through WordPress's global" in doc
    assert "must not create, request, or connect to a second database" in doc
    assert "dbDelta()" in doc
    assert "no phpMyAdmin import, SQL file, or separate manual migration" in doc
    assert "not intended for the WordPress database" in doc
    assert "create a dedicated MySQL database" not in doc
