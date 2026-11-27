from pathlib import Path


def test_ci_builds_separate_installable_wordpress_theme_and_plugin_packages():
    workflow = Path(".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert "Build WordPress marketing theme package" in workflow
    assert "wordpress-theme-package" in workflow
    assert "ecommerce-audit-agent-theme.zip" in workflow
    assert "Build WordPress customer plugin package" in workflow
    assert "wordpress-plugin-package" in workflow
    assert "ecommerce-audit-agent-plugin.zip" in workflow
    assert "ecommerce-audit-agent/ecommerce-audit-agent.php" in workflow
    assert "ecommerce-audit-agent/uninstall.php" in workflow


def test_hostinger_wordpress_database_runbook_preserves_database_boundaries():
    doc = Path("docs/hostinger-wordpress-database-setup.md").read_text(encoding="utf-8")
    assert "WordPress site database (Hostinger)" in doc
    assert "Hostinger SaaS operational MySQL database" in doc
    assert "Supabase PostgreSQL" in doc
    assert "The marketing theme deliberately creates no custom WordPress tables." in doc
    assert "do not create a second WordPress database" in doc
