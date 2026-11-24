from pathlib import Path


def test_public_marketing_contact_uses_signed_backend_delivery_not_wp_mail():
    root = Path(__file__).resolve().parents[1]
    theme = root / "wordpress-theme" / "ecommerce-audit-agent"
    functions = (theme / "functions.php").read_text(encoding="utf-8")
    footer = (theme / "footer.php").read_text(encoding="utf-8")
    header = (theme / "header.php").read_text(encoding="utf-8")
    backend = (root / "main.py").read_text(encoding="utf-8")

    assert """href="<?php echo esc_url(eaa_theme_api_base() . '/app'); ?>"""" in header
    assert "ecommerce-audit-agent.vercel.app/app" not in header
    assert "wp_mail(" not in functions
    assert "get_option('admin_email')" not in functions
    assert "get_option('admin_email')" not in footer
    assert "wp_remote_post(eaa_theme_api_base() . '/api/v1/public/contact'" in functions
    assert "hash_hmac('sha256'" in functions
    assert "X-EAA-Timestamp" in functions
    assert "X-EAA-Signature" in functions
    assert "eaa_theme_whatsapp_number" in functions
    assert "eaa_theme_whatsapp_cta" in functions
    assert "https://juncsys.com" in footer
    assert '@app.post("/api/v1/public/contact")' in backend
    assert "EAA_CONTACT_FORM_SECRET" in backend
    assert "EAA_CONTACT_TO_EMAIL" in backend
    assert 'mail["Reply-To"] = email' in backend
    assert 'formataddr(("Ecommerce Audit Agent", sender_address))' in backend
    assert "_send_email_message" in backend
