from document_basics_checks import inspect_document_basics


def test_document_basics_detects_missing_language_charset_title_and_landmarks():
    findings = inspect_document_basics(
        "<html><head></head><body><div>Store</div></body></html>",
        "https://shop.example/",
    )

    titles = {finding.title for finding in findings}
    assert "Document language is not declared in the HTML element" in titles
    assert "Character encoding declaration not detected" in titles
    assert "Non-empty page title not detected" in titles
    assert "No common semantic landmark elements detected" in titles
    assert all(finding.status == "manual_review_required" for finding in findings)


def test_document_basics_accepts_declared_metadata_and_semantic_landmarks():
    findings = inspect_document_basics(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        "<title>Shop home</title></head><body><header>Header</header>"
        "<nav>Menu</nav><main>Products</main><footer>Footer</footer></body></html>",
        "https://shop.example/",
    )

    assert findings == []


def test_document_basics_flags_duplicate_titles_but_does_not_infer_encoding_failure():
    findings = inspect_document_basics(
        '<html lang="en"><head><title>One</title><title>Two</title>'
        '</head><body><main>Content</main></body></html>',
        "https://shop.example/",
    )

    titles = {finding.title for finding in findings}
    assert "Multiple non-empty title elements detected" in titles
    assert "Character encoding declaration not detected" in titles
    assert "Document language is not declared in the HTML element" not in titles
    assert "No common semantic landmark elements detected" not in titles
