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
        "<title>Shop home</title><meta name=\"description\" content=\"A useful shop description.\"></head><body><header>Header</header>"
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


def test_document_basics_flags_missing_meta_description():
    findings = inspect_document_basics(
        '<html lang="en"><head><meta charset="utf-8"><title>Shop</title></head>'
        '<body><main>Products</main></body></html>',
        "https://shop.example/products/",
    )
    assert "Non-empty meta description not detected" in {finding.title for finding in findings}


def test_document_basics_flags_duplicate_meta_descriptions_and_accepts_one():
    one = inspect_document_basics(
        '<html lang="en"><head><meta charset="utf-8"><title>Shop</title>'
        '<meta name="description" content="A useful store description."></head>'
        '<body><main>Products</main></body></html>',
        "https://shop.example/",
    )
    assert not any("meta description" in finding.title.lower() for finding in one)

    duplicate = inspect_document_basics(
        '<html lang="en"><head><title>Shop</title>'
        '<meta name="description" content="First">'
        '<meta name="description" content="Second"></head><body><main>Products</main></body></html>',
        "https://shop.example/",
    )
    assert "Multiple non-empty meta descriptions detected" in {
        finding.title for finding in duplicate
    }


def test_document_basics_advises_on_extremely_long_meta_description_without_ranking_claims():
    description = "A" * 321
    findings = inspect_document_basics(
        '<html lang="en"><head><meta charset="utf-8"><title>Shop</title>'
        f'<meta name="description" content="{description}"></head>'
        '<body><main>Products</main></body></html>',
        "https://shop.example/products/",
    )
    finding = next(item for item in findings if item.title == "Meta description is unusually long")
    assert finding.status == "manual_review_required"
    assert finding.severity == "info"
    assert "does not establish a defect or ranking impact" in finding.impact
    assert description not in finding.evidence
