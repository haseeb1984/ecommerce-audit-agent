from product_consistency_checks import inspect_visible_product_consistency


def _page(price="19.99", currency="USD", availability="In stock"):
    return f"""
    <html><body>
      <h1>Widget</h1>
      <span class="product-price" data-price="{price}">$ {price}</span>
      <span class="currency-code" data-currency="{currency}">{currency}</span>
      <span class="stock-status">{availability}</span>
      <script type="application/ld+json">
      {{
        "@context": "https://schema.org",
        "@type": "Product",
        "name": "Widget",
        "offers": {{
          "@type": "Offer",
          "price": "19.99",
          "priceCurrency": "USD",
          "availability": "https://schema.org/InStock"
        }}
      }}
      </script>
    </body></html>
    """


def test_visible_product_offer_values_matching_jsonld_record_passes():
    findings, outcomes = inspect_visible_product_consistency(
        _page(), "https://shop.example/products/widget", "2026-11-04T00:00:00+00:00"
    )
    by_id = {item.check_id: item for item in outcomes}

    assert not findings
    assert by_id["structured_data.visible_price_consistency"].outcome == "pass"
    assert by_id["structured_data.visible_currency_consistency"].outcome == "pass"
    assert by_id["structured_data.visible_availability_consistency"].outcome == "pass"


def test_visible_price_currency_and_stock_mismatches_are_verified_issues():
    findings, outcomes = inspect_visible_product_consistency(
        _page(price="24.99", currency="EUR", availability="Out of stock"),
        "https://shop.example/products/widget",
    )
    by_id = {item.check_id: item for item in outcomes}

    assert by_id["structured_data.visible_price_consistency"].outcome == "issue"
    assert by_id["structured_data.visible_currency_consistency"].outcome == "issue"
    assert by_id["structured_data.visible_availability_consistency"].outcome == "issue"
    assert len(findings) == 3
    assert all(item.status == "verified" for item in findings)


def test_hidden_price_and_ambiguous_multiple_offer_values_are_not_passed():
    html = """
    <html><body>
      <span class="price" style="display:none">$19.99</span>
      <span class="price">$19.99 - $29.99</span>
      <script type="application/ld+json">
      {"@type":"Product","offers":[
        {"@type":"Offer","price":"19.99","priceCurrency":"USD","availability":"https://schema.org/InStock"},
        {"@type":"Offer","price":"29.99","priceCurrency":"USD","availability":"https://schema.org/OutOfStock"}
      ]}
      </script>
    </body></html>
    """
    findings, outcomes = inspect_visible_product_consistency(
        html, "https://shop.example/products/widget"
    )
    by_id = {item.check_id: item for item in outcomes}

    assert not findings
    assert by_id["structured_data.visible_price_consistency"].outcome == "not_assessed"
    assert by_id["structured_data.visible_availability_consistency"].outcome == "not_assessed"


def test_currency_symbol_alone_does_not_infer_ambiguous_currency():
    html = """
    <html><body>
      <span class="price">$19.99</span>
      <span class="stock-status">In stock</span>
      <script type="application/ld+json">
      {"@type":"Product","offers":{"@type":"Offer","price":"19.99",
       "priceCurrency":"USD","availability":"https://schema.org/InStock"}}
      </script>
    </body></html>
    """
    _, outcomes = inspect_visible_product_consistency(
        html, "https://shop.example/products/widget"
    )
    by_id = {item.check_id: item for item in outcomes}
    assert by_id["structured_data.visible_currency_consistency"].outcome == "not_assessed"


def test_visible_sku_and_gtin_match_product_jsonld_identifiers():
    html = """
    <html><body>
      <h1>Widget</h1>
      <span itemprop="sku">WID-100</span>
      <span itemprop="gtin13">0123456789012</span>
      <script type="application/ld+json">
      {"@type":"Product","name":"Widget","sku":"WID-100","gtin13":"0123456789012",
       "offers":{"@type":"Offer","price":"19.99","priceCurrency":"USD",
        "availability":"https://schema.org/InStock"}}
      </script>
    </body></html>
    """
    _, outcomes = inspect_visible_product_consistency(
        html, "https://shop.example/products/widget"
    )
    by_id = {item.check_id: item for item in outcomes}

    assert by_id["structured_data.visible_sku_consistency"].outcome == "pass"
    assert by_id["structured_data.visible_gtin_consistency"].outcome == "pass"


def test_visible_product_identifier_mismatch_is_verified():
    html = """
    <html><body>
      <h1>Widget</h1>
      <span class="product-sku">WID-200</span>
      <span class="barcode">0123456789012</span>
      <script type="application/ld+json">
      {"@type":"Product","sku":"WID-100","gtin13":"1234567890128"}
      </script>
    </body></html>
    """
    findings, outcomes = inspect_visible_product_consistency(
        html, "https://shop.example/products/widget"
    )
    by_id = {item.check_id: item for item in outcomes}

    assert by_id["structured_data.visible_sku_consistency"].outcome == "issue"
    assert by_id["structured_data.visible_gtin_consistency"].outcome == "issue"
    assert {item.title for item in findings} == {
        "Visible product SKU differs from structured product SKU",
        "Visible product GTIN differs from structured product GTIN",
    }


def test_variant_product_identifiers_are_not_arbitrarily_selected():
    html = """
    <html><body>
      <h1>Widget</h1>
      <span class="sku">WID-100</span>
      <span class="gtin">0123456789012</span>
      <script type="application/ld+json">
      {"@type":"ProductGroup","hasVariant":[
        {"@type":"Product","sku":"WID-100","gtin13":"0123456789012"},
        {"@type":"Product","sku":"WID-200","gtin13":"0123456789013"}
      ]}
      </script>
    </body></html>
    """
    _, outcomes = inspect_visible_product_consistency(
        html, "https://shop.example/products/widget"
    )
    by_id = {item.check_id: item for item in outcomes}

    assert by_id["structured_data.visible_sku_consistency"].outcome == "not_assessed"
    assert by_id["structured_data.visible_gtin_consistency"].outcome == "not_assessed"


def test_malformed_gtin_is_not_treated_as_a_verified_identifier():
    html = """
    <html><body>
      <span class="barcode">12345</span>
      <script type="application/ld+json">
      {"@type":"Product","gtin13":"12345"}
      </script>
    </body></html>
    """
    _, outcomes = inspect_visible_product_consistency(
        html, "https://shop.example/products/widget"
    )
    by_id = {item.check_id: item for item in outcomes}

    assert by_id["structured_data.visible_gtin_consistency"].outcome == "not_assessed"



def test_gtin_with_invalid_check_digit_is_not_assessed():
    html = """
    <html><body>
      <span itemprop="gtin13">0123456789013</span>
      <script type="application/ld+json">
      {"@type":"Product","gtin13":"0123456789013"}
      </script>
    </body></html>
    """
    _, outcomes = inspect_visible_product_consistency(
        html, "https://shop.example/products/widget"
    )
    by_id = {item.check_id: item for item in outcomes}
    assert by_id["structured_data.visible_gtin_consistency"].outcome == "not_assessed"


def test_gtin_supported_lengths_validate_gs1_check_digit():
    from product_consistency_checks import _is_valid_gtin

    assert _is_valid_gtin("12345670")
    assert _is_valid_gtin("123456789012")
    assert _is_valid_gtin("0123456789012")
    assert _is_valid_gtin("10012345000017")
    assert not _is_valid_gtin("0123456789013")
