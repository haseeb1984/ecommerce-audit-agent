import pytest

from scan_api import _validate_single_site_submission


def test_bulk_scan_accepts_multiple_pages_from_one_store():
    _validate_single_site_submission([
        "https://shop.example/",
        "https://shop.example/products/item-a",
        "https://shop.example/collections/sale",
    ])


def test_bulk_scan_rejects_urls_from_multiple_stores():
    with pytest.raises(ValueError, match="same ecommerce website"):
        _validate_single_site_submission([
            "https://shop-one.example/",
            "https://shop-two.example/products/item-a",
        ])


def test_bulk_scan_rejects_empty_site_submission():
    with pytest.raises(ValueError, match="same ecommerce website"):
        _validate_single_site_submission([])
