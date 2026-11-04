"""Compare source-visible product offer signals with Product JSON-LD.

This is a conservative static-HTML check. It never infers a currency from an
ambiguous symbol and never treats missing or variant-ambiguous signals as a pass.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from html.parser import HTMLParser
import json
import re
from typing import Any

from audit_checks import AuditFinding, CheckOutcome, _finding


_PRICE_TOKEN = re.compile(
    r"(?<![\w.])(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{1,2})?(?![\w.])"
)
_CURRENCY_TOKEN = re.compile(r"(?<![A-Za-z])([A-Z]{3})(?![A-Za-z])")
_AVAILABILITY_MAP = {
    "instock": "in_stock", "available": "in_stock", "in stock": "in_stock",
    "in-stock": "in_stock", "outofstock": "out_of_stock",
    "out of stock": "out_of_stock", "out-of-stock": "out_of_stock",
    "soldout": "out_of_stock", "sold out": "out_of_stock",
    "unavailable": "out_of_stock", "backorder": "backorder",
    "preorder": "preorder", "pre order": "preorder",
    "presale": "preorder", "discontinued": "discontinued",
}


class _VisibleProductSignals(HTMLParser):
    """Collect narrowly scoped, non-hidden semantic product values from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: dict[str, list[str]] = {
            "price": [], "currency": [], "availability": [], "name": [], "sku": [], "gtin": []
        }
        self._hidden_stack: list[bool] = []
        self._captures: list[dict[str, Any]] = []

    @staticmethod
    def _add(values: list[str], value: Any) -> None:
        if isinstance(value, str) and value.strip():
            cleaned = re.sub(r"\s+", " ", value).strip()
            if cleaned and cleaned not in values:
                values.append(cleaned)

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs_map = {key.lower(): (value or "") for key, value in attrs}
        style = attrs_map.get("style", "").replace(" ", "").lower()
        parent_hidden = self._hidden_stack[-1] if self._hidden_stack else False
        hidden = parent_hidden or "hidden" in attrs_map or attrs_map.get("aria-hidden", "").lower() == "true" or "display:none" in style or "visibility:hidden" in style
        self._hidden_stack.append(hidden)
        if hidden:
            if tag.lower() in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
                self._hidden_stack.pop()
            return

        itemprops = {token.lower() for token in re.split(r"\s+", attrs_map.get("itemprop", "").strip()) if token}
        classes = set(re.split(r"[^a-z0-9]+", (attrs_map.get("class", "") + " " + attrs_map.get("id", "")).lower()))
        capture_keys: list[str] = []
        if "price" in itemprops or "price" in classes or ({"product", "sale", "current"} & classes and "price" in classes):
            capture_keys.append("price")
        if "pricecurrency" in itemprops or "currency" in classes or "currency-code" in classes or "data-currency" in attrs_map:
            capture_keys.append("currency")
        if "availability" in itemprops or classes.intersection({"availability", "stock", "stock-status", "availability-status", "inventory-status"}):
            capture_keys.append("availability")
        if tag.lower() == "h1" or "name" in itemprops:
            capture_keys.append("name")
        if "sku" in itemprops or classes.intersection({"sku", "product-sku", "item-sku"}):
            capture_keys.append("sku")
        if itemprops.intersection({"gtin", "gtin8", "gtin12", "gtin13", "gtin14"}) or classes.intersection({"gtin", "barcode", "product-barcode", "barcode-number"}):
            capture_keys.append("gtin")

        void_tags = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
        if tag.lower() in void_tags:
            capture_keys = []

        for key in capture_keys:
            record = {"tag": tag.lower(), "key": key, "parts": []}
            self._captures.append(record)
            # Semantic attributes are useful when the element has no text node.
            attr_value = attrs_map.get("content") or attrs_map.get("value")
            if key == "price":
                attr_value = attrs_map.get("content") or attrs_map.get("data-price") or attrs_map.get("value") or attr_value
            elif key == "currency":
                attr_value = attrs_map.get("content") or attrs_map.get("data-currency") or attr_value
            elif key == "availability":
                attr_value = attrs_map.get("content") or attrs_map.get("data-availability") or attr_value
            elif key == "sku":
                attr_value = attrs_map.get("content") or attrs_map.get("data-sku") or attrs_map.get("value") or attr_value
            elif key == "gtin":
                attr_value = attrs_map.get("content") or attrs_map.get("data-gtin") or attrs_map.get("data-barcode") or attrs_map.get("value") or attr_value
            if attr_value:
                record["parts"].append(attr_value)

        # HTML void elements have no end tag; do not let them corrupt the
        # inherited-hidden stack for the remaining document.
        if tag.lower() in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            if self._hidden_stack:
                self._hidden_stack.pop()

    def handle_data(self, data: str) -> None:
        if self._hidden_stack and self._hidden_stack[-1]:
            return
        for record in self._captures:
            record["parts"].append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        for index in range(len(self._captures) - 1, -1, -1):
            if self._captures[index]["tag"] == tag:
                record = self._captures.pop(index)
                self._add(self.values[record["key"]], " ".join(record["parts"]))
                break
        if self._hidden_stack:
            self._hidden_stack.pop()

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.handle_endtag(tag)


def _jsonld_product_offers(html: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, list[str]]]:
    parser = _VisibleProductSignals()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass
    offers: list[dict[str, Any]] = []
    products: list[dict[str, Any]] = []
    for script_match in re.finditer(
        r"""<script\b[^>]*type\s*=\s*['"]application/ld\+json['"][^>]*>(.*?)</script\s*>""",
        html,
        re.I | re.S,
    ):
        try:
            root = json.loads(script_match.group(1))
        except (json.JSONDecodeError, TypeError):
            continue
        stack = [root]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                raw_type = node.get("@type", [])
                types = raw_type if isinstance(raw_type, list) else [raw_type]
                normalized = {
                    item.strip().rstrip("/").rsplit("/", 1)[-1].rsplit("#", 1)[-1].lower()
                    for item in types if isinstance(item, str)
                }
                if "product" in normalized:
                    products.append(node)
                    raw_offers = node.get("offers", [])
                    if isinstance(raw_offers, dict):
                        raw_offers = [raw_offers]
                    if isinstance(raw_offers, list):
                        offers.extend(item for item in raw_offers if isinstance(item, dict))
                stack.extend(value for value in node.values() if isinstance(value, (dict, list)))
            elif isinstance(node, list):
                stack.extend(node)
    return products, offers, parser.values


def _decimal_values(values: list[str]) -> set[Decimal]:
    parsed: set[Decimal] = set()
    for value in values:
        # Attribute and visible text may repeat the same price; collapse identical tokens only.
        matches = set(_PRICE_TOKEN.findall(value.replace("\\u00a0", " ")))
        if len(matches) != 1:
            continue
        token = next(iter(matches)).replace(",", "")
        try:
            number = Decimal(token)
        except (InvalidOperation, ValueError):
            continue
        if number.is_finite() and number >= 0:
            parsed.add(number)
    return parsed


def _currency_values(values: list[str]) -> set[str]:
    result: set[str] = set()
    for value in values:
        token = value.strip().upper()
        if re.fullmatch(r"[A-Z]{3}", token):
            result.add(token)
        else:
            result.update(match.upper() for match in _CURRENCY_TOKEN.findall(token))
    return result


def _availability_values(values: list[str]) -> set[str]:
    result: set[str] = set()
    for value in values:
        token = value.strip().lower().rstrip("/").rsplit("/", 1)[-1]
        token = re.sub(r"([a-z])([A-Z])", r"\1 \2", token).replace("_", " ")
        compact = re.sub(r"[^a-z]", "", token)
        normalized = _AVAILABILITY_MAP.get(token) or _AVAILABILITY_MAP.get(compact)
        if normalized:
            result.add(normalized)
    return result

def _is_valid_gtin(value: str) -> bool:
    """Validate supported GTIN lengths and the GS1 modulo-10 check digit."""
    if len(value) not in {8, 12, 13, 14} or not value.isdigit():
        return False
    weighted_sum = sum(
        int(digit) * (3 if position % 2 == 0 else 1)
        for position, digit in enumerate(reversed(value[:-1]))
    )
    expected_check_digit = (10 - weighted_sum % 10) % 10
    return expected_check_digit == int(value[-1])


def _identifier_values(values: list[str], *, gtin: bool = False) -> set[str]:
    """Normalize explicitly visible product identifiers without guessing missing digits."""
    result: set[str] = set()
    for value in values:
        if gtin:
            digits = re.sub(r"[^0-9]", "", value)
            # Semantic attributes and visible text can repeat the same GTIN.
            if len(digits) in {16, 24, 26, 28} and digits[:len(digits) // 2] == digits[len(digits) // 2:]:
                digits = digits[:len(digits) // 2]
            if _is_valid_gtin(digits):
                result.add(digits)
        else:
            parts = re.sub(r"\\s+", " ", value).strip().upper().split()
            if not parts:
                continue
            result.add(parts[0] if len(set(parts)) == 1 else " ".join(parts))
    return result


def inspect_visible_product_consistency(
    html: str, page_url: str, checked_at_utc: str | None = None
) -> tuple[list[AuditFinding], list[CheckOutcome]]:
    """Compare visible product offer values with JSON-LD when both are unambiguous."""
    checked_at = checked_at_utc or datetime.now(timezone.utc).isoformat()
    products, offers, visible = _jsonld_product_offers(html)
    findings: list[AuditFinding] = []
    outcomes: list[CheckOutcome] = []

    def record(check_id: str, outcome: str, evidence: str, title: str, explanation: str) -> None:
        outcomes.append(CheckOutcome(
            check_id=check_id, category="structured_data", page_url=page_url,
            outcome=outcome, observed_at_utc=checked_at,
            method="Static HTML comparison of visible semantic product signals and Product/Offer JSON-LD",
            evidence=evidence,
        ))
        if outcome == "issue":
            findings.append(_finding(
                "structured_data", title, "verified", "medium", evidence,
                explanation,
                "Align the product's visible selected/default offer and Product/Offer JSON-LD using the same current catalog source. Check all variants before changing price or stock data.",
                ["Inspect the visible product page and selected/default variant.", "Compare the exact source values in Product/Offer JSON-LD.", "Retest the page and representative variant URLs after correcting the catalog/template source."],
                page_url,
            ))

    # Multiple offers/prices commonly represent selectable variants or price ranges.
    # Without a browser-selected variant, do not choose one arbitrarily.
    schema_prices: set[Decimal] = set()
    for offer in offers:
        raw = offer.get("price")
        values = [str(raw)] if isinstance(raw, (str, int, float)) and not isinstance(raw, bool) else []
        schema_prices.update(_decimal_values(values))
    visible_prices = _decimal_values(visible["price"])
    if not products or not offers or len(schema_prices) != 1 or len(visible_prices) != 1:
        reason = (
            f"Visible price values parsed: {len(visible_prices)}; distinct Product/Offer prices parsed: {len(schema_prices)}; "
            f"Product entities: {len(products)}; Offer objects: {len(offers)}. "
            "Comparison not assessed because one side is missing, unparsable, or variant/range ambiguous."
        )
        record("structured_data.visible_price_consistency", "not_assessed", reason, "", "")
    else:
        matches = visible_prices == schema_prices
        evidence = f"Visible semantic price: {next(iter(visible_prices))}; Product/Offer JSON-LD price: {next(iter(schema_prices))}."
        record(
            "structured_data.visible_price_consistency", "pass" if matches else "issue",
            evidence, "Visible product price differs from structured offer price",
            "The initial HTML exposes different visible and structured offer prices. This may affect how consumers interpret product information; the check does not determine which source is commercially authoritative.",
        )

    schema_currencies = {
        str(offer.get("priceCurrency", "")).strip().upper()
        for offer in offers
        if isinstance(offer.get("priceCurrency"), str) and re.fullmatch(r"[A-Za-z]{3}", offer["priceCurrency"].strip())
    }
    visible_currencies = _currency_values(visible["currency"])
    if not products or not offers or len(schema_currencies) != 1 or len(visible_currencies) != 1:
        record(
            "structured_data.visible_currency_consistency", "not_assessed",
            f"Visible explicit currency codes: {len(visible_currencies)}; distinct Offer currency codes: {len(schema_currencies)}. Comparison not assessed because an explicit, unambiguous currency was not available on both sides.",
            "", "",
        )
    else:
        matches = visible_currencies == schema_currencies
        evidence = f"Visible currency code: {next(iter(visible_currencies))}; Product/Offer JSON-LD currency: {next(iter(schema_currencies))}."
        record(
            "structured_data.visible_currency_consistency", "pass" if matches else "issue",
            evidence, "Visible product currency differs from structured offer currency",
            "The initial HTML exposes different visible and structured currency codes. Currency symbols alone are not used because symbols such as $ can represent multiple currencies.",
        )

    schema_availability = _availability_values([
        str(offer.get("availability", "")) for offer in offers
        if isinstance(offer.get("availability"), str)
    ])
    visible_availability = _availability_values(visible["availability"])
    if not products or not offers or len(schema_availability) != 1 or len(visible_availability) != 1:
        record(
            "structured_data.visible_availability_consistency", "not_assessed",
            f"Visible availability states parsed: {len(visible_availability)}; Offer availability states parsed: {len(schema_availability)}. Comparison not assessed because a clear state was not available on both sides or multiple variants differ.",
            "", "",
        )
    else:
        matches = visible_availability == schema_availability
        evidence = f"Visible availability: {next(iter(visible_availability))}; Product/Offer JSON-LD availability: {next(iter(schema_availability))}."
        record(
            "structured_data.visible_availability_consistency", "pass" if matches else "issue",
            evidence, "Visible stock status differs from structured offer availability",
            "The initial HTML exposes different visible and structured availability states. This static check cannot verify real-time inventory, fulfillment eligibility, or the state after a customer selects another variant.",
        )


    # Product title is a customer-visible identity signal. Compare only one
    # unambiguous H1 and one Product entity; do not normalize away meaningful text.
    visible_names = {
        re.sub(r"\\s+", " ", value).strip().casefold()
        for value in visible["name"] if value.strip()
    }
    schema_names = {
        re.sub(r"\\s+", " ", str(product.get("name"))).strip().casefold()
        for product in products
        if isinstance(product.get("name"), str) and product.get("name").strip()
    }
    if len(products) != 1 or len(schema_names) != 1 or len(visible_names) != 1:
        record(
            "structured_data.visible_name_consistency", "not_assessed",
            f"Visible product names: {len(visible_names)}; Product JSON-LD names: {len(schema_names)}; Product entities: {len(products)}. Comparison not assessed because one clear name and Product entity were not available.",
            "", "",
        )
    else:
        matches = visible_names == schema_names
        evidence = f"Visible product name: {next(iter(visible_names))}; Product JSON-LD name: {next(iter(schema_names))}."
        record(
            "structured_data.visible_name_consistency", "pass" if matches else "issue",
            evidence, "Visible product name differs from structured product name",
            "The initial HTML exposes a different product title from Product JSON-LD. Confirm the canonical product title and selected variant before changing the page or structured data.",
        )

    # SKU and GTIN are useful catalogue identifiers, but pages often omit them
    # or expose several variant identifiers. Only compare one explicit value
    # on each side; never select a variant identifier arbitrarily.
    for visible_key, schema_keys, check_id, label, is_gtin in (
        ("sku", ("sku",), "structured_data.visible_sku_consistency", "SKU", False),
        ("gtin", ("gtin", "gtin8", "gtin12", "gtin13", "gtin14"), "structured_data.visible_gtin_consistency", "GTIN", True),
    ):
        schema_values = _identifier_values([
            str(product.get(key))
            for product in products
            for key in schema_keys
            if isinstance(product.get(key), (str, int)) and not isinstance(product.get(key), bool)
        ], gtin=is_gtin)
        visible_values = _identifier_values(visible[visible_key], gtin=is_gtin)
        if len(products) != 1 or len(schema_values) != 1 or len(visible_values) != 1:
            record(
                check_id, "not_assessed",
                f"Visible {label} identifiers: {len(visible_values)}; Product JSON-LD {label} identifiers: {len(schema_values)}. Comparison not assessed because an explicit single identifier was not available on both sides or multiple variants were present.",
                "", "",
            )
        else:
            matches = visible_values == schema_values
            evidence = f"Visible {label}: {next(iter(visible_values))}; Product JSON-LD {label}: {next(iter(schema_values))}."
            record(
                check_id, "pass" if matches else "issue", evidence,
                f"Visible product {label} differs from structured product {label}",
                f"The initial HTML exposes a different visible {label} and Product JSON-LD identifier. Confirm the selected product variant and source catalogue record before changing identifiers.",
            )
    return findings, outcomes
