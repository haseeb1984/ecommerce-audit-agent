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
            "price": [], "currency": [], "availability": [], "name": []
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
            if attr_value:
                record["parts"].append(attr_value)

        # Open Graph product metadata is machine-readable corroboration, not visible UI.
        # Keep it separate from visible text by not treating meta values as visible captures.
        if tag.lower() == "meta":
            property_name = attrs_map.get("property", "").lower()
            itemprop = attrs_map.get("itemprop", "").lower()
            content = attrs_map.get("content", "")
            if property_name in {"product:price:amount", "og:price:amount"} or itemprop == "price":
                self._add(self.values["price"], content)
            elif property_name in {"product:price:currency", "og:price:currency"} or itemprop == "pricecurrency":
                self._add(self.values["currency"], content)
            elif itemprop == "availability":
                self._add(self.values["availability"], content)

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
        r"<script\b[^>]*type\s*=\s*['\\"]application/ld\+json['\\"][^>]*>(.*?)</script\s*>",
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
        matches = _PRICE_TOKEN.findall(value.replace("\u00a0", " "))
        if len(matches) != 1:
            continue
        token = matches[0].replace(",", "")
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

    return findings, outcomes
