"""
tests/test_phone.py — unit tests for modules/phone.py

Tests normalization, country detection, format generation.
No network calls. Instant.
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.phone import normalize, detect_country, make_formats, scan_phone


class TestNormalize:
    def test_strips_spaces(self):
        assert normalize("+91 98765 43210") == "+919876543210"

    def test_strips_dashes(self):
        assert normalize("+1-800-555-0199") == "+18005550199"

    def test_strips_parens(self):
        assert normalize("+1 (415) 555-2671") == "+14155552671"

    def test_preserves_plus(self):
        result = normalize("+919876543210")
        assert result.startswith("+")

    def test_no_plus(self):
        result = normalize("9876543210")
        assert not result.startswith("+")


class TestDetectCountry:
    def test_india(self):
        result = detect_country("+919876543210")
        assert result["country"] == "India"
        assert result["prefix"] == "+91"
        assert result["flag"] == "🇮🇳"

    def test_usa(self):
        result = detect_country("+14155552671")
        assert "USA" in result["country"]
        assert result["prefix"] == "+1"

    def test_uk(self):
        result = detect_country("+447911123456")
        assert result["country"] == "UK"
        assert result["prefix"] == "+44"

    def test_germany(self):
        result = detect_country("+4915123456789")
        assert result["country"] == "Germany"

    def test_unknown_prefix(self):
        result = detect_country("+9999999999")
        assert result["country"] == "Unknown"
        assert result["flag"] == "🌐"

    def test_three_digit_prefix(self):
        result = detect_country("+8801712345678")
        assert result["country"] == "Bangladesh"
        assert result["prefix"] == "+880"


class TestMakeFormats:
    def test_returns_list(self):
        result = make_formats("+919876543210")
        assert isinstance(result, list)
        assert len(result) > 0

    def test_contains_original(self):
        result = make_formats("+919876543210")
        assert "+919876543210" in result

    def test_contains_digits_only(self):
        result = make_formats("+919876543210")
        assert "919876543210" in result

    def test_no_duplicates(self):
        result = make_formats("+919876543210")
        assert len(result) == len(set(result))


class TestScanPhone:
    def test_returns_dict(self):
        result = scan_phone("+919876543210")
        assert isinstance(result, dict)

    def test_has_required_keys(self):
        result = scan_phone("+919876543210")
        required = ["type", "query", "normalized", "country", "formats",
                    "score", "chips", "deep_links"]
        for key in required:
            assert key in result, f"Missing key: {key}"

    def test_type_is_phone(self):
        result = scan_phone("+919876543210")
        assert result["type"] == "phone"

    def test_score_in_range(self):
        result = scan_phone("+919876543210")
        assert 0 <= result["score"] <= 100

    def test_deep_links_present(self):
        result = scan_phone("+919876543210")
        assert len(result["deep_links"]) > 0
        for link in result["deep_links"]:
            assert "label" in link
            assert "url" in link
            assert link["url"].startswith("http")

    def test_chips_present(self):
        result = scan_phone("+919876543210")
        assert len(result["chips"]) > 0
        for chip in result["chips"]:
            assert "label" in chip
            assert "color" in chip

    def test_india_detected(self):
        result = scan_phone("+919876543210")
        assert result["country"]["country"] == "India"

    def test_whatsapp_link_in_deeplinks(self):
        result = scan_phone("+919876543210")
        labels = [l["label"] for l in result["deep_links"]]
        assert "WhatsApp" in labels
