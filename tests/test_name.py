"""
tests/test_name.py — unit tests for modules/name.py

Tests dork generation and scan structure.
Mocks web search to avoid network calls.
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch
from modules.name import scan_name, _build_dorks


class TestBuildDorks:
    def test_returns_14_dorks(self):
        dorks = _build_dorks("John Doe", '"John Doe"')
        assert len(dorks) == 14

    def test_each_dork_has_required_keys(self):
        dorks = _build_dorks("John Doe", '"John Doe"')
        for dork in dorks:
            assert "label" in dork
            assert "query" in dork
            assert "url"   in dork
            assert "icon"  in dork

    def test_dork_urls_are_google(self):
        dorks = _build_dorks("John Doe", '"John Doe"')
        for dork in dorks:
            assert "google.com" in dork["url"]

    def test_name_in_queries(self):
        dorks = _build_dorks("John Doe", '"John Doe"')
        for dork in dorks:
            assert "John Doe" in dork["query"] or "John Doe" in dork["url"]

    def test_linkedin_dork_exists(self):
        dorks = _build_dorks("John Doe", '"John Doe"')
        labels = [d["label"] for d in dorks]
        assert "LinkedIn profiles" in labels

    def test_pdf_dork_exists(self):
        dorks = _build_dorks("John Doe", '"John Doe"')
        labels = [d["label"] for d in dorks]
        assert "PDF documents" in labels


class TestScanName:
    @patch("modules.name.search", return_value=[
        {"title": "John Doe | LinkedIn", "link": "https://linkedin.com/in/johndoe", "snippet": "Software Engineer"},
        {"title": "John Doe GitHub",      "link": "https://github.com/johndoe",     "snippet": "Developer"},
        {"title": "John Doe Blog",         "link": "https://johndoe.medium.com",     "snippet": "Writer"},
    ])
    def test_returns_dict(self, mock_search):
        result = scan_name("John Doe")
        assert isinstance(result, dict)

    @patch("modules.name.search", return_value=[])
    def test_has_required_keys(self, mock_search):
        result = scan_name("John Doe")
        required = ["type", "query", "score", "chips", "dorks",
                    "web_results", "social_hits", "general_hits", "deep_links"]
        for key in required:
            assert key in result, f"Missing key: {key}"

    @patch("modules.name.search", return_value=[])
    def test_type_is_name(self, mock_search):
        result = scan_name("John Doe")
        assert result["type"] == "name"

    @patch("modules.name.search", return_value=[])
    def test_score_in_range(self, mock_search):
        result = scan_name("John Doe")
        assert 0 <= result["score"] <= 100

    @patch("modules.name.search", return_value=[
        {"title": "John Doe LinkedIn", "link": "https://linkedin.com/in/johndoe", "snippet": "Engineer"},
        {"title": "John Doe GitHub",   "link": "https://github.com/johndoe",     "snippet": "Dev"},
    ])
    def test_social_hits_detected(self, mock_search):
        result = scan_name("John Doe")
        assert len(result["social_hits"]) > 0

    @patch("modules.name.search", return_value=[])
    def test_filters_appended(self, mock_search):
        result = scan_name("John Doe", filters=["Kolkata", "Python Developer"])
        assert result["filters"] == ["Kolkata", "Python Developer"]

    @patch("modules.name.search", return_value=[])
    def test_14_dorks_always_generated(self, mock_search):
        result = scan_name("Jane Smith")
        assert len(result["dorks"]) == 14

    @patch("modules.name.search", return_value=[])
    def test_deep_links_present(self, mock_search):
        result = scan_name("John Doe")
        assert len(result["deep_links"]) > 0
        for link in result["deep_links"]:
            assert "label" in link
            assert "url"   in link
