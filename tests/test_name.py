"""
tests/test_name.py — unit tests for modules/name.py

Covers the dork definitions and scan structure.
Mocks web search to avoid network calls.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch
from modules.name import scan_name, _run_dork, _DORK_DEFINITIONS


class TestDorkDefinitions:
    def test_has_14_dorks(self):
        assert len(_DORK_DEFINITIONS) == 14

    def test_each_dork_has_required_keys(self):
        for d in _DORK_DEFINITIONS:
            for key in ("label", "icon", "key", "query_tpl"):
                assert key in d

    def test_keys_are_unique(self):
        keys = [d["key"] for d in _DORK_DEFINITIONS]
        assert len(keys) == len(set(keys))

    def test_templates_contain_name_placeholder(self):
        for d in _DORK_DEFINITIONS:
            assert "{name}" in d["query_tpl"]

    def test_expected_platforms_present(self):
        labels = [d["label"] for d in _DORK_DEFINITIONS]
        assert "LinkedIn profiles" in labels
        assert "Instagram profiles" in labels
        assert "PDF documents" in labels


class TestRunDork:
    @patch("modules.name.search", return_value=[])
    def test_query_contains_name_and_google_url(self, _):
        out = _run_dork(_DORK_DEFINITIONS[0], "John Doe", "")
        assert "John Doe" in out["query"]
        assert "google.com/search" in out["url"]
        assert out["found"] is False and out["count"] == 0

    @patch("modules.name.search", return_value=[])
    def test_context_appended(self, _):
        out = _run_dork(_DORK_DEFINITIONS[0], "John Doe", '"Kolkata"')
        assert out["query"].endswith('"Kolkata"')

    @patch("modules.name.search", return_value=[{"title": "t", "link": "https://x.com/a", "snippet": "s"}])
    def test_found_flag_and_count(self, _):
        out = _run_dork(_DORK_DEFINITIONS[0], "John Doe", "")
        assert out["found"] is True and out["count"] == 1


class TestScanName:
    @patch("modules.name.search", return_value=[])
    def test_has_required_keys(self, _):
        result = scan_name("John Doe")
        for key in ["type", "query", "score", "chips", "dork_results",
                    "social_hits", "general_hits", "all_results", "deep_links"]:
            assert key in result, f"Missing key: {key}"

    @patch("modules.name.search", return_value=[])
    def test_type_is_name(self, _):
        assert scan_name("John Doe")["type"] == "name"

    @patch("modules.name.search", return_value=[])
    def test_score_in_range(self, _):
        assert 0 <= scan_name("John Doe")["score"] <= 100

    @patch("modules.name.search", return_value=[
        {"title": "John Doe LinkedIn", "link": "https://linkedin.com/in/johndoe", "snippet": "Engineer"},
        {"title": "John Doe GitHub",   "link": "https://github.com/johndoe",     "snippet": "Dev"},
    ])
    def test_social_hits_detected(self, _):
        assert len(scan_name("John Doe")["social_hits"]) > 0

    @patch("modules.name.search", return_value=[])
    def test_filters_echoed(self, _):
        result = scan_name("John Doe", filters=["Kolkata", "Python Developer"])
        assert result["filters"] == ["Kolkata", "Python Developer"]

    @patch("modules.name.search", return_value=[])
    def test_14_dork_results_in_order(self, _):
        result = scan_name("Jane Smith")
        assert [d["key"] for d in result["dork_results"]] == [d["key"] for d in _DORK_DEFINITIONS]

    @patch("modules.name.search", return_value=[])
    def test_deep_links_present(self, _):
        for link in scan_name("John Doe")["deep_links"]:
            assert "label" in link and "url" in link
