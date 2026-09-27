"""
tests/test_search.py — unit tests for modules/search.py

Mocks all HTTP/DDG calls.
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch, MagicMock
from modules.search import search, _google_cse, _ddg


class TestSearchFallback:
    @patch("modules.search.GOOGLE_CSE_KEY", "")
    @patch("modules.search.GOOGLE_CSE_ID", "")
    @patch("modules.search._ddg")
    def test_uses_ddg_when_no_cse_keys(self, mock_ddg):
        mock_ddg.return_value = [{"title": "Test", "link": "https://example.com", "snippet": "test"}]
        result = search("test query")
        mock_ddg.assert_called_once()

    @patch("modules.search.GOOGLE_CSE_KEY", "fake-key")
    @patch("modules.search.GOOGLE_CSE_ID", "fake-id")
    @patch("modules.search._google_cse")
    def test_uses_google_when_keys_set(self, mock_cse):
        mock_cse.return_value = [{"title": "Test", "link": "https://example.com", "snippet": "test"}]
        result = search("test query")
        mock_cse.assert_called_once()

    @patch("modules.search.GOOGLE_CSE_KEY", "fake-key")
    @patch("modules.search.GOOGLE_CSE_ID", "fake-id")
    @patch("modules.search._google_cse", return_value=[])
    @patch("modules.search._ddg")
    def test_falls_back_to_ddg_when_cse_empty(self, mock_ddg, mock_cse):
        mock_ddg.return_value = [{"title": "DDG Result", "link": "https://example.com", "snippet": ""}]
        result = search("test query")
        mock_ddg.assert_called_once()


class TestSearchResultFormat:
    @patch("modules.search.GOOGLE_CSE_KEY", "")
    @patch("modules.search.GOOGLE_CSE_ID", "")
    @patch("modules.search._ddg")
    def test_results_have_required_keys(self, mock_ddg):
        mock_ddg.return_value = [
            {"title": "Test", "link": "https://example.com", "snippet": "A snippet"}
        ]
        results = search("test")
        assert isinstance(results, list)
        for r in results:
            assert "title"   in r
            assert "link"    in r
            assert "snippet" in r

    @patch("modules.search.GOOGLE_CSE_KEY", "")
    @patch("modules.search.GOOGLE_CSE_ID", "")
    @patch("modules.search._ddg", side_effect=Exception("DDG blocked"))
    def test_returns_empty_on_all_failures(self, mock_ddg):
        result = search("test query")
        assert result == []

    @patch("modules.search.GOOGLE_CSE_KEY", "")
    @patch("modules.search.GOOGLE_CSE_ID", "")
    @patch("modules.search._ddg")
    def test_respects_max_results(self, mock_ddg):
        mock_ddg.return_value = [
            {"title": f"Result {i}", "link": f"https://example.com/{i}", "snippet": ""}
            for i in range(20)
        ]
        results = search("test", max_results=5)
        assert len(results) <= 5


class TestGoogleCSE:
    @patch("modules.search.requests.get")
    def test_parses_google_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "items": [
                {"title": "Google Result", "link": "https://example.com", "snippet": "A snippet"},
            ]
        }
        mock_get.return_value = mock_resp

        results = _google_cse("test", 5)
        assert len(results) == 1
        assert results[0]["title"] == "Google Result"

    @patch("modules.search.requests.get", side_effect=Exception("timeout"))
    def test_handles_exception(self, mock_get):
        results = _google_cse("test", 5)
        assert results == []


class TestDDG:
    @patch("modules.search.DDGS")
    def test_parses_ddg_response(self, mock_ddgs_cls):
        mock_ddgs = MagicMock()
        mock_ddgs.__enter__ = MagicMock(return_value=mock_ddgs)
        mock_ddgs.__exit__ = MagicMock(return_value=False)
        mock_ddgs.text.return_value = [
            {"title": "DDG Result", "href": "https://example.com", "body": "A body"}
        ]
        mock_ddgs_cls.return_value = mock_ddgs

        results = _ddg("test", 5)
        assert len(results) == 1
        assert results[0]["link"] == "https://example.com"
        assert results[0]["snippet"] == "A body"
