"""
tests/test_breach.py — unit tests for modules/breach.py

Mocks all HTTP calls — no network needed.
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch, MagicMock
from modules.breach import check_breach, _leakcheck_public, _hibp


class TestCheckBreachRouting:
    @patch("modules.breach.HIBP_API_KEY", "fake-key")
    @patch("modules.breach._hibp")
    def test_uses_hibp_when_key_set(self, mock_hibp):
        mock_hibp.return_value = {"breached": False, "count": 0, "sources": [], "error": None}
        check_breach("test@example.com")
        mock_hibp.assert_called_once_with("test@example.com")

    @patch("modules.breach.HIBP_API_KEY", "")
    @patch("modules.breach.LEAKCHECK_KEY", "")
    @patch("modules.breach._leakcheck_public")
    def test_uses_leakcheck_public_when_no_keys(self, mock_lc):
        mock_lc.return_value = {"breached": False, "count": 0, "sources": [], "error": None}
        check_breach("test@example.com")
        mock_lc.assert_called_once_with("test@example.com")


class TestLeakCheckPublic:
    @patch("modules.breach.requests.get")
    def test_breached_email(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "success": True,
            "found": 3,
            "sources": ["Adobe", "LinkedIn", "Dropbox"]
        }
        mock_get.return_value = mock_resp

        result = _leakcheck_public("victim@example.com")

        assert result["breached"] is True
        assert result["count"] == 3
        assert "Adobe" in result["sources"]
        assert result["error"] is None

    @patch("modules.breach.requests.get")
    def test_clean_email(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"success": True, "found": 0, "sources": []}
        mock_get.return_value = mock_resp

        result = _leakcheck_public("clean@example.com")

        assert result["breached"] is False
        assert result["count"] == 0
        assert result["sources"] == []

    @patch("modules.breach.requests.get", side_effect=Exception("timeout"))
    def test_handles_network_error(self, mock_get):
        result = _leakcheck_public("test@example.com")
        assert result["breached"] is False
        assert result["error"] is not None


class TestHIBP:
    @patch("modules.breach.requests.get")
    def test_breached(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"Name": "Adobe"}, {"Name": "LinkedIn"}
        ]
        mock_get.return_value = mock_resp

        result = _hibp("victim@example.com")

        assert result["breached"] is True
        assert result["count"] == 2
        assert "Adobe" in result["sources"]

    @patch("modules.breach.requests.get")
    def test_not_breached_404(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = _hibp("clean@example.com")

        assert result["breached"] is False
        assert result["count"] == 0

    @patch("modules.breach.requests.get", side_effect=Exception("network error"))
    def test_handles_exception(self, mock_get):
        result = _hibp("test@example.com")
        assert result["breached"] is False
        assert result["error"] is not None


class TestReturnStructure:
    @patch("modules.breach.HIBP_API_KEY", "")
    @patch("modules.breach.LEAKCHECK_KEY", "")
    @patch("modules.breach.requests.get")
    def test_always_returns_required_keys(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"success": True, "found": 0, "sources": []}
        mock_get.return_value = mock_resp

        result = check_breach("test@example.com")
        assert "breached" in result
        assert "count"    in result
        assert "sources"  in result
        assert "error"    in result

    @patch("modules.breach.HIBP_API_KEY", "")
    @patch("modules.breach.LEAKCHECK_KEY", "")
    @patch("modules.breach.requests.get", side_effect=Exception("fail"))
    def test_never_raises(self, mock_get):
        result = check_breach("test@example.com")
        assert isinstance(result, dict)
