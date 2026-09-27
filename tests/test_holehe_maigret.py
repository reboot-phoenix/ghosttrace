"""
tests/test_holehe_maigret.py — unit tests for subprocess runners

Tests output parsing without actually running the subprocesses.
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch, MagicMock
from modules.holehe_runner import run_holehe, _parse
from modules.maigret_runner import _not_installed, _parse_json
import json, tempfile


class TestHoleheParse:
    def test_parses_found_site(self):
        output = "[+] Instagram (https://www.instagram.com)\n[-] Twitter\n"
        result = _parse(output, "test@example.com")
        assert len(result["found"]) == 1
        assert result["found"][0]["site"] == "Instagram"
        assert result["found"][0]["url"] == "https://www.instagram.com"

    def test_parses_not_found(self):
        output = "[-] Twitter\n[-] Facebook\n"
        result = _parse(output, "test@example.com")
        assert result["found"] == []
        assert "Twitter" in result["not_found"]
        assert "Facebook" in result["not_found"]

    def test_parses_errors(self):
        output = "[x] SomeError: timeout\n"
        result = _parse(output, "test@example.com")
        assert len(result["errors"]) == 1

    def test_multiple_found(self):
        output = (
            "[+] Instagram (https://instagram.com)\n"
            "[+] GitHub (https://github.com)\n"
            "[-] Twitter\n"
        )
        result = _parse(output, "test@example.com")
        assert len(result["found"]) == 2

    def test_summary_message_found(self):
        output = "[+] Instagram (https://instagram.com)\n"
        result = _parse(output, "test@example.com")
        assert "Found on" in result["summary"]

    def test_summary_message_not_found(self):
        output = "[-] Twitter\n[-] Facebook\n"
        result = _parse(output, "test@example.com")
        assert "Not found" in result["summary"]

    def test_installed_flag(self):
        output = "[-] Twitter\n"
        result = _parse(output, "test@example.com")
        assert result["installed"] is True


class TestHolehRunner:
    @patch("modules.holehe_runner.subprocess.run", side_effect=FileNotFoundError)
    def test_not_installed_graceful(self, mock_run):
        result = run_holehe("test@example.com")
        assert result["installed"] is False
        assert result["found"] == []

    @patch("modules.holehe_runner.subprocess.run")
    def test_runs_successfully(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "[+] Instagram (https://instagram.com)\n[-] Twitter\n"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc
        result = run_holehe("test@example.com")
        assert result["installed"] is True
        assert len(result["found"]) == 1

    @patch("modules.holehe_runner.subprocess.run")
    def test_timeout_graceful(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="holehe", timeout=60)
        result = run_holehe("test@example.com")
        assert result["found"] == []
        assert "timed out" in result["summary"].lower()


class TestMaigretNotInstalled:
    def test_not_installed_structure(self):
        result = _not_installed()
        assert result["installed"] is False
        assert result["found"] == []
        assert result["total_checked"] == 0
        assert "not installed" in result["summary"].lower()


class TestMaigretParseJSON:
    def test_parses_valid_json(self):
        data = {
            "sites": {
                "GitHub": {
                    "status": {"status": "Claimed"},
                    "url_user": "https://github.com/testuser",
                    "tags": ["coding"],
                    "profile": {"name": "Test User", "bio": "Developer", "location": "India", "image": ""}
                },
                "Twitter": {
                    "status": {"status": "Available"},
                    "url_user": "https://twitter.com/testuser",
                    "tags": ["social"],
                    "profile": {}
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            path = f.name

        result = _parse_json(path, "testuser")
        assert len(result["found"]) == 1
        assert result["found"][0]["site"] == "GitHub"
        assert result["total_checked"] == 2

    def test_handles_missing_file(self):
        result = _parse_json("/nonexistent/path.json", "testuser")
        assert result["found"] == []

    def test_found_entry_has_required_keys(self):
        data = {
            "sites": {
                "GitHub": {
                    "status": {"status": "Claimed"},
                    "url_user": "https://github.com/testuser",
                    "tags": ["coding"],
                    "profile": {"name": "Test", "bio": "", "location": "", "image": ""}
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            path = f.name

        result = _parse_json(path, "testuser")
        entry = result["found"][0]
        for key in ["site", "url", "category", "name", "bio", "location"]:
            assert key in entry, f"Missing key: {key}"
