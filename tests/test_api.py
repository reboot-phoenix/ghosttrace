"""
tests/test_api.py — Flask API route tests

Tests all routes with mocked scan functions.
No network calls. Fast.
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch
import json
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ── /health ───────────────────────────────────────────────────────────────────

class TestHealth:
    def test_returns_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_returns_json(self, client):
        r = client.get("/health")
        data = json.loads(r.data)
        assert data["status"] == "online"
        assert data["service"] == "GhostTrace"
        assert data["version"] == "3.0"


# ── /ping ─────────────────────────────────────────────────────────────────────

class TestPing:
    def test_returns_200(self, client):
        r = client.get("/ping")
        assert r.status_code == 200


# ── / ─────────────────────────────────────────────────────────────────────────

class TestIndex:
    def test_returns_200(self, client):
        r = client.get("/")
        assert r.status_code == 200

    def test_returns_html(self, client):
        r = client.get("/")
        assert b"GhostTrace" in r.data


# ── /detect ───────────────────────────────────────────────────────────────────

class TestDetect:
    def test_detects_email(self, client):
        r = client.post("/detect", json={"query": "user@example.com"})
        data = json.loads(r.data)
        assert data["type"] == "email"
        assert data["supported"] is True

    def test_detects_username(self, client):
        r = client.post("/detect", json={"query": "johndoe99"})
        data = json.loads(r.data)
        assert data["type"] == "username"

    def test_detects_ip(self, client):
        r = client.post("/detect", json={"query": "1.1.1.1"})
        data = json.loads(r.data)
        assert data["type"] == "ip"

    def test_detects_domain(self, client):
        r = client.post("/detect", json={"query": "example.com"})
        data = json.loads(r.data)
        assert data["type"] == "domain"

    def test_detects_name(self, client):
        r = client.post("/detect", json={"query": "John Doe"})
        data = json.loads(r.data)
        assert data["type"] == "name"

    def test_detects_phone(self, client):
        r = client.post("/detect", json={"query": "+919876543210"})
        data = json.loads(r.data)
        assert data["type"] == "phone"

    def test_empty_query_returns_400(self, client):
        r = client.post("/detect", json={"query": ""})
        assert r.status_code == 400

    def test_missing_query_returns_400(self, client):
        r = client.post("/detect", json={})
        assert r.status_code == 400

    def test_echoes_query_back(self, client):
        r = client.post("/detect", json={"query": "user@example.com"})
        data = json.loads(r.data)
        assert data["query"] == "user@example.com"


# ── /scan ─────────────────────────────────────────────────────────────────────

class TestScanPhone:
    def test_phone_scan_returns_200(self, client):
        r = client.post("/scan", json={"query": "+919876543210", "scan_type": "phone"})
        assert r.status_code == 200

    def test_phone_scan_has_required_fields(self, client):
        r = client.post("/scan", json={"query": "+919876543210", "scan_type": "phone"})
        data = json.loads(r.data)
        assert "score"     in data
        assert "chips"     in data
        assert "type"      in data
        assert "timestamp" in data


class TestScanName:
    @patch("app.scan_name")
    def test_name_scan_calls_module(self, mock_scan, client):
        mock_scan.return_value = {
            "type": "name", "query": "John Doe", "score": 50,
            "chips": [], "dorks": [], "web_results": [],
            "social_hits": [], "general_hits": [], "deep_links": [], "filters": []
        }
        r = client.post("/scan", json={"query": "John Doe", "scan_type": "name"})
        assert r.status_code == 200
        mock_scan.assert_called_once()

    @patch("app.scan_name")
    def test_filters_passed_to_name_scan(self, mock_scan, client):
        mock_scan.return_value = {
            "type": "name", "query": "John Doe", "score": 0,
            "chips": [], "dorks": [], "web_results": [],
            "social_hits": [], "general_hits": [], "deep_links": [], "filters": ["Kolkata"]
        }
        r = client.post("/scan", json={
            "query": "John Doe", "scan_type": "name", "filters": ["Kolkata"]
        })
        assert r.status_code == 200
        call_args = mock_scan.call_args
        assert "Kolkata" in call_args[0][1]


class TestScanErrors:
    def test_empty_query_returns_400(self, client):
        r = client.post("/scan", json={"query": "", "scan_type": "email"})
        assert r.status_code == 400

    def test_unsupported_type_returns_400(self, client):
        r = client.post("/scan", json={"query": "test", "scan_type": "hash_md5"})
        assert r.status_code == 400

    def test_missing_query_returns_400(self, client):
        r = client.post("/scan", json={"scan_type": "email"})
        assert r.status_code == 400

    def test_auto_detect_type(self, client):
        # No scan_type — should auto detect email
        r = client.post("/scan", json={"query": "+919876543210"})
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["type"] == "phone"


class TestScanResponseStructure:
    def test_always_has_timestamp(self, client):
        r = client.post("/scan", json={"query": "+919876543210", "scan_type": "phone"})
        data = json.loads(r.data)
        assert "timestamp" in data
        assert isinstance(data["timestamp"], int)

    def test_always_has_scan_type(self, client):
        r = client.post("/scan", json={"query": "+919876543210", "scan_type": "phone"})
        data = json.loads(r.data)
        assert "scan_type" in data

    def test_score_always_0_to_100(self, client):
        r = client.post("/scan", json={"query": "+919876543210", "scan_type": "phone"})
        data = json.loads(r.data)
        assert 0 <= data["score"] <= 100


# ── Rate limiting ─────────────────────────────────────────────────────────────

class TestRateLimit:
    def test_rate_limit_after_20_requests(self, client):
        # Burn through 20 requests
        for _ in range(20):
            client.post("/scan", json={"query": "+919876543210", "scan_type": "phone"})
        # 21st should be rate limited
        r = client.post("/scan", json={"query": "+919876543210", "scan_type": "phone"})
        assert r.status_code == 429
