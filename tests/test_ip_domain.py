"""
tests/test_ip_domain.py — unit tests for modules/ip_domain.py

Mocks all HTTP calls and socket resolution.
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch, MagicMock
from modules.ip_domain import scan_ip, scan_domain, _ipapi, _internetdb, _crtsh, _dns


class TestScanIP:
    @patch("modules.ip_domain._ipapi")
    @patch("modules.ip_domain._internetdb")
    @patch("modules.ip_domain._rdap_ip")
    def test_returns_dict(self, mock_rdap, mock_shodan, mock_geo):
        mock_geo.return_value    = {"country": "USA", "isp": "Cloudflare", "proxy": False, "hosting": True, "mobile": False}
        mock_shodan.return_value = {"ports": [80, 443], "vulns": [], "hostnames": [], "tags": []}
        mock_rdap.return_value   = {}
        result = scan_ip("1.1.1.1")
        assert isinstance(result, dict)

    @patch("modules.ip_domain._ipapi")
    @patch("modules.ip_domain._internetdb")
    @patch("modules.ip_domain._rdap_ip")
    def test_has_required_keys(self, mock_rdap, mock_shodan, mock_geo):
        mock_geo.return_value    = {}
        mock_shodan.return_value = {}
        mock_rdap.return_value   = {}
        result = scan_ip("1.1.1.1")
        for key in ["type", "query", "score", "chips", "geo", "shodan", "deep_links"]:
            assert key in result, f"Missing: {key}"

    @patch("modules.ip_domain._ipapi")
    @patch("modules.ip_domain._internetdb")
    @patch("modules.ip_domain._rdap_ip")
    def test_type_is_ip(self, mock_rdap, mock_shodan, mock_geo):
        mock_geo.return_value = mock_shodan.return_value = mock_rdap.return_value = {}
        result = scan_ip("8.8.8.8")
        assert result["type"] == "ip"

    @patch("modules.ip_domain._ipapi")
    @patch("modules.ip_domain._internetdb")
    @patch("modules.ip_domain._rdap_ip")
    def test_score_range(self, mock_rdap, mock_shodan, mock_geo):
        mock_geo.return_value    = {"proxy": False, "hosting": False}
        mock_shodan.return_value = {"ports": [22, 80, 443, 8080], "vulns": ["CVE-2021-1234"]}
        mock_rdap.return_value   = {}
        result = scan_ip("1.2.3.4")
        assert 0 <= result["score"] <= 100

    @patch("modules.ip_domain._ipapi")
    @patch("modules.ip_domain._internetdb")
    @patch("modules.ip_domain._rdap_ip")
    def test_deep_links_have_ip(self, mock_rdap, mock_shodan, mock_geo):
        mock_geo.return_value = mock_shodan.return_value = mock_rdap.return_value = {}
        result = scan_ip("1.1.1.1")
        urls = [l["url"] for l in result["deep_links"]]
        assert any("1.1.1.1" in u for u in urls)

    @patch("modules.ip_domain._ipapi")
    @patch("modules.ip_domain._internetdb")
    @patch("modules.ip_domain._rdap_ip")
    def test_proxy_chip_when_vpn(self, mock_rdap, mock_shodan, mock_geo):
        mock_geo.return_value    = {"proxy": True, "hosting": False, "mobile": False,
                                    "country": "NL", "isp": "Some VPN"}
        mock_shodan.return_value = {}
        mock_rdap.return_value   = {}
        result = scan_ip("1.2.3.4")
        chip_labels = [c["label"] for c in result["chips"]]
        assert any("VPN" in l or "Proxy" in l for l in chip_labels)


class TestScanDomain:
    @patch("modules.ip_domain._resolve", return_value="93.184.216.34")
    @patch("modules.ip_domain._dns")
    @patch("modules.ip_domain._rdap_domain")
    @patch("modules.ip_domain._crtsh")
    @patch("modules.ip_domain._ipapi")
    @patch("modules.ip_domain._internetdb")
    def test_returns_dict(self, mock_shodan, mock_geo, mock_crtsh, mock_rdap, mock_dns, mock_resolve):
        mock_dns.return_value    = {"A": ["93.184.216.34"], "MX": [], "TXT": [], "NS": [], "AAAA": []}
        mock_rdap.return_value   = {"registrar": "ICANN", "registered": "1995-08-14"}
        mock_crtsh.return_value  = ["www.example.com", "mail.example.com"]
        mock_geo.return_value    = {"country": "USA", "isp": "Edgecast"}
        mock_shodan.return_value = {"ports": [80, 443], "vulns": []}
        result = scan_domain("example.com")
        assert isinstance(result, dict)

    @patch("modules.ip_domain._resolve", return_value=None)
    @patch("modules.ip_domain._dns", return_value={})
    @patch("modules.ip_domain._rdap_domain", return_value={})
    @patch("modules.ip_domain._crtsh", return_value=[])
    @patch("modules.ip_domain._ipapi", return_value={})
    @patch("modules.ip_domain._internetdb", return_value={})
    def test_has_required_keys(self, *mocks):
        result = scan_domain("example.com")
        for key in ["type", "query", "score", "chips", "dns", "rdap", "subdomains", "deep_links"]:
            assert key in result, f"Missing: {key}"

    @patch("modules.ip_domain._resolve", return_value=None)
    @patch("modules.ip_domain._dns", return_value={})
    @patch("modules.ip_domain._rdap_domain", return_value={})
    @patch("modules.ip_domain._crtsh", return_value=[])
    @patch("modules.ip_domain._ipapi", return_value={})
    @patch("modules.ip_domain._internetdb", return_value={})
    def test_type_is_domain(self, *mocks):
        result = scan_domain("example.com")
        assert result["type"] == "domain"

    @patch("modules.ip_domain._resolve", return_value=None)
    @patch("modules.ip_domain._dns", return_value={})
    @patch("modules.ip_domain._rdap_domain", return_value={})
    @patch("modules.ip_domain._crtsh", return_value=["sub1.example.com", "sub2.example.com"])
    @patch("modules.ip_domain._ipapi", return_value={})
    @patch("modules.ip_domain._internetdb", return_value={})
    def test_subdomains_included(self, *mocks):
        result = scan_domain("example.com")
        assert len(result["subdomains"]) == 2


class TestIPApi:
    @patch("modules.ip_domain.requests.get")
    def test_parses_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success", "country": "India", "countryCode": "IN",
            "regionName": "West Bengal", "city": "Kolkata",
            "isp": "Jio", "org": "Reliance", "as": "AS55836",
            "asname": "Reliance Jio", "reverse": "", "mobile": True,
            "proxy": False, "hosting": False, "query": "1.2.3.4",
            "zip": "700001", "lat": 22.5, "lon": 88.3, "timezone": "Asia/Kolkata"
        }
        mock_get.return_value = mock_resp
        result = _ipapi("1.2.3.4")
        assert result["country"] == "India"
        assert result["city"] == "Kolkata"
        assert result["mobile"] is True

    @patch("modules.ip_domain.requests.get")
    def test_returns_empty_on_fail(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "fail"}
        mock_get.return_value = mock_resp
        result = _ipapi("999.999.999.999")
        assert result == {}


class TestInternetDB:
    @patch("modules.ip_domain.requests.get")
    def test_parses_shodan_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "ports": [22, 80, 443],
            "vulns": ["CVE-2021-44228"],
            "hostnames": ["example.com"],
            "cpes": [],
            "tags": ["cloud"]
        }
        mock_get.return_value = mock_resp
        result = _internetdb("1.2.3.4")
        assert 80 in result["ports"]
        assert "CVE-2021-44228" in result["vulns"]

    @patch("modules.ip_domain.requests.get", side_effect=Exception("timeout"))
    def test_returns_empty_on_error(self, mock_get):
        result = _internetdb("1.2.3.4")
        assert result == {}
