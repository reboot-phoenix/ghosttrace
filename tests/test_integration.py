"""
tests/test_integration.py — real network integration tests

These tests make ACTUAL network calls to verify live APIs are working.
Run with: pytest tests/test_integration.py -v --timeout=30

Marks: @pytest.mark.integration
Skip in CI: pytest --ignore=tests/test_integration.py
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

pytestmark = pytest.mark.integration


# ── IP-API.com ────────────────────────────────────────────────────────────────

class TestIPApiLive:
    def test_cloudflare_dns_ip(self):
        from modules.ip_domain import _ipapi
        result = _ipapi("1.1.1.1")
        assert result != {}
        assert result.get("country") is not None
        assert result.get("isp") is not None

    def test_google_dns_ip(self):
        from modules.ip_domain import _ipapi
        result = _ipapi("8.8.8.8")
        assert "Google" in result.get("org", "") or "Google" in result.get("isp", "")


# ── Shodan InternetDB ─────────────────────────────────────────────────────────

class TestShodanInternetDBLive:
    def test_known_ip_has_ports(self):
        from modules.ip_domain import _internetdb
        result = _internetdb("1.1.1.1")
        # Cloudflare 1.1.1.1 always has 443 open
        assert isinstance(result.get("ports", []), list)
        assert 443 in result.get("ports", [])

    def test_returns_dict(self):
        from modules.ip_domain import _internetdb
        result = _internetdb("8.8.8.8")
        assert isinstance(result, dict)


# ── DNS via Cloudflare DoH ────────────────────────────────────────────────────

class TestDNSLive:
    def test_google_com_has_a_records(self):
        from modules.ip_domain import _dns
        result = _dns("google.com")
        assert len(result.get("A", [])) > 0

    def test_google_com_has_mx_records(self):
        from modules.ip_domain import _dns
        result = _dns("google.com")
        assert len(result.get("MX", [])) > 0

    def test_returns_all_record_types(self):
        from modules.ip_domain import _dns
        result = _dns("example.com")
        assert "A"   in result
        assert "MX"  in result
        assert "TXT" in result
        assert "NS"  in result


# ── crt.sh subdomains ─────────────────────────────────────────────────────────

class TestCrtshLive:
    def test_known_domain_has_subdomains(self):
        from modules.ip_domain import _crtsh
        result = _crtsh("github.com")
        assert isinstance(result, list)
        assert len(result) > 0

    def test_returns_strings(self):
        from modules.ip_domain import _crtsh
        result = _crtsh("example.com")
        for sub in result:
            assert isinstance(sub, str)
            assert "example.com" in sub


# ── RDAP ─────────────────────────────────────────────────────────────────────

class TestRDAPLive:
    def test_example_com_rdap(self):
        from modules.ip_domain import _rdap_domain
        result = _rdap_domain("example.com")
        assert isinstance(result, dict)

    def test_returns_registrar_for_known_domain(self):
        from modules.ip_domain import _rdap_domain
        result = _rdap_domain("github.com")
        # GitHub's domain should have a registrar
        assert result.get("registrar") or result.get("nameservers")


# ── GitHub commit search ──────────────────────────────────────────────────────

class TestGitHubCommitSearchLive:
    def test_known_email_returns_commits(self):
        from modules.email import _github_commits
        # Torvalds' public email used in early commits
        result = _github_commits("torvalds@linux-foundation.org")
        # May or may not find commits depending on GH API
        assert isinstance(result, dict)
        assert "commits" in result
        assert "author_name" in result
        assert "repos" in result

    def test_random_email_returns_empty(self):
        from modules.email import _github_commits
        result = _github_commits("definitelynotreal_xyz_abc@noemail.example")
        assert result["commits"] == []


# ── Gravatar ──────────────────────────────────────────────────────────────────

class TestGravatarLive:
    def test_returns_dict(self):
        from modules.email import _gravatar
        result = _gravatar("test@example.com")
        assert isinstance(result, dict)
        assert "found" in result
        assert "hash"  in result

    def test_known_gravatar_email(self):
        # Gravatar's own test email
        from modules.email import _gravatar
        result = _gravatar("gravatar@automattic.com")
        assert isinstance(result, dict)


# ── EmailRep ──────────────────────────────────────────────────────────────────

class TestEmailRepLive:
    def test_returns_dict_for_valid_email(self):
        from modules.email import _emailrep
        result = _emailrep("test@example.com")
        assert isinstance(result, dict)

    def test_suspicious_disposable_email(self):
        from modules.email import _emailrep
        result = _emailrep("test@mailinator.com")
        # mailinator is always flagged
        if result:  # API might rate-limit
            assert result.get("suspicious") is True or result.get("reputation") in ("none", "low")


# ── LeakCheck public ─────────────────────────────────────────────────────────

class TestLeakCheckPublicLive:
    def test_known_breached_email(self):
        from modules.breach import _leakcheck_public
        # Adobe breach — well known test case
        result = _leakcheck_public("test@adobe.com")
        assert isinstance(result, dict)
        assert "breached" in result
        assert "count"    in result
        assert "sources"  in result

    def test_structure_always_valid(self):
        from modules.breach import _leakcheck_public
        result = _leakcheck_public("nobody@nowhere.invalid")
        assert "breached" in result
        assert "error"    in result


# ── Full scan integration ─────────────────────────────────────────────────────

class TestFullScanIntegration:
    def test_phone_scan_completes(self):
        from modules.phone import scan_phone
        result = scan_phone("+14155552671")
        assert result["type"] == "phone"
        assert 0 <= result["score"] <= 100
        assert len(result["deep_links"]) > 0

    def test_name_scan_completes(self):
        from modules.name import scan_name
        result = scan_name("Linus Torvalds")
        assert result["type"] == "name"
        assert len(result["dorks"]) == 14
        assert result["score"] >= 0

    def test_ip_scan_completes(self):
        from modules.ip_domain import scan_ip
        result = scan_ip("1.1.1.1")
        assert result["type"] == "ip"
        assert result["geo"].get("country") is not None
        assert 443 in result["shodan"].get("ports", [])

    def test_domain_scan_completes(self):
        from modules.ip_domain import scan_domain
        result = scan_domain("example.com")
        assert result["type"] == "domain"
        assert result["resolved_ip"] is not None
        assert len(result["dns"].get("A", [])) > 0
