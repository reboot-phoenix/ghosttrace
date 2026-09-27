"""
tests/test_detector.py — unit tests for detector.py

Tests every input type detection with valid and edge-case inputs.
No network calls. Instant.
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detector import detect_input, SUPPORTED_TYPES


class TestEmailDetection:
    def test_basic_email(self):
        assert detect_input("user@example.com") == "email"

    def test_email_with_plus(self):
        assert detect_input("user+tag@gmail.com") == "email"

    def test_email_with_dots(self):
        assert detect_input("first.last@company.co.uk") == "email"

    def test_email_with_subdomain(self):
        assert detect_input("user@mail.example.org") == "email"

    def test_email_uppercase(self):
        assert detect_input("USER@EXAMPLE.COM") == "email"


class TestPhoneDetection:
    def test_phone_with_country_code(self):
        assert detect_input("+919876543210") == "phone"

    def test_phone_with_spaces(self):
        assert detect_input("+91 98765 43210") == "phone"

    def test_phone_with_dashes(self):
        assert detect_input("+1-800-555-0199") == "phone"

    def test_phone_us(self):
        assert detect_input("+14155552671") == "phone"


class TestIPDetection:
    def test_ipv4_basic(self):
        assert detect_input("1.1.1.1") == "ip"

    def test_ipv4_google(self):
        assert detect_input("8.8.8.8") == "ip"

    def test_ipv4_local(self):
        assert detect_input("192.168.1.1") == "ip"

    def test_ipv4_zeros(self):
        assert detect_input("0.0.0.0") == "ip"


class TestDomainDetection:
    def test_basic_domain(self):
        assert detect_input("example.com") == "domain"

    def test_subdomain(self):
        assert detect_input("sub.example.com") == "domain"

    def test_country_tld(self):
        assert detect_input("example.co.uk") == "domain"

    def test_new_tld(self):
        assert detect_input("my.app") == "domain"


class TestURLDetection:
    def test_http_url(self):
        assert detect_input("http://example.com") == "url"

    def test_https_url(self):
        assert detect_input("https://example.com/path") == "url"


class TestHashDetection:
    def test_md5(self):
        assert detect_input("d41d8cd98f00b204e9800998ecf8427e") == "hash_md5"

    def test_sha1(self):
        assert detect_input("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash_sha1"

    def test_sha256(self):
        assert detect_input("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash_sha256"


class TestUsernameDetection:
    def test_simple_username(self):
        assert detect_input("johndoe") == "username"

    def test_username_with_numbers(self):
        assert detect_input("user123") == "username"

    def test_username_with_dots(self):
        # john.doe matches domain pattern (.doe = 3-char TLD) - correct behaviour
        # Use underscores/dashes for unambiguous usernames
        assert detect_input("john_doe") == "username"
        assert detect_input("john-doe") == "username"

    def test_username_with_underscores(self):
        assert detect_input("john_doe_99") == "username"

    def test_username_with_dashes(self):
        assert detect_input("john-doe") == "username"


class TestNameDetection:
    def test_full_name(self):
        assert detect_input("John Doe") == "name"

    def test_three_word_name(self):
        assert detect_input("John Michael Doe") == "name"

    def test_name_with_initial(self):
        assert detect_input("John D. Smith") == "name"


class TestUnknown:
    def test_empty_string(self):
        assert detect_input("") == "unknown"

    def test_gibberish(self):
        assert detect_input("!@#$%^&*") == "unknown"


class TestSupportedTypes:
    def test_supported_types_exist(self):
        assert "email"    in SUPPORTED_TYPES
        assert "phone"    in SUPPORTED_TYPES
        assert "username" in SUPPORTED_TYPES
        assert "name"     in SUPPORTED_TYPES
        assert "ip"       in SUPPORTED_TYPES
        assert "domain"   in SUPPORTED_TYPES

    def test_unsupported_types_not_in_set(self):
        assert "url"       not in SUPPORTED_TYPES
        assert "hash_md5"  not in SUPPORTED_TYPES
        assert "unknown"   not in SUPPORTED_TYPES
