"""
tests/conftest.py — shared pytest configuration

Fixtures and markers available to all test files.
"""

import pytest
import sys, os

# Make sure the project root is always on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "integration: marks tests that make real network calls (deselect with -m 'not integration')"
    )


@pytest.fixture
def sample_email():
    return "test@example.com"


@pytest.fixture
def sample_phone():
    return "+919876543210"


@pytest.fixture
def sample_ip():
    return "1.1.1.1"


@pytest.fixture
def sample_domain():
    return "example.com"


@pytest.fixture
def sample_username():
    return "testuser"


@pytest.fixture
def sample_name():
    return "John Doe"


@pytest.fixture
def mock_web_results():
    return [
        {"title": "John Doe | LinkedIn", "link": "https://linkedin.com/in/johndoe", "snippet": "Engineer"},
        {"title": "John Doe GitHub",     "link": "https://github.com/johndoe",     "snippet": "Developer"},
        {"title": "Some Blog Post",       "link": "https://blog.example.com/post",  "snippet": "Article"},
    ]
