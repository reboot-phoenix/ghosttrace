"""
tests/conftest.py — shared pytest configuration

Fixtures and markers available to all test files.
"""

import pytest
import sys, os, tempfile

# Keep tests hermetic: no background downloads, no writes to the real data/ folder
os.environ.setdefault("FEED_REFRESH", "0")
_tmp = tempfile.mkdtemp(prefix="ghosttrace-test-")
os.environ.setdefault("FEEDS_DB", os.path.join(_tmp, "feeds.db"))
os.environ.setdefault("REPORTS_DB", os.path.join(_tmp, "reports.db"))

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


@pytest.fixture(autouse=True)
def _no_real_search(monkeypatch):
    """Unit tests must never touch the real network or wait on retry back-off."""
    from modules import search as _s
    monkeypatch.setattr(_s, "_sleep", lambda s: None)
    class _Offline:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def text(self, *a, **k): raise RuntimeError("offline in tests")
    monkeypatch.setattr(_s, "DDGS", _Offline)
    yield


@pytest.fixture(autouse=True)
def _fresh_caches():
    """Result/search caches are process-wide; isolate every test from the previous one."""
    from modules import pipeline
    pipeline.clear_cache()
    try:
        from modules import search as _s
        _s.clear_cache()
    except (ImportError, AttributeError):
        pass
    yield
