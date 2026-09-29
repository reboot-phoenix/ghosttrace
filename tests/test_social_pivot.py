"""tests/test_social_pivot.py — candidate generation, scoring, deep/fast wiring. No network."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch
from modules import social_pivot as sp
from modules.correlate import correlate


def test_name_variants():
    assert "john.smith" in sp._name_variants("John Smith")
    assert sp._name_variants("Madonna") == []


def test_candidates_dedupe_filter_and_order():
    data = {"query": "john.smith@x.com", "gravatar": {"username": "jsmith99"}, "github": {}}
    identity = {"real_name": {"value": "John Smith"}}
    cands = sp.candidate_handles("email", data, identity)
    handles = [c["handle"] for c in cands]
    assert handles[0] == "jsmith99"                 # linked outranks the rest
    assert len(handles) == len(set(handles))
    assert len(cands) <= sp.MAX_CANDIDATES


def test_generic_and_short_handles_skipped():
    cands = sp.candidate_handles("email", {"query": "info@x.com"}, {})
    assert cands == []
    assert sp.candidate_handles("username", {"query": "ab"}, {}) == []
    assert sp.candidate_handles("username", {"query": "12345678"}, {}) == []


def test_score_never_confirmed():
    score, _ = sp.score_hit("linked", "John Smith", "John Smith")
    assert score <= 0.95 and sp._label(score) == "PROBABLE"
    low, reasons = sp.score_hit("name_variant", "Totally Different", "John Smith")
    assert sp._label(low) == "LINKED" and any("does not match" in r for r in reasons)


def test_find_social_profiles_labels_and_sorts():
    fake = {"found": [{"site": "Instagram", "url": "https://instagram.com/jsmith99", "name": "John Smith"}]}
    with patch.object(sp, "run_maigret", return_value=fake):
        out = sp.find_social_profiles("username", {"query": "jsmith99", "found": []},
                                      {"real_name": {"value": "John Smith"}})
    assert out and out[0]["confidence"] in ("PROBABLE", "LINKED")
    assert "Unverified" in out[0]["note"]


def test_fast_skips_pivots_deep_runs_them():
    data = {"type": "username", "query": "jsmith99", "found": []}
    with patch("modules.social_pivot.find_social_profiles", return_value=[{"x": 1}]) as f, \
         patch("modules.correlate._plan_pivots", return_value=[]) as plan:
        fast = correlate(dict(data), deep=False)
        assert not f.called and not plan.called and fast["social_candidates"] == []
        deep = correlate(dict(data), deep=True)
        assert f.called and plan.called and deep["social_candidates"] == [{"x": 1}]
