"""Golden-case regression gate: a scoring change may not break a previously fixed case."""
import json
import os
import pytest

from modules.scam import assess

_PATH = os.path.join(os.path.dirname(__file__), "golden_cases.json")
_DATA = json.load(open(_PATH))


def _flagged(case) -> bool:
    return assess(case["kind"], case["value"])["verdict"] != "no_strong_signals"


@pytest.mark.parametrize("case", _DATA["cases"], ids=lambda c: c["value"])
def test_golden_case(case):
    assert _flagged(case) is (case["expect"] == "scam"), case["note"]


@pytest.mark.parametrize("case", _DATA["known_gaps"], ids=lambda c: "gap:" + c["value"])
def test_known_gap(case):
    """Documented misses. xfail now; when a fix lands the case XPASSes: move it into "cases"."""
    if _flagged(case) is not (case["expect"] == "scam"):
        pytest.xfail("known gap: " + case["note"])
