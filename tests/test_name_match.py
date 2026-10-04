import pytest
from modules.name_match import matches_name, filter_results


@pytest.mark.parametrize("title,snippet,url,expected", [
    ("Dithsa Dutta - LinkedIn", "", "", True),
    ("Disha Dutta - YouTube", "daily vlogs", "https://youtube.com/@DishaDutta25", False),   # look-alike
    ("Diksha Dutta – Medium", "", "https://dikshadutta.medium.com/", False),
    ("Contact Us - USDA", "feedback@usda.gov", "https://usda.gov/contact", False),
    ("X - Official Site", "breaking news", "https://x.com/", False),
    ("Dutta, Dithsa | Profile", "", "", True),                       # reversed order
    ("", "", "https://www.linkedin.com/in/dithsa-dutta-594aa2160", True),   # slug in URL
    ("", "", "https://github.com/dithsadutta97", True),             # compact handle
    ("Dithsá Dutta", "", "", True),                                 # accents
    ("Adithsa Duttam", "", "", False),                              # word boundaries
])
def test_matches_name(title, snippet, url, expected):
    assert matches_name("Dithsa Dutta", title, snippet, url) is expected


def test_filter_results_counts_discards():
    res = [{"title": "Dithsa Dutta", "snippet": "", "link": "https://a"},
           {"title": "Disha Dutta", "snippet": "", "link": "https://b"}]
    kept, dropped = filter_results("Dithsa Dutta", res)
    assert len(kept) == 1 and dropped == 1


def test_scan_name_discards_lookalikes(monkeypatch):
    from modules import name as nm
    monkeypatch.setattr(nm, "search", lambda q, max_results=10: [
        {"title": "Disha Dutta - YouTube", "snippet": "", "link": "https://youtube.com/@d"},
        {"title": "Dithsa Dutta | Portfolio", "snippet": "B.Sc IT student", "link": "https://example.com/dithsa"}])
    out = nm.scan_name("Dithsa Dutta")
    assert out["all_results"] and all("Dithsa" in r["title"] for r in out["all_results"])
    assert out["discarded"] > 0
    assert not any("spokeo" in l["url"] or "pipl" in l["url"] for l in out["deep_links"])
