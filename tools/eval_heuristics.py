"""
tools/eval_heuristics.py — measure the domain heuristics on real data (offline, no network calls
except the optional downloads below).

  python tools/eval_heuristics.py [--n 6000]

Phishing set : hosts in the local feed database (run `python -m modules.feed_db refresh` first)
Legit sets   : head (rank 1-15k) and long tail (rank 300k+) of the public top-1M list, plus every
               top-1M host that lives on a free/shared platform (blogspot, github.io, ...)
Reported     : share of hosts flagged "suspicious" or worse. Higher is better on phishing,
               lower is better on legit. Heuristics only: no feeds, no page fetch.
CAVEAT       : the phishing list is "known, already reported" phishing, and top-1M sites are not a
               perfect stand-in for ordinary legit sites. Treat the numbers as indicative.
"""
import argparse, os, random, sqlite3, sys, urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.scam import assess
from modules import feed_db

TOP = "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains"
SHARED_SUFFIXES = ("blogspot.", "github.io", "herokuapp.com", "netlify.app", "pages.dev", "web.app",
                   "000webhostapp.com", "weebly.com", "wixsite.com", "vercel.app", "glitch.me", "onrender.com")


def flagged(host: str) -> bool:
    return assess("domain", host)["verdict"] != "no_strong_signals"


def rate(hosts):
    return 100.0 * sum(flagged(h) for h in hosts) / max(len(hosts), 1)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--n", type=int, default=6000); n = ap.parse_args().n
    random.seed(11)
    c = sqlite3.connect(feed_db._path())
    phish = [r[0] for r in c.execute("SELECT host FROM bad WHERE source='phishing_database'")]
    if not phish:
        sys.exit("Feed DB is empty. Run: python -m modules.feed_db refresh")
    cache = os.path.join(os.path.dirname(feed_db._path()) or ".", "top1m.txt")
    if not os.path.exists(cache):
        print("downloading top-1M list ..."); urllib.request.urlretrieve(TOP, cache)
    top = [l.strip() for l in open(cache) if l.strip()]
    sets = {
        "PHISHING (want high)":           random.sample(phish, min(n, len(phish))),
        "legit head (want low)":          top[:min(n, 15000)],
        "legit long tail (want low)":     random.sample(top[300000:], n),
        "legit on free hosts (want low)": random.sample([h for h in top if h.endswith(SHARED_SUFFIXES) or ".blogspot." in h], n),
    }
    print(f"{'set':34s} {'n':>6s}  flagged")
    for name, hosts in sets.items():
        print(f"{name:34s} {len(hosts):6d}  {rate(hosts):5.1f}%")


if __name__ == "__main__":
    main()
