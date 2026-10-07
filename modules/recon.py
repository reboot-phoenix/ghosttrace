"""
modules/recon.py — passive attack-surface recon for a domain (GhostTrace E: pentester mode)

PASSIVE ONLY, by design: certificate transparency (crt.sh), DNS resolution, RDAP/WHOIS, and
ASN lookups, plus one liveness HEAD request per host. No port scanning, no active probing
beyond that HEAD, no brute-force login attempts. This is the same boundary passive-mode
Amass and Subfinder draw. For domains you are authorized to test (yours, or in scope for a
bug bounty / engagement) — same expectation as any recon tool, not something we can verify
server-side, so the UI says this plainly rather than pretending to enforce it.

Pipeline, each stage checkpointed against SOFT_BUDGET so a slow upstream degrades the result
instead of losing it entirely to the caller's outer timeout:
  1. crt.sh                  → every certificate-logged subdomain (free, no key)
  2. DNS resolve each host   → IP address, on a dedicated bounded pool (not the shared one
                                every other scan on the server also draws from)
  3. ip-api.com batch        → ASN + org + country per unique public IP (free, no key; HTTP
                                only — ip-api's HTTPS endpoint needs a paid key, and the only
                                data in this call is IP addresses, nothing sensitive)
  4. RDAP                    → registrar + nameservers for the apex domain
  5. cluster                 → group subdomains by shared IP / shared org, with known CDN and
                                shared-hosting providers (Cloudflare, AWS, GitHub Pages, ...)
                                called out separately — "behind the same CDN" is not the same
                                finding as "behind the same dedicated server"
  6. live-check               → HEAD each host via safe_head (SSRF-validated on every hop,
                                including redirects) — status code + redirect target only

Returns a graph-shaped result: {nodes, edges, clusters} so a future UI can draw it, plus a
flat "hosts" table for anyone who just wants the list.
"""
from __future__ import annotations
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout

import requests

from modules.ip_domain import _crtsh, _rdap_domain
from modules.safe_http import safe_head, UnsafeURL

MAX_HOSTS = 50            # matches crt.sh's own cap (see modules/ip_domain._crtsh)
MAX_LIVE_PROBES = 30
HEAD_TIMEOUT = 5
SOFT_BUDGET = 35.0         # seconds; leaves margin under the pipeline's 45s outer timeout
_UA = {"User-Agent": "GhostTrace-recon/1.0 (passive; see /recon docs)"}

# Providers where "shares an IP/org" is routine and not itself a finding (CDNs, PaaS, big
# cloud). Hosts clustered only under these are reported separately from genuine infra overlap.
_COMMON_PROVIDERS = {
    "cloudflare", "amazon", "aws", "google", "microsoft", "azure", "akamai", "fastly",
    "github", "gitlab", "netlify", "vercel", "digitalocean", "linode", "ovh", "hetzner",
    "oracle corporation", "alibaba",
}


def _is_common_provider(org: str) -> bool:
    o = (org or "").lower()
    return any(p in o for p in _COMMON_PROVIDERS)


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _asn_batch(ips: list[str]) -> dict[str, dict]:
    """ip-api.com batch endpoint: up to 100 IPs in one call, no key needed."""
    out = {ip: {} for ip in ips}
    if not ips:
        return out
    try:
        r = requests.post(
            "http://ip-api.com/batch?fields=query,status,as,asname,org,country,isp",
            json=[{"query": ip} for ip in ips[:100]], timeout=10,
        )
        for row in r.json():
            if row.get("status") == "success":
                out[row["query"]] = {"asn": row.get("as", ""), "asname": row.get("asname", ""),
                                     "org": row.get("org") or row.get("isp", ""),
                                     "country": row.get("country", "")}
    except Exception:
        pass
    return out


def _head(host: str) -> dict:
    for scheme in ("https", "http"):
        try:
            r = safe_head(f"{scheme}://{host}", timeout=HEAD_TIMEOUT, headers=_UA)
            final = r.chain[-1] if len(r.chain) > 1 else None
            return {"alive": True, "scheme": scheme, "status": r.status_code,
                    "redirects_to": final, "blocked": False}
        except UnsafeURL as e:
            return {"alive": False, "scheme": None, "status": None, "redirects_to": None,
                    "blocked": True, "reason": str(e)}
        except requests.RequestException:
            continue
    return {"alive": False, "scheme": None, "status": None, "redirects_to": None, "blocked": False}


def _parallel(fn, items: list[str], timeout: float, max_workers: int) -> dict[str, dict]:
    """Run fn(item) for each item on a short-lived, dedicated pool (isolated from every other
    scan's own workload), with a per-task timeout measured from when that task actually starts.
    Returns {item: {"ok": bool, "value": ...}}."""
    out: dict[str, dict] = {}
    if not items:
        return out
    with ThreadPoolExecutor(max_workers=min(max_workers, len(items))) as pool:
        futs = {pool.submit(fn, i): i for i in items}
        for fut in futs:
            item = futs[fut]
            try:
                out[item] = {"ok": True, "value": fut.result(timeout=timeout)}
            except FutTimeout:
                out[item] = {"ok": False, "value": None}
            except Exception:
                out[item] = {"ok": False, "value": None}
    return out


def recon_domain(domain: str, probe_live: bool = True) -> dict:
    domain = domain.lower().strip(".")
    warnings: list[str] = []
    t0 = time.time()
    budget_left = lambda: SOFT_BUDGET - (time.time() - t0)

    subs = _crtsh(domain)
    hosts = sorted({domain, *subs})[:MAX_HOSTS]
    if len(subs) >= 50:
        warnings.append("crt.sh result was capped at 50 names; more subdomains likely exist.")

    resolved = _parallel(_resolve, hosts, timeout=5, max_workers=20)
    host_ip = {h: r["value"] for h, r in resolved.items() if r["ok"] and r["value"]}
    unresolved = sorted(set(hosts) - set(host_ip))

    public_ips = sorted({ip for ip in host_ip.values() if _is_public(ip)})
    private_hosts = sorted({h for h, ip in host_ip.items() if not _is_public(ip)})
    if private_hosts:
        warnings.append(f"{len(private_hosts)} host(s) resolved to a private/internal address "
                        "and were excluded from ASN lookups and live-checks (split-horizon DNS, "
                        "VPN-only hosts, or misconfiguration).")

    asn_info: dict[str, dict] = {}
    rdap: dict = {}
    if budget_left() > 5:
        asn_info = _asn_batch(public_ips)
    else:
        warnings.append("Skipped ASN/org lookup: recon was running close to its time budget.")
    if budget_left() > 3:
        rdap = _rdap_domain(domain)
    else:
        warnings.append("Skipped RDAP/WHOIS lookup: recon was running close to its time budget.")

    live: dict[str, dict] = {}
    if probe_live:
        targets = [h for h, ip in host_ip.items() if _is_public(ip)][:MAX_LIVE_PROBES]
        if budget_left() > 5 and targets:
            res = _parallel(_head, targets, timeout=HEAD_TIMEOUT + 2, max_workers=15)
            live = {h: (r["value"] if r["ok"] else
                       {"alive": False, "scheme": None, "status": None, "redirects_to": None, "blocked": False})
                   for h, r in res.items()}
            if sum(1 for ip in host_ip.values() if _is_public(ip)) > MAX_LIVE_PROBES:
                warnings.append(f"Live-check (HTTP HEAD) was limited to the first {MAX_LIVE_PROBES} resolvable hosts.")
        elif targets:
            warnings.append("Skipped live-check: recon was running close to its time budget.")

    # ── cluster by shared IP and by shared ASN/org, CDNs/PaaS called out separately ──────────
    by_ip: dict[str, list[str]] = {}
    for h, ip in host_ip.items():
        if _is_public(ip):
            by_ip.setdefault(ip, []).append(h)
    by_org: dict[str, list[str]] = {}
    for h, ip in host_ip.items():
        org = asn_info.get(ip, {}).get("org") or asn_info.get(ip, {}).get("asname")
        if org:
            by_org.setdefault(org, []).append(h)

    def _split(groups: dict[str, list[str]], key_is_org: bool):
        notable, common = [], []
        for key, hs in sorted(groups.items()):
            hs = sorted(set(hs))
            if len(hs) <= 1:
                continue
            is_common = _is_common_provider(key if key_is_org else
                                            (asn_info.get(key, {}).get("org", "")))
            (common if is_common else notable).append(
                {"org" if key_is_org else "ip": key, "hosts": hs})
        return notable, common

    ip_notable, ip_common = _split(by_ip, key_is_org=False)
    org_notable, org_common = _split(by_org, key_is_org=True)
    if ip_common or org_common:
        n = len({h for c in ip_common + org_common for h in c["hosts"]})
        warnings.append(f"{n} host(s) cluster only under a common CDN/cloud provider "
                        "(Cloudflare, AWS, etc.) — listed separately since that's routine, "
                        "not evidence of shared dedicated infrastructure.")

    clusters = {"shared_ip": ip_notable, "shared_org": org_notable,
               "common_provider_ip": ip_common, "common_provider_org": org_common}

    # ── graph shape (for a future visual) ─────────────────────────────────────
    nodes = [{"id": h, "type": "host", "ip": host_ip.get(h), "resolved": h in host_ip,
             "alive": live.get(h, {}).get("alive")} for h in hosts]
    nodes += [{"id": ip, "type": "ip", **asn_info.get(ip, {})} for ip in public_ips]
    edges = [{"from": h, "to": ip, "type": "resolves_to"} for h, ip in host_ip.items() if _is_public(ip)]

    rows = []
    for h in hosts:
        ip = host_ip.get(h)
        info = asn_info.get(ip, {}) if ip else {}
        l = live.get(h, {})
        rows.append({"host": h, "ip": ip, "asn": info.get("asn", ""), "org": info.get("org", ""),
                     "country": info.get("country", ""), "alive": l.get("alive"),
                     "status": l.get("status"), "redirects_to": l.get("redirects_to"),
                     "live_check_blocked": l.get("blocked", False)})

    return {
        "domain": domain, "apex": rdap,
        "subdomain_count": len(hosts), "unresolved": unresolved,
        "hosts": rows, "clusters": clusters,
        "graph": {"nodes": nodes, "edges": edges},
        "warnings": warnings, "elapsed_s": round(time.time() - t0, 1),
        "passive_only": True,
    }
