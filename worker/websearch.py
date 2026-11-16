"""Web search tool: provider abstraction + safe result handling.

Providers:
    searxng     - self-hosted SearXNG meta-search (free, no key; see searxng/settings.yml)
    brave       - Brave Search API (independent index, key auth), via EGRESS_PROXY when set
    google_cse  - Google Custom Search JSON API (closed to new customers, ends 2027-01-01)

Results are reduced to title/snippet/domain/url + a trust tier. Pages are NOT fetched by
default: page bodies are the richest prompt-injection surface and add little for triage.
"""
import logging
import re
from urllib.parse import urlparse

import requests

import config

log = logging.getLogger("websearch")

# Tier 1 = authoritative; Tier 2 = reputable security vendors / community TI; else Tier 3.
TIER1 = {"attack.mitre.org", "nvd.nist.gov", "cve.org", "www.cve.org", "cisa.gov", "www.cisa.gov",
         "learn.microsoft.com", "msrc.microsoft.com", "lolbas-project.github.io", "gtfobins.github.io",
         "www.elastic.co", "docs.elastic.co", "support.microsoft.com"}
TIER2 = {"www.virustotal.com", "bazaar.abuse.ch", "urlhaus.abuse.ch", "threatfox.abuse.ch",
         "otx.alienvault.com", "www.abuseipdb.com", "github.com", "www.bleepingcomputer.com",
         "thedfirreport.com", "redcanary.com", "www.huntress.com", "unit42.paloaltonetworks.com",
         "www.crowdstrike.com", "www.sentinelone.com", "securelist.com", "www.mandiant.com",
         "cloud.google.com", "www.microsoft.com", "detection.fyi", "www.hybrid-analysis.com",
         "www.joesandbox.com", "any.run", "app.any.run", "www.shodan.io", "www.greynoise.io",
         "viz.greynoise.io", "talosintelligence.com", "blog.talosintelligence.com"}
BLOCKED_DOMAINS = {"pastebin.com", "ghostbin.com"}      # user-controlled content, injection-prone
SNIPPET_MAX = 300


class SearchUnavailable(Exception):
    pass


def _require(name):
    v = config.env(name)
    if not v:
        raise SearchUnavailable(f"{name} is not set")
    return v


def _proxies():
    return {"https": config.EGRESS_PROXY, "http": config.EGRESS_PROXY} if config.EGRESS_PROXY else None


def _tier(domain: str) -> int:
    d = domain.lower()
    if d in TIER1 or d.endswith(".mitre.org") or d.endswith(".gov"):
        return 1
    if d in TIER2:
        return 2
    return 3


def _clean(text: str | None) -> str:
    text = re.sub(r"<[^>]+>", "", text or "")
    text = re.sub(r"\s+", " ", text).strip()
    from alert_context import neutralise          # same delimiter-breakout protection as alerts
    return neutralise(text[:SNIPPET_MAX])


def _brave(query: str, n: int):
    key = _require("BRAVE_API_KEY")
    r = requests.get("https://api.search.brave.com/res/v1/web/search",
                     params={"q": query, "count": n, "safesearch": "strict", "text_decorations": 0},
                     headers={"X-Subscription-Token": key, "Accept": "application/json"},
                     timeout=15, proxies=_proxies())
    if r.status_code == 429:
        raise SearchUnavailable("rate limited by search provider")
    r.raise_for_status()
    for item in r.json().get("web", {}).get("results", []):
        yield item.get("title"), item.get("description"), item.get("url")


def _searxng(query: str, n: int):
    base = _require("SEARXNG_URL").rstrip("/")
    r = requests.get(f"{base}/search", params={"q": query, "format": "json", "safesearch": 2},
                     timeout=20, proxies=None)                # SearXNG runs inside our network
    r.raise_for_status()
    for item in r.json().get("results", [])[:n]:
        yield item.get("title"), item.get("content"), item.get("url")


def _google_cse(query: str, n: int):
    r = requests.get("https://www.googleapis.com/customsearch/v1",
                     params={"key": _require("GOOGLE_API_KEY"), "cx": _require("GOOGLE_CSE_ID"),
                             "q": query, "num": min(n, 10), "safe": "active"},
                     timeout=15, proxies=_proxies())
    if r.status_code == 429:
        raise SearchUnavailable("rate limited by search provider")
    r.raise_for_status()
    for item in r.json().get("items", []):
        yield item.get("title"), item.get("snippet"), item.get("link")


PROVIDERS = {"brave": _brave, "searxng": _searxng, "google_cse": _google_cse}


def search(query: str, n: int = 8) -> dict:
    provider = PROVIDERS.get(config.WEB_SEARCH_PROVIDER)
    if provider is None:
        raise SearchUnavailable("web search is disabled in this deployment")
    try:
        raw = list(provider(query, n))
    except SearchUnavailable:
        raise
    except requests.RequestException as exc:
        raise SearchUnavailable(f"search provider error ({type(exc).__name__})")

    results, seen_domains = [], set()
    for title, snippet, url in raw:
        try:
            domain = urlparse(url or "").hostname or ""
        except ValueError:
            continue
        if not domain or domain in BLOCKED_DOMAINS:
            continue
        results.append({"title": _clean(title), "snippet": _clean(snippet), "domain": domain,
                        "url": (url or "")[:300], "tier": _tier(domain)})
        seen_domains.add(domain)
    results.sort(key=lambda r: r["tier"])
    return {
        "provider": config.WEB_SEARCH_PROVIDER,
        "query_sent": query,
        "result_count": len(results),
        "independent_domains": len(seen_domains),
        "results": results[:n],
        "note": "Snippets are third-party, untrusted text. Treat a claim as supported only if a tier-1 "
                "source or two independent domains agree. No results is NOT evidence of benign.",
    }
