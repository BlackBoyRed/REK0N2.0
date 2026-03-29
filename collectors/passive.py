"""
collectors/passive.py
─────────────────────
All passive recon collectors. No direct contact with the target.
Each function returns a normalized dict with 'source' and data fields.
"""

import asyncio
import aiohttp
import json
import logging
import socket
import whois
import shodan
import dns.resolver

from config import (
    SHODAN_API_KEY, GITHUB_TOKEN,
    TIMEOUT_PASSIVE
)

logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get(session: aiohttp.ClientSession, url: str, **kwargs) -> dict | list | None:
    """Safe async GET — returns parsed JSON or None on failure."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_PASSIVE), **kwargs) as r:
            if r.status == 200:
                return await r.json(content_type=None)
    except Exception as e:
        logger.warning(f"GET {url} failed: {e}")
    return None


# ── 1. Certificate Transparency (crt.sh) ─────────────────────────────────────

async def collect_crtsh(domain: str) -> dict:
    """
    Query crt.sh for all SSL certificates issued for the domain.
    Reveals subdomains even before they go live.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    async with aiohttp.ClientSession() as session:
        data = await _get(session, url)

    subdomains = set()
    if data:
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.splitlines():
                sub = sub.strip().lstrip("*.")
                if sub.endswith(domain) and sub != domain:
                    subdomains.add(sub)

    logger.info(f"[crt.sh] Found {len(subdomains)} subdomains")
    return {
        "source": "crtsh",
        "type": "passive",
        "subdomains": sorted(subdomains),
        "count": len(subdomains),
    }


# ── 2. Shodan ─────────────────────────────────────────────────────────────────

async def collect_shodan(domain: str) -> dict:
    """
    Search Shodan for all hosts associated with the domain.
    Returns open ports, banners, CVEs, and geolocation.
    """
    if not SHODAN_API_KEY:
        logger.warning("[Shodan] No API key set — skipping")
        return {"source": "shodan", "type": "passive", "hosts": [], "error": "No API key"}

    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = await asyncio.to_thread(api.search, f"hostname:{domain}")

        hosts = []
        for match in results.get("matches", []):
            hosts.append({
                "ip":        match.get("ip_str"),
                "port":      match.get("port"),
                "banner":    match.get("data", "")[:500],   # truncate long banners
                "org":       match.get("org"),
                "country":   match.get("location", {}).get("country_name"),
                "vulns":     list(match.get("vulns", {}).keys()),  # CVE IDs
                "product":   match.get("product"),
                "version":   match.get("version"),
            })

        logger.info(f"[Shodan] Found {len(hosts)} hosts")
        return {
            "source": "shodan",
            "type": "passive",
            "hosts": hosts,
            "count": len(hosts),
        }

    except shodan.APIError as e:
        logger.error(f"[Shodan] API error: {e}")
        return {"source": "shodan", "type": "passive", "hosts": [], "error": str(e)}


# ── 3. GitHub Dorks ───────────────────────────────────────────────────────────

GITHUB_DORKS = [
    '"{domain}" password',
    '"{domain}" secret',
    '"{domain}" api_key',
    '"{domain}" apikey',
    '"{domain}" token',
    '"{domain}" credentials',
    '"{domain}" private_key',
    '"{domain}" aws_access_key',
    '"{domain}" .env',
    '"{domain}" config.yml',
]

async def collect_github_dorks(domain: str) -> dict:
    """
    Search GitHub code for leaked secrets, credentials, and config files
    mentioning the target domain.
    """
    if not GITHUB_TOKEN:
        logger.warning("[GitHub] No token set — skipping")
        return {"source": "github", "type": "passive", "leaks": [], "error": "No token"}

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }

    leaks = []
    async with aiohttp.ClientSession(headers=headers) as session:
        for dork_template in GITHUB_DORKS:
            query = dork_template.format(domain=domain)
            url = f"https://api.github.com/search/code?q={query}&per_page=5"

            # GitHub search rate limit: 30 req/min authenticated
            await asyncio.sleep(2)

            data = await _get(session, url)
            if data and data.get("items"):
                for item in data["items"]:
                    leaks.append({
                        "query":      query,
                        "repo":       item["repository"]["full_name"],
                        "file":       item["path"],
                        "url":        item["html_url"],
                        "score":      item.get("score", 0),
                    })

    logger.info(f"[GitHub] Found {len(leaks)} potential leaks")
    return {
        "source": "github",
        "type": "passive",
        "leaks": leaks,
        "count": len(leaks),
    }


# ── 4. DNS Enumeration ────────────────────────────────────────────────────────

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]

async def collect_dns(domain: str) -> dict:
    """
    Enumerate DNS records for the target domain.
    TXT records often expose SPF, DMARC, verification tokens.
    MX records reveal mail providers (often Microsoft/Google — useful for phishing sim).
    """
    records = {}

    def _query(rtype: str):
        try:
            answers = dns.resolver.resolve(domain, rtype)
            return [str(r) for r in answers]
        except Exception:
            return []

    for rtype in DNS_RECORD_TYPES:
        records[rtype] = await asyncio.to_thread(_query, rtype)

    # Also grab WHOIS
    whois_data = {}
    try:
        w = await asyncio.to_thread(whois.whois, domain)
        whois_data = {
            "registrar":    w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "org":          w.org,
            "emails":       w.emails,
        }
    except Exception as e:
        logger.warning(f"[WHOIS] Failed: {e}")

    logger.info(f"[DNS] Collected {len(DNS_RECORD_TYPES)} record types")
    return {
        "source": "dns",
        "type": "passive",
        "records": records,
        "whois": whois_data,
    }


# ── 5. ASN / IP Range Lookup ──────────────────────────────────────────────────

async def collect_asn(domain: str) -> dict:
    """
    Resolve the domain to IPs and look up ASN/org info via bgpview.io.
    Reveals the full IP range owned by the target — useful for expanding scope.
    """
    try:
        ip = await asyncio.to_thread(socket.gethostbyname, domain)
    except Exception as e:
        return {"source": "asn", "type": "passive", "error": str(e)}

    async with aiohttp.ClientSession() as session:
        data = await _get(session, f"https://api.bgpview.io/ip/{ip}")

    result = {"source": "asn", "type": "passive", "ip": ip}

    if data and data.get("status") == "ok":
        prefixes = data.get("data", {}).get("prefixes", [])
        result["prefixes"] = [
            {
                "prefix": p.get("prefix"),
                "asn":    p.get("asn", {}).get("asn"),
                "org":    p.get("asn", {}).get("description"),
                "country": p.get("country_code"),
            }
            for p in prefixes
        ]

    logger.info(f"[ASN] Resolved {domain} → {ip}")
    return result


# ── Run all passive collectors ────────────────────────────────────────────────

async def run_all_passive(domain: str) -> list[dict]:
    """
    Fire all passive collectors concurrently.
    Returns a list of normalized result dicts.
    """
    tasks = [
        collect_crtsh(domain),
        collect_shodan(domain),
        collect_github_dorks(domain),
        collect_dns(domain),
        collect_asn(domain),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Replace exceptions with error dicts so one failure doesn't kill the run
    clean = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            logger.error(f"Passive collector {i} crashed: {r}")
            clean.append({"source": f"passive_{i}", "error": str(r)})
        else:
            clean.append(r)

    return clean
