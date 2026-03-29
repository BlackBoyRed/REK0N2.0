"""
collectors/aggregator.py
─────────────────────────
Takes raw output from all passive + active collectors and produces
one clean, deduplicated, normalized ReconResult object.
This is what gets fed to the AI analysis layer.
"""

import json
import logging
import os
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

from config import RAW_DATA_DIR

logger = logging.getLogger(__name__)


# ── Normalized Schema ─────────────────────────────────────────────────────────

@dataclass
class PortInfo:
    port:      int
    protocol:  str
    state:     str
    service:   str
    product:   str   = ""
    version:   str   = ""
    extrainfo: str   = ""
    scripts:   dict  = field(default_factory=dict)

@dataclass
class HostInfo:
    ip:       str
    hostname: str         = ""
    org:      str         = ""
    country:  str         = ""
    ports:    list        = field(default_factory=list)
    vulns:    list[str]   = field(default_factory=list)  # CVE IDs from Shodan
    banner:   str         = ""

@dataclass
class LeakInfo:
    source: str
    repo:   str
    file:   str
    url:    str
    query:  str

@dataclass
class TechInfo:
    technology: str
    version:    str = ""
    detail:     str = ""
    flagged:    bool = False

@dataclass
class ReconResult:
    domain:            str
    scan_time:         str
    scan_mode:         str

    # Subdomains (merged from crt.sh + sublist3r, deduplicated)
    subdomains:        list[str]       = field(default_factory=list)

    # All discovered hosts
    hosts:             list[HostInfo]  = field(default_factory=list)

    # Leaked credentials / secrets on GitHub
    leaks:             list[LeakInfo]  = field(default_factory=list)

    # Web technologies detected
    technologies:      list[TechInfo]  = field(default_factory=list)

    # Directory / path findings
    paths:             list[dict]      = field(default_factory=list)

    # DNS records
    dns_records:       dict            = field(default_factory=dict)
    whois:             dict            = field(default_factory=dict)

    # IP ranges owned by target
    asn_prefixes:      list[dict]      = field(default_factory=list)

    # Missing HTTP security headers
    missing_headers:   list[str]       = field(default_factory=list)
    server_header:     str             = ""

    # Summary counts (filled by aggregator)
    summary:           dict            = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save(self, path: str = None) -> str:
        """Save raw result to data/raw/<domain>_<timestamp>.json"""
        os.makedirs(RAW_DATA_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = path or os.path.join(RAW_DATA_DIR, f"{self.domain}_{ts}.json")
        with open(filename, "w") as f:
            f.write(self.to_json())
        logger.info(f"Saved raw recon data to {filename}")
        return filename


# ── Aggregation Logic ─────────────────────────────────────────────────────────

def aggregate(domain: str, mode: str, raw_results: list[dict]) -> ReconResult:
    """
    Merge all collector outputs into one normalized ReconResult.
    Handles deduplication and cross-source merging.
    """
    result = ReconResult(
        domain    = domain,
        scan_time = datetime.now().isoformat(),
        scan_mode = mode,
    )

    # Track IPs we've seen so we can merge Shodan + Nmap data
    hosts_by_ip: dict[str, HostInfo] = {}
    subdomains_seen: set[str] = set()

    for collector_output in raw_results:
        if not collector_output or "error" in collector_output:
            continue

        source = collector_output.get("source", "")

        # ── Subdomains ──────────────────────────────────────────
        if source in ("crtsh", "sublist3r"):
            for sub in collector_output.get("subdomains", []):
                if sub and sub not in subdomains_seen:
                    subdomains_seen.add(sub)
                    result.subdomains.append(sub)

        # ── Hosts (Shodan — passive fingerprint) ────────────────
        elif source == "shodan":
            for h in collector_output.get("hosts", []):
                ip = h.get("ip", "")
                if ip not in hosts_by_ip:
                    hosts_by_ip[ip] = HostInfo(
                        ip      = ip,
                        org     = h.get("org", ""),
                        country = h.get("country", ""),
                        banner  = h.get("banner", ""),
                        vulns   = h.get("vulns", []),
                    )
                    hosts_by_ip[ip].ports.append(PortInfo(
                        port     = h.get("port", 0),
                        protocol = "tcp",
                        state    = "open",
                        service  = h.get("product", ""),
                        version  = h.get("version", ""),
                    ))
                else:
                    # Merge CVEs + banner from Shodan into existing host
                    hosts_by_ip[ip].vulns.extend(h.get("vulns", []))
                    if not hosts_by_ip[ip].banner:
                        hosts_by_ip[ip].banner = h.get("banner", "")

        # ── Hosts (Nmap — active port scan) ─────────────────────
        elif source == "nmap":
            for h in collector_output.get("hosts", []):
                ip = h.get("host", "")
                if ip not in hosts_by_ip:
                    hosts_by_ip[ip] = HostInfo(
                        ip       = ip,
                        hostname = h.get("hostname", ""),
                    )
                else:
                    # Nmap gives better hostname resolution
                    if h.get("hostname"):
                        hosts_by_ip[ip].hostname = h["hostname"]

                for p in h.get("ports", []):
                    hosts_by_ip[ip].ports.append(PortInfo(
                        port      = p["port"],
                        protocol  = p["protocol"],
                        state     = p["state"],
                        service   = p["service"],
                        product   = p.get("product", ""),
                        version   = p.get("version", ""),
                        extrainfo = p.get("extrainfo", ""),
                        scripts   = p.get("scripts", {}),
                    ))

        # ── GitHub Leaks ────────────────────────────────────────
        elif source == "github":
            for leak in collector_output.get("leaks", []):
                result.leaks.append(LeakInfo(
                    source = "github",
                    repo   = leak.get("repo", ""),
                    file   = leak.get("file", ""),
                    url    = leak.get("url", ""),
                    query  = leak.get("query", ""),
                ))

        # ── Technologies ────────────────────────────────────────
        elif source == "whatweb":
            flagged_names = {t["technology"] for t in collector_output.get("flagged", [])}
            for tech in collector_output.get("technologies", []):
                result.technologies.append(TechInfo(
                    technology = tech.get("technology", ""),
                    version    = tech.get("version", ""),
                    detail     = tech.get("detail", ""),
                    flagged    = tech.get("technology") in flagged_names,
                ))

        # ── Paths (Gobuster) ────────────────────────────────────
        elif source == "gobuster":
            result.paths = collector_output.get("interesting", [])

        # ── DNS ─────────────────────────────────────────────────
        elif source == "dns":
            result.dns_records = collector_output.get("records", {})
            result.whois       = collector_output.get("whois", {})

        # ── ASN ─────────────────────────────────────────────────
        elif source == "asn":
            result.asn_prefixes = collector_output.get("prefixes", [])

        # ── HTTP Headers ────────────────────────────────────────
        elif source == "http_headers":
            result.missing_headers = collector_output.get("missing_security", [])
            result.server_header   = collector_output.get("server", "")

    # Flatten hosts dict → list
    result.hosts = list(hosts_by_ip.values())

    # Deduplicate CVEs per host
    for host in result.hosts:
        host.vulns = list(set(host.vulns))

    # Sort subdomains
    result.subdomains = sorted(set(result.subdomains))

    # Build summary
    result.summary = {
        "total_subdomains":   len(result.subdomains),
        "total_hosts":        len(result.hosts),
        "total_open_ports":   sum(len(h.ports) for h in result.hosts),
        "total_leaks":        len(result.leaks),
        "total_technologies": len(result.technologies),
        "total_paths":        len(result.paths),
        "cves_found":         sum(len(h.vulns) for h in result.hosts),
        "missing_headers":    len(result.missing_headers),
    }

    logger.info(f"Aggregation complete: {result.summary}")
    return result


# ── Quick debug / standalone test ─────────────────────────────────────────────

if __name__ == "__main__":
    # Test the schema with dummy data
    dummy = [
        {"source": "crtsh", "subdomains": ["dev.example.com", "api.example.com"]},
        {"source": "shodan", "hosts": [{"ip": "1.2.3.4", "port": 443, "org": "Example Inc", "vulns": ["CVE-2021-41773"], "banner": "Apache", "country": "US", "product": "Apache", "version": "2.4.49"}]},
        {"source": "github", "leaks": [{"repo": "someone/leaked", "file": ".env", "url": "https://github.com/...", "query": '"example.com" password'}]},
    ]
    r = aggregate("example.com", "normal", dummy)
    print(r.to_json())
