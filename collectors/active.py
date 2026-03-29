"""
collectors/active.py
─────────────────────
Active recon collectors — these make direct contact with the target.
Always ensure you have written authorization before running these.
Each function returns a normalized dict with 'source' and data fields.
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile

import nmap

from config import (
    SUBLIST3R_PATH, GOBUSTER_PATH, WHATWEB_PATH, WORDLIST_PATH,
    NMAP_TIMING, DEFAULT_MODE,
    TIMEOUT_NMAP, TIMEOUT_SUBLIST3R, TIMEOUT_GOBUSTER, TIMEOUT_WHATWEB,
)

logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _run_subprocess(cmd: list[str], timeout: int) -> tuple[str, str]:
    """Run a shell tool asynchronously. Returns (stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="ignore"), stderr.decode(errors="ignore")
    except asyncio.TimeoutError:
        logger.warning(f"Subprocess timed out: {' '.join(cmd)}")
        return "", "timeout"
    except Exception as e:
        logger.error(f"Subprocess error: {e}")
        return "", str(e)


# ── 1. Nmap — Port + Service + Version Scan ───────────────────────────────────

async def collect_nmap(target: str, mode: str = DEFAULT_MODE) -> dict:
    """
    Run nmap against the target with service/version detection.
    Maps open ports to service names and versions — feeds directly into
    CVE lookup and AI risk scoring.

    Flags used:
      -sV   version detection
      -sC   default scripts (grabs banners, checks for common vulns)
      -T4   timing (aggressive but not reckless)
      --top-ports 1000   scan the 1000 most common ports
    """
    timing = NMAP_TIMING.get(mode, "-T4")
    nm = nmap.PortScanner()

    logger.info(f"[Nmap] Starting scan on {target} ({mode} mode)")

    try:
        await asyncio.to_thread(
            nm.scan,
            target,
            arguments=f"-sV -sC {timing} --top-ports 1000",
        )
    except Exception as e:
        logger.error(f"[Nmap] Scan failed: {e}")
        return {"source": "nmap", "type": "active", "hosts": [], "error": str(e)}

    hosts = []
    for host in nm.all_hosts():
        host_info = {
            "host":     host,
            "hostname": nm[host].hostname(),
            "state":    nm[host].state(),
            "ports":    [],
        }
        for proto in nm[host].all_protocols():
            for port, data in nm[host][proto].items():
                host_info["ports"].append({
                    "port":     port,
                    "protocol": proto,
                    "state":    data["state"],
                    "service":  data["name"],
                    "product":  data.get("product", ""),
                    "version":  data.get("version", ""),
                    "extrainfo":data.get("extrainfo", ""),
                    "scripts":  data.get("script", {}),
                })
        hosts.append(host_info)

    logger.info(f"[Nmap] Found {len(hosts)} hosts, {sum(len(h['ports']) for h in hosts)} open ports")
    return {
        "source": "nmap",
        "type":   "active",
        "hosts":  hosts,
        "count":  len(hosts),
    }


# ── 2. Sublist3r — Active Subdomain Enumeration ───────────────────────────────

async def collect_sublist3r(domain: str) -> dict:
    """
    Run Sublist3r for active subdomain bruteforce + scraping.
    Complements crt.sh by hitting search engines and brute-forcing.

    Install: pip install sublist3r  OR  git clone https://github.com/aboul3la/Sublist3r
    """
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        outfile = f.name

    cmd = [
        SUBLIST3R_PATH, "-d", domain,
        "-o", outfile,
        "-n",        # no color output
        "-v",        # verbose
    ]

    logger.info(f"[Sublist3r] Enumerating subdomains for {domain}")
    stdout, stderr = await _run_subprocess(cmd, TIMEOUT_SUBLIST3R)

    subdomains = []
    if os.path.exists(outfile):
        with open(outfile) as f:
            subdomains = [line.strip() for line in f if line.strip()]
        os.unlink(outfile)

    logger.info(f"[Sublist3r] Found {len(subdomains)} subdomains")
    return {
        "source":     "sublist3r",
        "type":       "active",
        "subdomains": subdomains,
        "count":      len(subdomains),
    }


# ── 3. Gobuster — Directory + VHost Bruteforce ────────────────────────────────

async def collect_gobuster_dirs(domain: str) -> dict:
    """
    Bruteforce directories and files on the target web server.
    Finds hidden admin panels, backup files, API endpoints, and more.

    Install: go install github.com/OJ/gobuster/v3@latest
    """
    if not os.path.exists(WORDLIST_PATH):
        logger.warning(f"[Gobuster] Wordlist not found at {WORDLIST_PATH}")
        return {"source": "gobuster", "type": "active", "paths": [], "error": "Wordlist missing"}

    cmd = [
        GOBUSTER_PATH, "dir",
        "-u", f"https://{domain}",
        "-w", WORDLIST_PATH,
        "-q",             # quiet — only print results
        "--no-error",
        "-o", "/tmp/gobuster_out.txt",
        "-t", "20",       # 20 threads
        "-x", "php,html,js,json,txt,bak,xml",  # file extensions
    ]

    logger.info(f"[Gobuster] Dir scan on {domain}")
    stdout, stderr = await _run_subprocess(cmd, TIMEOUT_GOBUSTER)

    findings = []
    # Parse gobuster output: "/path (Status: 200) [Size: 1234]"
    pattern = re.compile(r"(/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?")
    for line in stdout.splitlines():
        m = pattern.search(line)
        if m:
            findings.append({
                "path":   m.group(1),
                "status": int(m.group(2)),
                "size":   int(m.group(3)) if m.group(3) else None,
            })

    # Also read output file if it exists
    if os.path.exists("/tmp/gobuster_out.txt"):
        with open("/tmp/gobuster_out.txt") as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    entry = {
                        "path": m.group(1),
                        "status": int(m.group(2)),
                        "size": int(m.group(3)) if m.group(3) else None,
                    }
                    if entry not in findings:
                        findings.append(entry)

    # Flag interesting status codes
    interesting = [f for f in findings if f["status"] in (200, 201, 301, 302, 403, 500)]

    logger.info(f"[Gobuster] Found {len(findings)} paths ({len(interesting)} interesting)")
    return {
        "source":      "gobuster",
        "type":        "active",
        "paths":       findings,
        "interesting": interesting,
        "count":       len(findings),
    }


# ── 4. WhatWeb — Technology Fingerprinting ────────────────────────────────────

async def collect_whatweb(domain: str) -> dict:
    """
    Fingerprint web technologies running on the target.
    Identifies CMS, frameworks, server software, JS libraries, WAFs, CDNs.

    Install: gem install whatweb  OR  apt install whatweb
    """
    outfile = "/tmp/whatweb_out.json"
    cmd = [
        WHATWEB_PATH,
        f"https://{domain}",
        "--log-json", outfile,
        "--quiet",
        "-a", "3",   # aggression level 3 (sends a few extra requests)
    ]

    logger.info(f"[WhatWeb] Fingerprinting {domain}")
    stdout, stderr = await _run_subprocess(cmd, TIMEOUT_WHATWEB)

    technologies = []
    try:
        if os.path.exists(outfile):
            with open(outfile) as f:
                raw = json.load(f)
            # WhatWeb JSON: list of targets, each with plugins dict
            for target in raw if isinstance(raw, list) else [raw]:
                plugins = target.get("plugins", {})
                for tech, details in plugins.items():
                    entry = {"technology": tech}
                    # Extract version if present
                    versions = details.get("version", [])
                    if versions:
                        entry["version"] = versions[0]
                    string_data = details.get("string", [])
                    if string_data:
                        entry["detail"] = string_data[0][:200]
                    technologies.append(entry)
    except Exception as e:
        logger.warning(f"[WhatWeb] Parse error: {e}")

    # Flag high-value tech findings
    vuln_indicators = ["WordPress", "Drupal", "Joomla", "Apache", "nginx",
                       "PHP", "jQuery", "Bootstrap", "Tomcat", "IIS"]
    flagged = [t for t in technologies if t["technology"] in vuln_indicators]

    logger.info(f"[WhatWeb] Detected {len(technologies)} technologies")
    return {
        "source":       "whatweb",
        "type":         "active",
        "technologies": technologies,
        "flagged":      flagged,
        "count":        len(technologies),
    }


# ── 5. HTTP Headers Grab ──────────────────────────────────────────────────────

import aiohttp

async def collect_http_headers(domain: str) -> dict:
    """
    Grab HTTP response headers from the target.
    Missing security headers (CSP, HSTS, X-Frame-Options) are findings.
    Server header leaks software version.
    """
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    headers = {}
    missing_security = []

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://{domain}",
                timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=True,
                ssl=False,
            ) as resp:
                headers = dict(resp.headers)

        for h in security_headers:
            if h.lower() not in {k.lower() for k in headers}:
                missing_security.append(h)

    except Exception as e:
        logger.warning(f"[Headers] Failed for {domain}: {e}")
        return {"source": "http_headers", "type": "active", "error": str(e)}

    logger.info(f"[Headers] Grabbed headers, {len(missing_security)} missing security headers")
    return {
        "source":           "http_headers",
        "type":             "active",
        "headers":          headers,
        "missing_security": missing_security,
        "server":           headers.get("Server", headers.get("server", "unknown")),
    }


# ── Run all active collectors ─────────────────────────────────────────────────

async def run_all_active(domain: str, mode: str = DEFAULT_MODE) -> list[dict]:
    """
    Fire all active collectors concurrently.
    Pass mode='stealth' to skip (returns empty list for passive-only runs).
    """
    if mode == "stealth":
        logger.info("Stealth mode — skipping active collectors")
        return []

    tasks = [
        collect_nmap(domain, mode),
        collect_sublist3r(domain),
        collect_gobuster_dirs(domain),
        collect_whatweb(domain),
        collect_http_headers(domain),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    clean = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            logger.error(f"Active collector {i} crashed: {r}")
            clean.append({"source": f"active_{i}", "type": "active", "error": str(r)})
        else:
            clean.append(r)

    return clean
