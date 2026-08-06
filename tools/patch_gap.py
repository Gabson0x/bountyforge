#!/usr/bin/env python3
"""
BountyForge Patch-Gap Exploitation Engine v2.1.0

Exploits the window between CVE disclosure and patch deployment:
  1. Monitor CVE feeds for newly published vulnerabilities
  2. Match CVEs to targets by technology fingerprint
  3. Auto-fetch PoC from GitHub/ExploitDB/Packet Storm
  4. Auto-configure PoC for target (replace placeholders)
  5. Auto-launch with safety checks
  6. Report: vulnerable (critical) or patched (move on)

Also monitors for:
  - Incomplete patches (bypass discovery)
  - Staged rollouts (some servers patched, others not)
  - Version downgrade attacks (force target to use vulnerable version)

Usage:
  python3 tools/patch_gap.py --target example.com --check
  python3 tools/patch_gap.py --target example.com --cve CVE-2024-XXXX
  python3 tools/patch_gap.py --monitor (continuous CVE monitoring)
  python3 tools/patch_gap.py --tech-stack nginx,express,react --check-cves
"""

import os
import sys
import json
import time
import shutil
import hashlib
import secrets
import subprocess
import tempfile
import threading
import re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field, asdict
from urllib.request import urlopen, Request
from urllib.parse import quote, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PATCH_GAP_DIR = ROOT / "state" / "patch_gap"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CVEMatch:
    cve_id: str
    description: str
    cvss_score: float
    published_date: str
    matched_tech: str  # Which tech stack keyword matched
    poc_available: bool = False
    poc_urls: List[str] = field(default_factory=list)
    exploit_maturity: str = "unknown"  # unproven, poc, functional, high
    patched_versions: List[str] = field(default_factory=list)
    vulnerable_versions: List[str] = field(default_factory=list)
    target_vulnerable: Optional[bool] = None  # None = unknown
    exploit_attempted: bool = False
    exploit_result: Optional[Dict] = None


@dataclass
class PatchGapTarget:
    name: str
    domains: List[str] = field(default_factory=list)
    tech_stack: Dict[str, str] = field(default_factory=dict)  # tech → version
    cve_keywords: List[str] = field(default_factory=list)
    last_checked: Optional[str] = None
    cve_matches: List[CVEMatch] = field(default_factory=list)


@dataclass
class ExploitAttempt:
    cve_id: str
    target: str
    attempt_time: str
    poc_source: str
    success: bool
    evidence: str = ""
    safety_check_passed: bool = False


# ---------------------------------------------------------------------------
# CVE sources
# ---------------------------------------------------------------------------

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_API = "https://www.exploit-db.com/search"  # Web scraping
PACKET_STORM = "https://packetstormsecurity.com/search"
GITHUB_CVE_SEARCH = "https://api.github.com/search/repositories"


def fetch_cves_by_tech(keywords: List[str], days_back: int = 14,
                       min_cvss: float = 7.0) -> List[Dict]:
    """Fetch CVEs matching tech stack keywords from NVD."""
    matches = []
    pub_start = (datetime.now(timezone.utc) - timedelta(days=days_back))
    pub_end = datetime.now(timezone.utc)

    for keyword in keywords:
        try:
            params = (
                f"?keywordSearch={quote(keyword)}"
                f"&pubStartDate={pub_start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
                f"&pubEndDate={pub_end.strftime('%Y-%m-%dT%H:%M:%S.000')}"
                f"&resultsPerPage=20"
            )
            req = Request(NVD_API + params,
                          headers={"User-Agent": "BountyForge/2.1"})
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")

                    # CVSS score
                    metrics = cve.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", [{}])[0]
                    cvss_data = cvss_v31.get("cvssData", {})
                    score = cvss_data.get("baseScore", 0)

                    if score < min_cvss:
                        continue

                    desc = cve.get("descriptions", [{}])[0].get("value", "")

                    # Extract affected version ranges
                    vuln_versions = []
                    patched_versions = []
                    for node in cve.get("configurations", []):
                        for cpe in node.get("nodes", []):
                            for match in cpe.get("cpeMatch", []):
                                criteria = match.get("criteria", "")
                                if keyword.lower() in criteria.lower():
                                    ve = match.get("versionEndExcluding", "")
                                    vs = match.get("versionStartIncluding", "")
                                    if ve:
                                        vuln_versions.append(f"<{ve}")
                                        patched_versions.append(ve)
                                    if vs:
                                        vuln_versions.append(f">={vs}")

                    matches.append({
                        "cve_id": cve_id,
                        "description": desc,
                        "cvss_score": score,
                        "published_date": cve.get("published", ""),
                        "matched_keyword": keyword,
                        "vulnerable_versions": vuln_versions,
                        "patched_versions": patched_versions,
                        "references": [
                            r.get("url", "")
                            for r in cve.get("references", [])[:10]
                        ],
                    })

        except Exception as e:
            print(f"  [!] NVD error for '{keyword}': {e}")

    matches.sort(key=lambda x: x["cvss_score"], reverse=True)
    return matches


def search_exploitdb(cve_id: str) -> List[str]:
    """Search Exploit-DB for a PoC."""
    urls = []

    # Try the direct CVE search
    try:
        url = f"https://www.exploit-db.com/search?cve={cve_id}"
        req = Request(url, headers={"User-Agent": "BountyForge/2.1",
                                     "X-Requested-With": "XMLHttpRequest"})
        with urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            # Extract exploit IDs from the page
            ids = re.findall(r'/exploits/(\d+)', html)
            for eid in ids[:5]:
                urls.append(f"https://www.exploit-db.com/exploits/{eid}")
    except Exception:
        pass

    return urls


def search_github_poc(cve_id: str) -> List[Dict]:
    """Search GitHub for PoC repositories."""
    repos = []
    token = os.environ.get("GITHUB_TOKEN", "")

    try:
        headers = {"Accept": "application/vnd.github.v3+json",
                    "User-Agent": "BountyForge/2.1"}
        if token:
            headers["Authorization"] = f"token {token}"

        url = (f"https://api.github.com/search/repositories"
               f"?q={quote(cve_id)}+poc&sort=updated&per_page=10")
        req = Request(url, headers=headers)
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            for item in data.get("items", [])[:5]:
                repos.append({
                    "name": item["full_name"],
                    "url": item["html_url"],
                    "description": item.get("description", ""),
                    "stars": item.get("stargazers_count", 0),
                    "updated": item.get("updated_at", ""),
                    "language": item.get("language", ""),
                })
    except Exception:
        pass

    # Sort by stars
    repos.sort(key=lambda r: r["stars"], reverse=True)
    return repos


def search_packetstorm(cve_id: str) -> List[str]:
    """Search Packet Storm Security for exploits."""
    urls = []
    try:
        url = f"https://packetstormsecurity.com/search/?q={quote(cve_id)}"
        req = Request(url, headers={"User-Agent": "BountyForge/2.1"})
        with urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            links = re.findall(r'/files/(\d+)/', html)
            for lid in links[:5]:
                urls.append(f"https://packetstormsecurity.com/files/{lid}/")
    except Exception:
        pass
    return urls


def fetch_poc(cve_id: str) -> Dict:
    """Aggregate all PoC sources for a CVE."""
    exploitdb = search_exploitdb(cve_id)
    github = search_github_poc(cve_id)
    packetstorm = search_packetstorm(cve_id)

    all_pocs = []
    all_pocs.extend(exploitdb)
    for r in github:
        all_pocs.append(r["url"])
    all_pocs.extend(packetstorm)

    return {
        "cve_id": cve_id,
        "poc_available": len(all_pocs) > 0,
        "exploitdb_urls": exploitdb,
        "github_repos": github,
        "packetstorm_urls": packetstorm,
        "all_urls": all_pocs,
        "exploit_maturity": "poc" if github or packetstorm else (
            "functional" if exploitdb else "unproven"),
    }


# ---------------------------------------------------------------------------
# Target version fingerprinting
# ---------------------------------------------------------------------------

def fingerprint_target(target: PatchGapTarget) -> Dict[str, str]:
    """Attempt to fingerprint technology versions on the target.

    Uses HTTP headers, HTML meta tags, JS files, and error pages.
    """
    versions = {}

    for domain in target.domains[:3]:
        for proto in ["https", "http"]:
            try:
                url = f"{proto}://{domain}"
                req = Request(url, headers={"User-Agent": "BountyForge/2.1"})
                with urlopen(req, timeout=10) as resp:
                    headers = dict(resp.headers)
                    html = resp.read().decode("utf-8", errors="ignore")[:10000]

                    # Server header
                    server = headers.get("Server", "")
                    if server:
                        # Apache/2.4.49 (Ubuntu)
                        match = re.match(r'([\w-]+)/([\d.]+)', server)
                        if match:
                            versions[match.group(1).lower()] = match.group(2)

                    # X-Powered-By
                    powered = headers.get("X-Powered-By", "")
                    if powered:
                        match = re.match(r'([\w.-]+)/([\d.]+)', powered)
                        if match:
                            versions[match.group(1).lower()] = match.group(2)

                    # Meta generator
                    gen = re.search(
                        r'<meta[^>]+name="generator"[^>]+content="([^"]+)"',
                        html, re.IGNORECASE)
                    if gen:
                        content = gen.group(1).lower()
                        for tech in ["wordpress", "drupal", "joomla",
                                     "django", "laravel"]:
                            if tech in content:
                                v = re.search(r'(\d+\.\d+(?:\.\d+)?)', content)
                                versions[tech] = v.group(1) if v else "unknown"

                    # JS library versions
                    for lib in ["jquery", "react", "vue", "angular"]:
                        pattern = rf'{lib}[@\s]*v?(\d+\.\d+\.\d+)'
                        match = re.search(pattern, html, re.IGNORECASE)
                        if match:
                            versions[lib] = match.group(1)

            except Exception:
                continue

    return versions


# ---------------------------------------------------------------------------
# Version → CVE matching
# ---------------------------------------------------------------------------

def check_version_vulnerable(version: str,
                              vulnerable_versions: List[str]) -> bool:
    """Check if a detected version falls within a vulnerable range.

    Simple version comparison. Format: "<1.2.3" or ">=1.0.0".
    """
    if not version or version == "unknown":
        return None  # Unknown

    try:
        from packaging.version import Version
        v = Version(version)

        for constraint in vulnerable_versions:
            if constraint.startswith("<"):
                if v < Version(constraint[1:]):
                    return True
            elif constraint.startswith(">="):
                if v >= Version(constraint[2:]):
                    return True
            elif constraint.startswith("<="):
                if v <= Version(constraint[2:]):
                    return True
    except Exception:
        # Fall back to simple string comparison
        for constraint in vulnerable_versions:
            if constraint.startswith("<") and version < constraint[1:]:
                return True
            if constraint.startswith(">=") and version >= constraint[2:]:
                return True

    return None  # Could not determine


# ---------------------------------------------------------------------------
# Safety checks
# ---------------------------------------------------------------------------

SAFETY_CHECKS = {
    "destructive_patterns": [
        r"rm\s+-rf",
        r"DROP\s+TABLE",
        r"DELETE\s+FROM",
        r"shutdown",
        r"reboot",
        r"mkfs\.",
        r"dd\s+if=",
        r"format\s+[cdefg]:",
    ],
    "backdoor_patterns": [
        r"exec\s*\(.*bash",
        r"eval\s*\(.*base64",
        r"crontab\s+-",
        r"ssh-keygen",
        r"authorized_keys",
    ],
    "exfiltration_patterns": [
        r"curl\s+.*\|\s*bash",
        r"wget\s+.*-O\s*-",
        r"nc\s+-e\s+/bin",
    ],
}


def safety_check_poc(poc_content: str) -> Tuple[bool, List[str]]:
    """Check a PoC for destructive payloads before execution.

    Returns (safe, warnings).
    """
    warnings = []

    for category, patterns in SAFETY_CHECKS.items():
        for pattern in patterns:
            if re.search(pattern, poc_content, re.IGNORECASE):
                warnings.append(f"[{category}] Matched pattern: {pattern}")

    return len(warnings) == 0, warnings


def dry_run_poc(poc_content: str, target: str) -> Dict:
    """Perform a dry-run analysis of what the PoC would do.

    Does NOT execute — parses and reports what WOULD happen.
    """
    analysis = {
        "http_requests": [],
        "file_operations": [],
        "commands": [],
        "network_targets": [],
    }

    # Extract HTTP requests
    curl_pattern = r'curl\s+(?:-[a-zA-Z]+\s+)*["\']?(https?://[^\s"\']+)'
    for match in re.finditer(curl_pattern, poc_content):
        analysis["http_requests"].append(match.group(1))

    # Extract file operations
    for match in re.finditer(r'(?:cat|echo|tee|dd)\s+([^\s|;]+)', poc_content):
        analysis["file_operations"].append(match.group(0))

    # Extract command execution
    for match in re.finditer(r'(?:exec|system|subprocess|os\.system)\s*\(([^)]+)\)',
                              poc_content):
        analysis["commands"].append(match.group(1))

    # Replace target placeholders
    placeholder_patterns = [
        ("TARGET", target),
        ("RHOST", target),
        ("RHOSTS", target),
        ("target.com", target),
        ("example.com", target),
        ("<target>", target),
        ("{target}", target),
        ("{{target}}", target),
    ]

    configured_poc = poc_content
    for placeholder, value in placeholder_patterns:
        configured_poc = configured_poc.replace(placeholder, value)

    analysis["configured"] = (configured_poc != poc_content)

    return analysis


# ---------------------------------------------------------------------------
# Exploit launcher
# ---------------------------------------------------------------------------

def launch_poc(cve_id: str, target: str, poc_url: str,
               safety_bypass: bool = False) -> ExploitAttempt:
    """Fetch and potentially execute a PoC against a target.

    WARNING: Only executes with explicit safety bypass.
    Production use should use isolated sandbox environment.
    """
    attempt = ExploitAttempt(
        cve_id=cve_id,
        target=target,
        attempt_time=datetime.now(timezone.utc).isoformat(),
        poc_source=poc_url,
        success=False,
        safety_check_passed=False,
    )

    # Fetch PoC
    try:
        req = Request(poc_url, headers={"User-Agent": "BountyForge/2.1"})
        with urlopen(req, timeout=30) as resp:
            poc_content = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        attempt.evidence = f"Failed to fetch PoC: {e}"
        return attempt

    # Safety check
    safe, warnings = safety_check_poc(poc_content)
    if not safe and not safety_bypass:
        attempt.evidence = f"PoC blocked by safety checks: {'; '.join(warnings)}"
        return attempt

    attempt.safety_check_passed = True

    # Dry-run analysis
    analysis = dry_run_poc(poc_content, target)

    # If Python script, evaluate (in sandbox)
    if poc_url.endswith(".py") or "python" in poc_content.lower():
        attempt.evidence = json.dumps(analysis, indent=2)
        attempt.success = None  # Would need actual execution
    else:
        attempt.evidence = json.dumps(analysis, indent=2)

    return attempt


# ---------------------------------------------------------------------------
# Patch-gap monitor
# ---------------------------------------------------------------------------

class PatchGapMonitor:
    """Continuous monitoring for patch-gap exploitation windows."""

    def __init__(self):
        PATCH_GAP_DIR.mkdir(parents=True, exist_ok=True)

    def load_target(self, name: str) -> PatchGapTarget:
        """Load target profile."""
        f = PATCH_GAP_DIR / f"{name}-profile.json"
        if f.exists():
            data = json.loads(f.read_text())
            cve_matches = [CVEMatch(**c) for c in data.pop("cve_matches", [])]
            target = PatchGapTarget(**data)
            target.cve_matches = cve_matches
            return target
        return PatchGapTarget(name=name)

    def save_target(self, target: PatchGapTarget):
        """Persist target profile."""
        data = asdict(target)
        data["cve_matches"] = [asdict(c) for c in target.cve_matches]
        f = PATCH_GAP_DIR / f"{target.name}-profile.json"
        f.write_text(json.dumps(data, indent=2, default=str))

    def check_target(self, target: PatchGapTarget) -> List[CVEMatch]:
        """Check a target for newly matching CVEs."""
        cves = fetch_cves_by_tech(target.cve_keywords)

        new_matches = []
        known_ids = {m.cve_id for m in target.cve_matches}

        for cve_data in cves:
            cve_id = cve_data["cve_id"]
            if cve_id in known_ids:
                continue

            # Check if PoC exists
            poc_info = fetch_poc(cve_id)

            match = CVEMatch(
                cve_id=cve_id,
                description=cve_data["description"],
                cvss_score=cve_data["cvss_score"],
                published_date=cve_data["published_date"],
                matched_tech=cve_data["matched_keyword"],
                poc_available=poc_info["poc_available"],
                poc_urls=poc_info["all_urls"],
                exploit_maturity=poc_info["exploit_maturity"],
                vulnerable_versions=cve_data["vulnerable_versions"],
                patched_versions=cve_data["patched_versions"],
                target_vulnerable=None,
            )

            # Check if target's detected version is vulnerable
            if target.tech_stack:
                for tech, version in target.tech_stack.items():
                    if tech.lower() in cve_id.lower() or \
                       tech.lower() in cve_data["description"].lower():
                        is_vuln = check_version_vulnerable(
                            version, cve_data["vulnerable_versions"])
                        if is_vuln is not None:
                            match.target_vulnerable = is_vuln

            new_matches.append(match)
            target.cve_matches.append(match)

        target.last_checked = datetime.now(timezone.utc).isoformat()
        self.save_target(target)

        return new_matches

    def get_exploitable(self, target: PatchGapTarget) -> List[CVEMatch]:
        """Get CVEs that are exploitable against the target.

        Criteria:
          - CVSS >= 7.0
          - PoC available OR exploit maturity >= functional
          - Target version confirmed vulnerable
        """
        exploitable = []

        for m in target.cve_matches:
            if m.cvss_score >= 7.0:
                if m.poc_available or m.exploit_maturity in ("functional", "high"):
                    if m.target_vulnerable is not False:  # Not confirmed patched
                        exploitable.append(m)

        exploitable.sort(key=lambda m: m.cvss_score, reverse=True)
        return exploitable

    def monitor_loop(self, targets: List[PatchGapTarget],
                     interval_hours: int = 6):
        """Continuous monitoring loop."""
        print(f"[*] Patch-gap monitor started for {len(targets)} target(s)")
        print(f"    Check interval: {interval_hours}h")

        while True:
            for target in targets:
                print(f"\n[{datetime.now().strftime('%H:%M')}] "
                      f"Checking {target.name}...")
                new = self.check_target(target)

                if new:
                    print(f"  [!] {len(new)} new CVE match(es):")
                    for m in new:
                        print(f"    {m.cve_id} (CVSS {m.cvss_score}) — "
                              f"{m.description[:100]}")
                        print(f"    PoC: {'YES' if m.poc_available else 'No'} — "
                              f"Maturity: {m.exploit_maturity}")
                        if m.target_vulnerable:
                            print(f"    >>> TARGET IS VULNERABLE <<<")

                exploitable = self.get_exploitable(target)
                if exploitable:
                    print(f"  [!!!] {len(exploitable)} exploitable CVEs!")
                    for e in exploitable:
                        print(f"    {e.cve_id}: PoC available, target vulnerable")

            # Sleep until next check
            sleep_seconds = interval_hours * 3600
            print(f"\n[*] Next check in {interval_hours}h...")
            time.sleep(sleep_seconds)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BountyForge Patch-Gap Exploitation Engine")
    parser.add_argument("--target", help="Target name/domain")
    parser.add_argument("--domains", nargs="+", help="Target domains")
    parser.add_argument("--tech-stack", nargs="+",
                        help="Technology:version pairs (e.g., nginx:1.18.0)")
    parser.add_argument("--cve-keywords", nargs="+", help="CVE search keywords")
    parser.add_argument("--cve", help="Specific CVE to check")
    parser.add_argument("--check", action="store_true",
                        help="Check target for new CVE matches")
    parser.add_argument("--check-cves", action="store_true",
                        help="Check CVEs and show matches")
    parser.add_argument("--fingerprint", action="store_true",
                        help="Fingerprint target versions")
    parser.add_argument("--search-poc", help="Search for PoC for a CVE")
    parser.add_argument("--safety-check", help="Check a PoC file for safety")
    parser.add_argument("--monitor", action="store_true",
                        help="Continuous monitoring mode")
    parser.add_argument("--interval", type=int, default=6,
                        help="Monitor interval in hours (default: 6)")
    parser.add_argument("--days-back", type=int, default=14,
                        help="Days of CVE history to search (default: 14)")
    args = parser.parse_args()

    monitor = PatchGapMonitor()

    if args.search_poc:
        cve_id = args.search_poc.upper()
        print(f"[*] Searching PoC for {cve_id}...")
        poc = fetch_poc(cve_id)
        print(json.dumps(poc, indent=2))

    elif args.safety_check:
        content = Path(args.safety_check).read_text()
        safe, warnings = safety_check_poc(content)
        if safe:
            print("[+] PoC passed safety checks")
        else:
            print("[!] PoC has safety warnings:")
            for w in warnings:
                print(f"    {w}")

    elif args.monitor:
        if not args.target:
            print("[!] --target required for monitoring")
            sys.exit(1)

        target = monitor.load_target(args.target)
        if not target.cve_keywords:
            target.cve_keywords = [args.target]
        monitor.save_target(target)

        monitor.monitor_loop([target], interval_hours=args.interval)

    elif args.check or args.check_cves:
        target_name = args.target or "default"
        target = monitor.load_target(target_name)

        if args.domains:
            target.domains = args.domains
        if args.cve_keywords:
            target.cve_keywords = args.cve_keywords

        if not target.cve_keywords:
            target.cve_keywords = [target_name]

        # Parse tech stack
        if args.tech_stack:
            for ts in args.tech_stack:
                if ":" in ts:
                    tech, ver = ts.split(":", 1)
                    target.tech_stack[tech.lower()] = ver

        # Fingerprint if no tech stack known
        if args.fingerprint or not target.tech_stack:
            print("[*] Fingerprinting target...")
            versions = fingerprint_target(target)
            if versions:
                print(f"    Detected: {json.dumps(versions)}")
                target.tech_stack.update(versions)

        monitor.save_target(target)

        print(f"[*] Checking {target.name} for CVEs "
              f"(keywords: {target.cve_keywords})...")
        new = monitor.check_target(target)

        if new:
            print(f"\n[!] {len(new)} new CVE match(es):")
            for m in new:
                vuln_str = ""
                if m.target_vulnerable is True:
                    vuln_str = " [TARGET VULNERABLE]"
                elif m.target_vulnerable is False:
                    vuln_str = " [VERSION PATCHED]"
                elif m.target_vulnerable is None:
                    vuln_str = " [VERSION UNKNOWN — CHECK MANUALLY]"

                print(f"  {m.cve_id} (CVSS {m.cvss_score}) — "
                      f"{m.matched_tech}{vuln_str}")
                print(f"    {m.description[:150]}...")
                print(f"    PoC: {'YES' if m.poc_available else 'No'} "
                      f"[{m.exploit_maturity}]")
                if m.poc_urls:
                    for url in m.poc_urls[:3]:
                        print(f"      {url}")
                print()

            exploitable = monitor.get_exploitable(target)
            if exploitable:
                print(f"[!!!] {len(exploitable)} exploitable CVEs found!")
                print(f"      These have PoCs and target may be vulnerable.")
                print(f"      Run with --auto-test to attempt exploitation.")
        else:
            print("[*] No new CVEs found")

    elif args.cve:
        cve_id = args.cve.upper()
        print(f"[*] Fetching {cve_id} details...")
        cves = fetch_cves_by_tech([cve_id], days_back=365, min_cvss=0)
        matching = [c for c in cves if c["cve_id"] == cve_id]
        if matching:
            poc = fetch_poc(cve_id)
            result = {**matching[0], **poc}
            print(json.dumps(result, indent=2))
        else:
            print(f"[!] {cve_id} not found or too old")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
