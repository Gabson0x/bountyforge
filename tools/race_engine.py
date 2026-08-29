#!/usr/bin/env python3
"""
BountyForge Race Engine — Race condition testing engine.

Tests for:
  - Single-packet attacks (Turbo Intruder style)
  - TOCTOU (Time-of-Check Time-of-Use)
  - Double-spend / duplicate entity creation
  - Limit bypass (coupon, rate limit, balance checks)
  - Concurrent write conflicts

Strategy:
  1. Identify state-changing endpoints (POST, PUT, PATCH, DELETE)
  2. Send N identical requests simultaneously
  3. Analyze responses for race indicators:
     - Inconsistent status codes
     - Duplicate resources created
     - Balance/limit discrepancies
     - Rate limit bypass
     - Conflicting writes

Usage:
  python3 tools/race_engine.py --target example.com
  python3 tools/race_engine.py --url "https://example.com/api/checkout" --method POST --data '{"item":"x"}'
"""

import asyncio
import hashlib
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from collections import Counter
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from tools.http_pool import HTTPPool, HTTPResult
    HAS_HTTP = True
except ImportError:
    HAS_HTTP = False


# ── Data structures ────────────────────────────────────────

@dataclass
class RaceResult:
    url: str
    method: str
    request_count: int
    status_codes: List[int] = field(default_factory=list)
    response_bodies: List[str] = field(default_factory=list)
    body_hashes: List[str] = field(default_factory=list)
    response_times: List[float] = field(default_factory=list)
    duration_ms: float = 0.0
    inconsistencies: List[str] = field(default_factory=list)
    is_vulnerable: bool = False


@dataclass
class RaceFinding:
    id: str = ""
    type: str = "race-condition"
    severity: str = "high"
    title: str = ""
    url: str = ""
    method: str = "POST"
    payload: str = ""
    evidence: str = ""
    source: str = "race_engine"
    timestamp: float = 0.0
    reproducible: bool = True
    cvss_score: float = 7.0

    def __post_init__(self):
        if not self.id:
            raw = f"{self.url}|{self.method}|{self.type}|{self.timestamp}"
            self.id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        if not self.timestamp:
            self.timestamp = time.time()

    def to_dict(self) -> Dict:
        return asdict(self)


# ── Race Engine ────────────────────────────────────────────

class RaceEngine:
    """
    Race condition testing engine.

    Sends concurrent requests to detect:
    - Duplicate resource creation (same token used twice)
    - Balance/limit bypass (exceeding authorized amount)
    - TOCTOU vulnerabilities (stale check data)
    - Rate limit bypass
    - Inconsistent state from concurrent writes
    """

    # Endpoint patterns likely to have race conditions
    RACE_SENSITIVE_PATTERNS = [
        "checkout", "purchase", "order", "payment",
        "transfer", "withdraw", "spend", "redeem",
        "apply", "use", "activate", "claim",
        "vote", "like", "follow", "subscribe",
        "reserve", "book", "cancel", "refund",
        "invite", "register", "enroll",
    ]

    def __init__(self, http_pool: HTTPPool, state_dir: str = None):
        self.http_pool = http_pool
        self.state_dir = state_dir or os.path.join(
            os.environ.get("BF_STATE_DIR", str(ROOT / "state")), "bus"
        )

    # ── Main entry point ───────────────────────────────────

    async def test_endpoints(
        self,
        urls: List[str],
        max_endpoints: int = 20,
    ) -> List[RaceFinding]:
        """
        Run race condition tests against state-changing endpoints.
        Filters URLs for those matching sensitive patterns.
        """
        findings = []

        sensitive = [
            u for u in urls
            if any(p in u.lower() for p in self.RACE_SENSITIVE_PATTERNS)
        ]

        if not sensitive:
            # Test all POST/PUT endpoints
            sensitive = urls[:max_endpoints]

        print(f"[race] Testing {len(sensitive[:max_endpoints])} race-sensitive endpoints")

        for url in sensitive[:max_endpoints]:
            # Determine method based on endpoint name
            method = self._guess_method(url)

            # Single-packet attack
            result = await self.single_packet_attack(url, method, count=20)
            if result.is_vulnerable:
                findings.append(self._result_to_finding(result))

            # For checkout/payment/transfer — test double-spend
            if any(p in url.lower() for p in ["checkout", "purchase", "transfer", "withdraw", "spend", "redeem"]):
                result = await self.double_spend_test(url, method)
                if result.is_vulnerable:
                    findings.append(self._result_to_finding(result))

            # Small delay between endpoints to avoid rate limiting
            await asyncio.sleep(0.1)

        print(f"[race] Complete: {len(findings)} race condition findings")
        return findings

    # ── Single-packet attack ───────────────────────────────

    async def single_packet_attack(
        self,
        url: str,
        method: str = "POST",
        data: Dict = None,
        count: int = 20,
    ) -> RaceResult:
        """
        Send N requests as fast as possible — send all before reading any response.
        This is the most effective race condition technique.

        Uses asyncio.create_task() to fire all requests, then gather.
        """
        start = time.monotonic()

        # Build a unique marker to detect if requests were processed independently
        marker = f"RACE-{secrets.token_hex(4)}"

        request_data = data or {"race_test": marker, "timestamp": int(time.time())}

        # Fire all requests simultaneously
        tasks = []
        for i in range(count):
            task = asyncio.create_task(
                self.http_pool.request(
                    method=method,
                    url=url,
                    json_data=request_data,
                    headers={"X-Race-Id": f"{marker}-{i}"},
                )
            )
            tasks.append(task)

        # Gather all results
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        duration = (time.monotonic() - start) * 1000

        # Normalize results
        results: List[HTTPResult] = []
        for r in raw_results:
            if isinstance(r, Exception):
                results.append(HTTPResult(url=url, method=method, status=-1, error=str(r)))
            else:
                results.append(r)

        return self._analyze_results(url, method, results, duration)

    # ── Double-spend test ──────────────────────────────────

    async def double_spend_test(
        self,
        url: str,
        method: str = "POST",
        count: int = 10,
    ) -> RaceResult:
        """
        Double-spend detection:
        Send N identical requests for an action that should only succeed once
        (e.g., applying a coupon, spending a token, redeeming a code).
        """
        start = time.monotonic()

        # Use a unique identifier for this test
        test_id = f"BF-DOUBLE-{secrets.token_hex(6)}"

        payload = {
            "id": test_id,
            "code": "TEST-COUPON-100",
            "amount": 1,
            "race_test": True,
        }

        tasks = []
        for i in range(count):
            task = asyncio.create_task(
                self.http_pool.request(
                    method=method,
                    url=url,
                    json_data=payload,
                    headers={
                        "X-Idempotency-Key": f"{test_id}-{i}",
                        "X-Test-Id": test_id,
                    },
                )
            )
            tasks.append(task)

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        duration = (time.monotonic() - start) * 1000

        results: List[HTTPResult] = []
        for r in raw_results:
            if isinstance(r, Exception):
                results.append(HTTPResult(url=url, method=method, status=-1, error=str(r)))
            else:
                results.append(r)

        return self._analyze_double_spend(url, method, results, duration)

    # ── TOCTOU test ────────────────────────────────────────

    async def toctou_test(
        self,
        url: str,
        check_url: str = None,
        method: str = "PUT",
    ) -> RaceResult:
        """
        Time-of-Check Time-of-Use test.

        1. Send GET request to read current state (check)
        2. Immediately send PUT/POST to modify state (use)
        3. Send GET again to see if state is consistent
        """
        start = time.monotonic()

        # Check: read current state
        check_url = check_url or url
        check_result = await self.http_pool.request("GET", check_url)
        check_data = check_result.body

        # Use: modify state + check simultaneously
        tasks = []
        for i in range(10):
            tasks.append(asyncio.create_task(
                self.http_pool.request(method, url, json_data={"value": f"toctou-{i}"})
            ))
        tasks.append(asyncio.create_task(
            self.http_pool.request("GET", check_url)
        ))

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        duration = (time.monotonic() - start) * 1000

        results: List[HTTPResult] = []
        for r in raw_results:
            if isinstance(r, Exception):
                results.append(HTTPResult(url=url, method=method, status=-1, error=str(r)))
            else:
                results.append(r)

        return self._analyze_results(url, method, results, duration)

    # ── Response analysis ──────────────────────────────────

    def _analyze_results(
        self,
        url: str,
        method: str,
        results: List[HTTPResult],
        duration: float,
    ) -> RaceResult:
        """Analyze concurrent request results for race condition signals."""
        status_codes = [r.status for r in results]
        bodies = [r.body for r in results if r.body]
        body_hashes = [r.body_hash for r in results if r.body_hash]
        response_times = [r.duration_ms for r in results if r.duration_ms > 0]

        inconsistencies: List[str] = []
        is_vulnerable = False

        # Signal 1: Multiple different status codes (should be consistent for idempotent ops)
        unique_statuses = set(status_codes)
        if len(unique_statuses) > 2 and -1 not in unique_statuses:
            inconsistencies.append(
                f"Multiple status codes ({len(unique_statuses)} unique): {sorted(unique_statuses)}"
            )
            is_vulnerable = True

        # Signal 2: Multiple 200/201 responses for what should be a one-time action
        success_count = sum(1 for s in status_codes if s in (200, 201, 202))
        if success_count > 1:
            inconsistencies.append(
                f"{success_count}/{len(results)} requests succeeded (expected at most 1)"
            )
            is_vulnerable = True

        # Signal 3: Different response bodies (not just different IDs)
        unique_hashes = set(body_hashes)
        if len(unique_hashes) > len(results) * 0.3:
            inconsistencies.append(
                f"High response diversity: {len(unique_hashes)} unique bodies from {len(results)} requests"
            )

        # Signal 4: Highly variable response times (some fast, some slow = contention)
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            if avg_time > 0:
                variance = sum((t - avg_time)**2 for t in response_times) / len(response_times)
                if variance > avg_time * 2:
                    inconsistencies.append(
                        f"High timing variance: avg={avg_time:.0f}ms, var={variance:.0f}ms²"
                    )

        # Signal 5: Mix of success + rate limit (429) = possible race before rate limiter kicks in
        if 200 in status_codes and 429 in status_codes:
            inconsistencies.append("Rate limit applied to some but not all requests")
            is_vulnerable = True

        return RaceResult(
            url=url,
            method=method,
            request_count=len(results),
            status_codes=status_codes,
            response_bodies=bodies[:5],  # Keep first 5 for evidence
            body_hashes=body_hashes,
            response_times=response_times,
            duration_ms=duration,
            inconsistencies=inconsistencies,
            is_vulnerable=is_vulnerable,
        )

    def _analyze_double_spend(
        self,
        url: str,
        method: str,
        results: List[HTTPResult],
        duration: float,
    ) -> RaceResult:
        """Analyze double-spend specific signals."""
        result = self._analyze_results(url, method, results, duration)

        # Additional double-spend signals
        success_count = sum(1 for r in results if r.status in (200, 201, 202))
        if success_count >= 2:
            result.inconsistencies.append(
                f"DOUBLE SPEND: {success_count} requests succeeded — "
                f"action that should be atomic was processed multiple times"
            )
            result.is_vulnerable = True

        # Check if responses contain increasing counters or IDs
        ids = []
        for r in results:
            if r.status == 200 or r.status == 201:
                import re
                # Look for order IDs, invoice numbers, etc.
                matches = re.findall(r'(?:order|invoice|transaction|payment|id)[_\s]*[:=]\s*["\']?(\d+)["\']?', r.body, re.I)
                ids.extend(matches)

        if len(ids) > 1 and len(set(ids)) < len(ids):
            result.inconsistencies.append(f"Duplicate IDs found: {ids}")
            result.is_vulnerable = True

        return result

    def _result_to_finding(self, result: RaceResult) -> RaceFinding:
        """Convert a RaceResult to a RaceFinding."""
        evidence = "\n".join(result.inconsistencies[:5])

        if "double spend" in evidence.lower():
            title = f"Race condition — double-spend possible on {urlparse(result.url).path}"
            severity = "critical"
            cvss = 9.0
        elif result.request_count > 0:
            success_count = sum(1 for s in result.status_codes if s in (200, 201, 202))
            if success_count > 1:
                title = f"Race condition — {success_count}/{result.request_count} concurrent requests succeeded on {urlparse(result.url).path}"
                severity = "high"
                cvss = 7.5
            else:
                title = f"Potential race condition — inconsistent responses on {urlparse(result.url).path}"
                severity = "medium"
                cvss = 5.5
        else:
            title = f"Race condition detected on {urlparse(result.url).path}"
            severity = "medium"
            cvss = 5.5

        return RaceFinding(
            type="race-condition",
            severity=severity,
            title=title,
            url=result.url,
            method=result.method,
            evidence=evidence,
            cvss_score=cvss,
        )

    def _guess_method(self, url: str) -> str:
        """Guess the HTTP method based on endpoint name."""
        url_lower = url.lower()
        if any(w in url_lower for w in ["checkout", "purchase", "transfer", "withdraw",
                                          "spend", "redeem", "apply", "use", "claim"]):
            return "POST"
        if any(w in url_lower for w in ["update", "edit", "change", "modify", "settings"]):
            return "PUT"
        if any(w in url_lower for w in ["delete", "remove", "cancel", "refund"]):
            return "DELETE"
        return "POST"

    # ── Utility: Test all endpoints from a URL list ────────

    async def test_from_url_list(
        self,
        urls: List[str],
        methods: Dict[str, str] = None,
    ) -> List[RaceFinding]:
        """
        Test a list of URLs, optionally with specific methods.
        methods = {"https://example.com/api/checkout": "POST", ...}
        """
        findings = []
        for url in urls[:30]:
            method = (methods or {}).get(url, self._guess_method(url))
            result = await self.single_packet_attack(url, method)
            if result.is_vulnerable:
                findings.append(self._result_to_finding(result))

            # Double-spend check for financial endpoints
            if any(p in url.lower() for p in ["checkout", "purchase", "transfer", "withdraw", "spend"]):
                result2 = await self.double_spend_test(url, method)
                if result2.is_vulnerable:
                    findings.append(self._result_to_finding(result2))

            await asyncio.sleep(0.1)

        return findings


# ── CLI ────────────────────────────────────────────────────

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="BountyForge Race Engine")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--url", help="Specific URL to test")
    parser.add_argument("--method", default="POST", help="HTTP method")
    parser.add_argument("--data", help="JSON data for POST body")
    parser.add_argument("--urls-file", help="File with URLs (one per line)")
    parser.add_argument("--count", type=int, default=20, help="Concurrent requests (default: 20)")
    parser.add_argument("--double-spend", action="store_true", help="Run double-spend test")
    parser.add_argument("--toctou", action="store_true", help="Run TOCTOU test")
    parser.add_argument("--output", help="Output JSON file")
    args = parser.parse_args()

    from tools.http_pool import HTTPPool

    pool = HTTPPool(max_connections=50, timeout=15)
    await pool.start()

    engine = RaceEngine(pool)

    try:
        data = json.loads(args.data) if args.data else None
    except json.JSONDecodeError:
        data = {"value": args.data} if args.data else None

    if args.url:
        # Test single URL
        if args.double_spend:
            result = await engine.double_spend_test(args.url, args.method, count=args.count)
        elif args.toctou:
            result = await engine.toctou_test(args.url, method=args.method)
        else:
            result = await engine.single_packet_attack(args.url, args.method, data=data, count=args.count)

        print(f"[*] Result: {result.request_count} requests in {result.duration_ms:.0f}ms")
        print(f"[*] Vulnerable: {result.is_vulnerable}")
        for inc in result.inconsistencies:
            print(f"  - {inc}")

        if result.is_vulnerable:
            finding = engine._result_to_finding(result)
            findings = [finding]
            print(f"\n[*] Finding: [{finding.severity}] {finding.title}")

    elif args.urls_file:
        urls = [l.strip() for l in Path(args.urls_file).read_text().splitlines() if l.strip()]
        findings = await engine.test_from_url_list(urls)
        print(f"\n[*] Findings: {len(findings)}")
        for f in findings:
            print(f"  [{f.severity}] {f.title}")
            print(f"    Evidence: {f.evidence[:200]}")

    else:
        base = args.target if args.target.startswith("http") else f"https://{args.target}"
        urls = [
            f"{base}/api/checkout",
            f"{base}/api/orders",
            f"{base}/api/cart",
            f"{base}/api/transfer",
            f"{base}/api/redeem",
            f"{base}/api/apply",
        ]
        findings = await engine.test_endpoints(urls)
        print(f"\n[*] Findings: {len(findings)}")
        for f in findings:
            print(f"  [{f.severity}] {f.title}")

    if args.output:
        Path(args.output).write_text(json.dumps(
            [f.to_dict() for f in (findings if 'findings' in dir() else [])], indent=2
        ))

    # Persist confirmed findings to the state bus
    if 'findings' in dir() and findings:
        try:
            from tools.bus_writer import save_findings
            save_findings(args.target, [f.to_dict() for f in findings], "race_engine")
        except Exception as e:
            print(f"[!] state bus write failed: {e}")

    await pool.stop()


if __name__ == "__main__":
    asyncio.run(main())
