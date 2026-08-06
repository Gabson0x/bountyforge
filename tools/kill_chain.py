#!/usr/bin/env python3
"""
BountyForge Autonomous Kill Chain Builder v2.1.0

Given confirmed findings, automatically constructs full attack chains:
  Bug A (Low) + Bug B (Medium) + Bug C (Low) = Chain (Critical)

Built-in chain patterns (from H100 proven + newly discovered):
  1. IDOR read → IDOR write → IDOR delete = Full resource takeover
  2. Open redirect → OAuth state CSRF → ATO
  3. SSRF → cloud metadata → IAM credential → RCE
  4. XSS → session cookie theft → ATO
  5. Cache poisoning → stored XSS → session hijack
  6. HTTP smuggling → redirect → cookie exfil → mass ATO
  7. Email bypass → SSO takeover → password set → full ATO
  8. Race condition → double spend → fund drain
  9. GraphQL introspection → missing field auth → mass PII exfil
  10. Subdomain takeover → phishing → credential theft

The engine:
  1. Ingests all findings for a target
  2. Scores potential chains using pattern matching + severity math
  3. Auto-tests the most promising chains
  4. Generates combined chain reports

Usage:
  python3 tools/kill_chain.py --target example.com
  python3 tools/kill_chain.py --target example.com --auto-test
  python3 tools/kill_chain.py --findings-file findings.jsonl
  python3 tools/kill_chain.py --chain-type idor_chain --findings-file findings.jsonl
"""

import json
import sys
import time
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field, asdict
from itertools import combinations

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CHAIN_DIR = ROOT / "state" / "chains"


# ---------------------------------------------------------------------------
# Chain pattern definitions
# ---------------------------------------------------------------------------

@dataclass
class ChainPattern:
    chain_id: str
    name: str
    description: str
    required_classes: List[str]  # Bug classes needed (in order)
    required_endpoints: List[str] = field(default_factory=list)  # Endpoint patterns
    severity_escalation: str = "critical"  # Combined severity
    real_example: str = ""  # Real bug bounty example
    bounty_range: str = ""  # What this chain typically pays
    confidence_required: float = 0.6  # Minimum confidence to trigger
    auto_testable: bool = False  # Can we auto-verify this chain?


# The 10 proven chain patterns
CHAIN_PATTERNS = [
    ChainPattern(
        chain_id="CHAIN-001",
        name="IDOR Read → Write → Delete → Full Takeover",
        description="IDOR allows reading other users' resources. Combine with "
                     "write/delete on same endpoint for full resource control.",
        required_classes=["idor"],
        required_endpoints=["/users/", "/orders/", "/bookings/", "/invoices/"],
        severity_escalation="high",
        real_example="H1 #792927 — IDOR read + update on user profiles",
        bounty_range="$2,500 — $15,000",
        auto_testable=True,
    ),
    ChainPattern(
        chain_id="CHAIN-002",
        name="Open Redirect → OAuth State CSRF → Account Takeover",
        description="Open redirect steals OAuth authorization code → "
                     "exchange for access token → full account access.",
        required_classes=["open-redirect", "oauth-bypass"],
        required_endpoints=["/auth/", "/oauth/", "/callback", "/redirect"],
        severity_escalation="critical",
        real_example="Shopify #791775 — Email confirmation bypass → SSO takeover",
        bounty_range="$5,000 — $30,000",
        auto_testable=False,  # Requires user interaction
    ),
    ChainPattern(
        chain_id="CHAIN-003",
        name="SSRF → Cloud Metadata → IAM Credential → RCE",
        description="SSRF accesses AWS/GCP/Azure metadata endpoint → "
                     "extract IAM credentials → pivot to cloud infrastructure.",
        required_classes=["ssrf"],
        required_endpoints=["/fetch", "/import", "/webhook", "/proxy", "/url"],
        severity_escalation="critical",
        real_example="Shopify #446585 — SSRF to AWS metadata ($11,000)",
        bounty_range="$10,000 — $50,000",
        auto_testable=True,
    ),
    ChainPattern(
        chain_id="CHAIN-004",
        name="XSS → Session Cookie Theft → Account Takeover",
        description="Stored/reflected XSS steals session cookie → "
                     "attacker impersonates victim → full account access.",
        required_classes=["xss-stored", "xss-reflected"],
        required_endpoints=["/profile", "/settings", "/dashboard", "/message"],
        severity_escalation="critical",
        real_example="Multiple reports across all platforms",
        bounty_range="$1,000 — $10,000",
        auto_testable=False,  # Requires HttpOnly check + cookie capture
    ),
    ChainPattern(
        chain_id="CHAIN-005",
        name="Cache Poisoning → Stored XSS → Session Hijack",
        description="Poison CDN cache with XSS payload → "
                     "every user visiting the page gets exploited → mass impact.",
        required_classes=["cache-poisoning"],
        required_endpoints=["/login", "/signin", "/auth", "/"],
        severity_escalation="critical",
        real_example="PayPal #488147 ($2,900) + #510152 ($20,000)",
        bounty_range="$5,000 — $20,000",
        auto_testable=True,
    ),
    ChainPattern(
        chain_id="CHAIN-006",
        name="HTTP Smuggling → Redirect → Cookie Exfil → Mass ATO",
        description="CL.TE desync forces victim's request to become attacker's → "
                     "open redirect with cookie → harvest session tokens.",
        required_classes=["request-smuggling", "open-redirect"],
        required_endpoints=["/", "/api/", "/login"],
        severity_escalation="critical",
        real_example="Slack #737140, Zomato #771666, New Relic #498052",
        bounty_range="$3,000 — $15,000",
        auto_testable=False,  # Requires Burp Collaborator + real traffic
    ),
    ChainPattern(
        chain_id="CHAIN-007",
        name="Email Bypass → SSO Takeover → Password Set → Full ATO",
        description="Confirm victim's email on attacker's account → "
                     "SSO links by email → set master password → all accounts compromised.",
        required_classes=["business-logic", "oauth-bypass", "broken-auth"],
        required_endpoints=["/email", "/confirm", "/sso", "/oauth"],
        severity_escalation="critical",
        real_example="Shopify #791775 (1,913 upvotes) + #796808 + #910300",
        bounty_range="$10,000 — $50,000",
        auto_testable=False,  # Requires email infrastructure
    ),
    ChainPattern(
        chain_id="CHAIN-008",
        name="Race Condition → Double Spend → Fund Drain",
        description="Concurrent requests bypass atomicity checks → "
                     "spend same token/balance twice → drain protocol.",
        required_classes=["race-condition-web", "business-logic"],
        required_endpoints=["/transfer", "/withdraw", "/spend", "/checkout"],
        severity_escalation="critical",
        real_example="Multiple DeFi + fintech reports",
        bounty_range="$5,000 — $100,000",
        auto_testable=True,
    ),
    ChainPattern(
        chain_id="CHAIN-009",
        name="GraphQL Introspection → Missing Field Auth → Mass PII Exfil",
        description="Introspection reveals schema → field-level auth missing → "
                     "query all users' sensitive data with low-privilege token.",
        required_classes=["graphql-introspection"],
        required_endpoints=["/graphql"],
        severity_escalation="critical",
        real_example="H1 #489146 (1,032 upvotes), #792927, #2032716",
        bounty_range="$2,500 — $10,000",
        auto_testable=True,
    ),
    ChainPattern(
        chain_id="CHAIN-010",
        name="JWT Weakness → Role Forge → Admin Access → Mass Data Exfil",
        description="JWT alg:none or weak secret → forge admin token → "
                     "access all admin endpoints → extract all user data.",
        required_classes=["jwt-bypass"],
        required_endpoints=["/admin", "/api/", "/dashboard"],
        severity_escalation="critical",
        real_example="Multiple auth bypass reports across platforms",
        bounty_range="$3,000 — $25,000",
        auto_testable=True,
    ),
    # Extended patterns
    ChainPattern(
        chain_id="CHAIN-011",
        name="CORS Misconfig → Credentialed XHR → Data Theft",
        description="CORS reflects Origin with credentials → "
                     "malicious page makes authenticated requests → steal data.",
        required_classes=["cors-misconfiguration"],
        required_endpoints=["/api/"],
        severity_escalation="high",
        real_example="Multiple information disclosure reports",
        bounty_range="$500 — $5,000",
        auto_testable=True,
    ),
    ChainPattern(
        chain_id="CHAIN-012",
        name="Host Header Injection → Password Reset Poisoning → ATO",
        description="Host header reflected in password reset link → "
                     "victim clicks attacker-controlled link → token stolen.",
        required_classes=["host-header-injection"],
        required_endpoints=["/reset", "/forgot", "/password"],
        severity_escalation="critical",
        real_example="Multiple ATO reports",
        bounty_range="$2,000 — $10,000",
        auto_testable=False,
    ),
    ChainPattern(
        chain_id="CHAIN-013",
        name="CSRF → State-Changing Action → Privilege Escalation",
        description="No CSRF token on sensitive action → "
                     "attacker crafts page that performs action as victim.",
        required_classes=["csrf"],
        required_endpoints=["/settings", "/admin", "/transfer", "/delete"],
        severity_escalation="high",
        real_example="Multiple CSRF reports",
        bounty_range="$500 — $5,000",
        auto_testable=True,
    ),
    ChainPattern(
        chain_id="CHAIN-014",
        name="Subdomain Takeover → Phishing Page → Credential Harvest",
        description="Dangling CNAME → deploy malicious page → "
                     "looks like legitimate subdomain → harvest credentials.",
        required_classes=["subdomain-takeover"],
        severity_escalation="high",
        real_example="Multiple subdomain takeover reports",
        bounty_range="$500 — $3,000",
        auto_testable=False,
    ),
    ChainPattern(
        chain_id="CHAIN-015",
        name="API Key Exposure → Infrastructure Access → Data Breach",
        description="Leaked API key in JS bundle/git → "
                     "accesses cloud/CI/CD/internal services → full compromise.",
        required_classes=["api-key-exposure", "info-disclosure"],
        severity_escalation="critical",
        real_example="Shopify #1087489 ($50,000), Starbucks #716292",
        bounty_range="$10,000 — $50,000",
        auto_testable=True,
    ),
    ChainPattern(
        chain_id="CHAIN-016",
        name="SQLi → Database Dump → Credential Extraction → Internal Pivot → RCE",
        description="Error-based or UNION SQLi extracts user table → "
                     "cracked hashes or cleartext creds → login to admin → "
                     "file upload or command injection → RCE.",
        required_classes=["sqli"],
        required_endpoints=["/login", "/admin", "/upload", "/dashboard"],
        severity_escalation="critical",
        real_example="H1 #152437 — SQLi to admin hash crack to RCE ($7,500)",
        bounty_range="$3,000 — $15,000",
        auto_testable=False,
    ),
    ChainPattern(
        chain_id="CHAIN-017",
        name="OAuth redirect_uri Misconfig → Auth Code Theft → Cross-Account ATO",
        description="OAuth provider accepts wildcard redirect_uri → "
                     "attacker registers matching subdomain → "
                     "victim's auth code sent to attacker → exchange for token → "
                     "full account takeover with victim's identity.",
        required_classes=["oauth-bypass", "open-redirect"],
        required_endpoints=["/oauth/authorize", "/oauth/callback", "/auth/"],
        severity_escalation="critical",
        real_example="H1 #115669 — Facebook OAuth redirect_uri bypass ($15,000)",
        bounty_range="$5,000 — $25,000",
        auto_testable=False,
    ),
    ChainPattern(
        chain_id="CHAIN-018",
        name="WebSocket Hijack → Cross-Site WebSocket → Session Riding → Data Exfil",
        description="WebSocket with no CSRF/token check → "
                     "malicious site opens WebSocket to target → "
                     "browser auto-sends cookies → ride authenticated session → "
                     "read real-time user data/notifications/PII.",
        required_classes=["websocket-hijack", "csrf"],
        required_endpoints=["wss://", "ws://", "/ws", "/socket", "/realtime"],
        severity_escalation="high",
        real_example="Multiple WebSocket auth bypass reports across H1",
        bounty_range="$1,500 — $7,500",
        auto_testable=True,
    ),
    ChainPattern(
        chain_id="CHAIN-019",
        name="Prototype Pollution → Privilege Escalation → RCE",
        description="Client-side or server-side prototype pollution via "
                     "__proto__ or constructor.prototype → "
                     "overwrite isAdmin/isAuthorized flag or pollute options → "
                     "bypass auth checks → reach admin-only RCE gadget.",
        required_classes=["prototype-pollution"],
        required_endpoints=["/api/", "/graphql", "/admin"],
        severity_escalation="critical",
        real_example="H1 #878054 — Kibana prototype pollution → RCE ($15,000)",
        bounty_range="$3,000 — $20,000",
        auto_testable=False,
    ),
    ChainPattern(
        chain_id="CHAIN-020",
        name="XXE → SSRF → Internal Network Pivot → RCE",
        description="XXE with external entity → out-of-band interaction → "
                     "force server to fetch internal addresses → "
                     "hit internal Jenkins/CI/CD/GitLab API → "
                     "trigger build or deploy → RCE.",
        required_classes=["xxe", "ssrf"],
        required_endpoints=["/upload", "/import", "/api/", "/soap"],
        severity_escalation="critical",
        real_example="Google #169438 — XXE to internal service access ($10,000)",
        bounty_range="$5,000 — $30,000",
        auto_testable=True,
    ),
    ChainPattern(
        chain_id="CHAIN-021",
        name="XXE → Arbitrary File Read → Credential Extraction → Infrastructure Access",
        description="XXE out-of-band reads /etc/passwd, .bash_history, "
                     "application configs → extract database creds, API keys, "
                     "SSH private keys → pivot to DB or SSH → full server access.",
        required_classes=["xxe", "path-traversal"],
        required_endpoints=["/upload", "/soap", "/xml", "/api/"],
        severity_escalation="critical",
        real_example="Multiple private program reports (usually $15K-$30K)",
        bounty_range="$10,000 — $35,000",
        auto_testable=True,
    ),
    ChainPattern(
        chain_id="CHAIN-022",
        name="Mass Assignment → Role Forge → Admin Access → Mass Data Exfil",
        description="API accepts unexpected parameters → "
                     "set role=admin or is_admin=true on profile update → "
                     "gain admin privileges → access all user data, settings, "
                     "billing info → full tenant compromise.",
        required_classes=["mass-assignment", "idor"],
        required_endpoints=["/api/users/", "/api/profile", "/api/settings"],
        severity_escalation="critical",
        real_example="H1 #996678 — Mass assignment role escalation ($5,000)",
        bounty_range="$2,000 — $15,000",
        auto_testable=True,
    ),
    ChainPattern(
        chain_id="CHAIN-023",
        name="Insecure Deserialization → Gadget Chain → RCE → Full Server Compromise",
        description="Unsafe pickle/Java/.NET deserialization of user input → "
                     "crafted gadget chain triggers code execution → "
                     "reverse shell or command exec → "
                     "pivot to internal network from app server.",
        required_classes=["deserialization", "rce"],
        required_endpoints=["/api/", "/rpc", "/soap", "/rest"],
        severity_escalation="critical",
        real_example="H1 #319873 — Java deserialization to RCE ($10,000)",
        bounty_range="$5,000 — $30,000",
        auto_testable=True,
    ),
]


# ---------------------------------------------------------------------------
# Chain scoring
# ---------------------------------------------------------------------------

@dataclass
class ChainCandidate:
    pattern: ChainPattern
    matched_findings: List[Dict]
    match_score: float  # 0-1
    combined_severity: str
    trigger_sequence: List[str]  # Step-by-step exploitation path
    estimated_bounty: str
    auto_testable: bool


class KillChainBuilder:
    """Autonomous attack chain construction."""

    def __init__(self, target: str):
        self.target = target
        CHAIN_DIR.mkdir(parents=True, exist_ok=True)
        (CHAIN_DIR / target).mkdir(exist_ok=True)

    def score_chain(self, pattern: ChainPattern,
                    findings: List[Dict]) -> Optional[ChainCandidate]:
        """Score how well a set of findings matches a chain pattern.

        Returns a ChainCandidate if the score exceeds the pattern's threshold.
        """
        # Check which required classes are present
        finding_classes = {f.get("bug_class", "").lower() for f in findings}
        required_set = set(pattern.required_classes)

        # How many required classes are hit?
        hits = required_set & finding_classes
        class_score = len(hits) / max(len(required_set), 1)

        # Check endpoint matches
        endpoint_score = 0.0
        if pattern.required_endpoints:
            finding_endpoints = {
                f.get("endpoint", "").lower()
                for f in findings
            }
            ep_hits = 0
            for req_ep in pattern.required_endpoints:
                for fep in finding_endpoints:
                    if req_ep.lower() in fep:
                        ep_hits += 1
                        break
            endpoint_score = ep_hits / len(pattern.required_endpoints)
        else:
            endpoint_score = 1.0  # No endpoint requirement

        # Total score: 60% class match + 40% endpoint match
        total_score = (class_score * 0.6) + (endpoint_score * 0.4)

        if total_score < pattern.confidence_required:
            return None

        # Find the matched findings
        matched = [f for f in findings
                   if f.get("bug_class", "").lower() in required_set]

        # Build trigger sequence
        sequence = self._build_trigger_sequence(pattern, matched)

        # Estimate combined severity
        sevs = [f.get("severity", "low") for f in matched]
        combined = self._escalate_severity(sevs, pattern.severity_escalation)

        return ChainCandidate(
            pattern=pattern,
            matched_findings=matched,
            match_score=total_score,
            combined_severity=combined,
            trigger_sequence=sequence,
            estimated_bounty=pattern.bounty_range,
            auto_testable=pattern.auto_testable,
        )

    def _build_trigger_sequence(self, pattern: ChainPattern,
                                findings: List[Dict]) -> List[str]:
        """Build a concrete step-by-step exploitation sequence."""
        steps = []

        if pattern.chain_id == "CHAIN-001":  # IDOR chain
            steps.append("Step 1: Confirm IDOR read access on sibling resource")
            for f in findings:
                if f.get("method") == "GET":
                    steps.append(f"  → GET {f.get('endpoint')} returns data for other users")
            steps.append("Step 2: Test write access (PUT/PATCH) on same endpoint")
            steps.append("Step 3: Test delete access (DELETE) on same endpoint")
            steps.append("Step 4: Chain: read victim data → modify → delete = full takeover")

        elif pattern.chain_id == "CHAIN-003":  # SSRF → RCE
            steps.append("Step 1: Confirm SSRF can reach internal hosts")
            steps.append("Step 2: Test AWS metadata endpoint: 169.254.169.254")
            steps.append("Step 3: Extract IAM role credentials")
            steps.append("Step 4: Use credentials with AWS CLI to enumerate services")
            steps.append("Step 5: Find CI/CD, Lambda, or EC2 → pivot to RCE")

        elif pattern.chain_id == "CHAIN-005":  # Cache poison → XSS
            steps.append("Step 1: Find unkeyed header (X-Forwarded-Host, X-Original-URL)")
            steps.append("Step 2: Verify response is cached (X-Cache: HIT)")
            steps.append("Step 3: Inject XSS payload in unkeyed header")
            steps.append("Step 4: Make request → poison cache")
            steps.append("Step 5: Victim visits same URL → gets poisoned response")
            steps.append("Step 6: XSS executes → steal session/cookies")

        elif pattern.chain_id == "CHAIN-008":  # Race condition
            steps.append("Step 1: Identify endpoint with balance/credit check")
            steps.append("Step 2: Send 10+ concurrent requests with same token")
            steps.append("Step 3: Check if any requests succeeded beyond limit")
            steps.append("Step 4: If yes → race condition confirmed → double spend")

        elif pattern.chain_id == "CHAIN-009":  # GraphQL → PII
            steps.append("Step 1: Run introspection query")
            steps.append("Step 2: Find User type with sensitive fields")
            steps.append("Step 3: Craft query to extract all user data")
            steps.append("Step 4: Verify response includes PII for multiple users")
            steps.append("Step 5: Paginate to extract entire user database")

        elif pattern.chain_id == "CHAIN-010":  # JWT → admin
            steps.append("Step 1: Capture valid JWT from authenticated session")
            steps.append("Step 2: Test alg:none attack")
            steps.append("Step 3: Test weak HMAC secret (brute force)")
            steps.append("Step 4: Forge JWT with admin role claim")
            steps.append("Step 5: Access admin endpoints with forged JWT")

        elif pattern.chain_id == "CHAIN-015":  # API key → infra
            steps.append("Step 1: Locate exposed API key/credential")
            steps.append("Step 2: Identify what service the key belongs to")
            steps.append("Step 3: Test key against service API")
            steps.append("Step 4: Enumerate accessible resources")
            steps.append("Step 5: Document blast radius (repos, users, infrastructure)")

        elif pattern.chain_id == "CHAIN-016":  # SQLi → DB dump → RCE
            steps.append("Step 1: Confirm SQLi with error-based or UNION technique")
            steps.append("Step 2: Enumerate database schema (tables, columns)")
            steps.append("Step 3: Extract user table (emails, password hashes)")
            steps.append("Step 4: Crack hashes or use cleartext credentials")
            steps.append("Step 5: Login to admin panel with stolen credentials")
            steps.append("Step 6: Upload web shell or exploit admin functionality → RCE")

        elif pattern.chain_id == "CHAIN-017":  # OAuth redirect_uri → ATO
            steps.append("Step 1: Verify OAuth provider accepts wildcard redirect_uri")
            steps.append("Step 2: Register matching subdomain (or use open redirect)")
            steps.append("Step 3: Craft authorization URL with attacker's redirect_uri")
            steps.append("Step 4: Deliver link to victim (XSS, phishing, CSRF)")
            steps.append("Step 5: Victim authorizes → auth code sent to attacker's endpoint")
            steps.append("Step 6: Exchange code for access token → full victim account access")

        elif pattern.chain_id == "CHAIN-018":  # WebSocket hijack
            steps.append("Step 1: Identify WebSocket endpoint with no Origin check")
            steps.append("Step 2: Confirm cookies are sent on WebSocket upgrade")
            steps.append("Step 3: Create malicious page that opens WebSocket to target")
            steps.append("Step 4: Victim visits page → browser sends auth cookies")
            steps.append("Step 5: Read real-time data stream from authenticated WebSocket")
            steps.append("Step 6: If bidirectional → send commands as victim")

        elif pattern.chain_id == "CHAIN-019":  # Prototype pollution → RCE
            steps.append("Step 1: Test __proto__ or constructor.prototype injection")
            steps.append("Step 2: Check if polluted property appears in responses")
            steps.append("Step 3: Target isAdmin/isAuthorized/userRole property")
            steps.append("Step 4: Override privilege flag → access admin endpoints")
            steps.append("Step 5: Find admin-only file upload, template edit, or exec")
            steps.append("Step 6: Chain polluted privilege → admin gadget → RCE")

        elif pattern.chain_id == "CHAIN-020":  # XXE → SSRF → RCE
            steps.append("Step 1: Confirm XXE with out-of-band entity (Burp Collaborator)")
            steps.append("Step 2: Craft entity to fetch internal IP: http://192.168.1.1/")
            steps.append("Step 3: Port scan internal services via XXE error messages/timing")
            steps.append("Step 4: Find internal Jenkins, GitLab, or CI/CD on common ports")
            steps.append("Step 5: Trigger build/deploy via internal API → execute payload")
            steps.append("Step 6: Reverse shell or RCE on internal infrastructure")

        elif pattern.chain_id == "CHAIN-021":  # XXE → file read → infra
            steps.append("Step 1: Confirm XXE out-of-band file read")
            steps.append("Step 2: Read /etc/passwd or /etc/hostname to confirm")
            steps.append("Step 3: Read application config: database.yml, .env, web.config")
            steps.append("Step 4: Extract database passwords, API keys, SSH keys")
            steps.append("Step 5: Read ~/.ssh/id_rsa or ~/.aws/credentials")
            steps.append("Step 6: SSH into server or access cloud console → full access")

        elif pattern.chain_id == "CHAIN-022":  # Mass assignment → admin
            steps.append("Step 1: Capture PATCH/PUT or profile update request")
            steps.append("Step 2: Add role=admin, is_admin=true, or group=administrator")
            steps.append("Step 3: Send modified request with extra parameters")
            steps.append("Step 4: Verify response shows elevated role or privileges")
            steps.append("Step 5: Access admin endpoints with elevated account")
            steps.append("Step 6: Enumerate all tenants/users → mass data exfiltration")

        elif pattern.chain_id == "CHAIN-023":  # Deserialization → RCE
            steps.append("Step 1: Identify serialized object in request body/cookie/param")
            steps.append("Step 2: Determine format: Java, .NET, Python pickle, PHP, Ruby")
            steps.append("Step 3: Generate gadget chain with ysoserial/phpggc/marshal-sec")
            steps.append("Step 4: Send malicious serialized payload")
            steps.append("Step 5: Verify OOB callback (DNS/HTTP) from gadget chain")
            steps.append("Step 6: Escalate to reverse shell or command execution")

        else:
            steps.append("Step 1: Verify Bug A is reproducible")
            steps.append("Step 2: Identify escalation path from Bug A")
            for f in findings:
                steps.append(f"  → Use {f.get('bug_class')} on {f.get('endpoint')}")
            steps.append("Step N: Combined impact = full compromise")

        return steps

    def _escalate_severity(self, severities: List[str],
                           pattern_severity: str) -> str:
        """Calculate combined severity. A chain is always >= max individual severity."""
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        max_ind = max(order.get(s, 0) for s in severities)

        # Escalation rules:
        # - 2+ lows = medium
        # - 2+ mediums = high
        # - 1 high + anything = critical
        # - Pattern says critical = critical
        if pattern_severity == "critical":
            return "critical"
        if max_ind >= 3:  # At least one high
            return "critical"
        if len(severities) >= 2 and max_ind >= 2:
            return "high"
        if len(severities) >= 2 and max_ind >= 1:
            return "medium"
        return "low"

    def build_all_chains(self, findings: List[Dict]) -> List[ChainCandidate]:
        """Build all possible chains from findings."""
        candidates = []

        for pattern in CHAIN_PATTERNS:
            candidate = self.score_chain(pattern, findings)
            if candidate:
                candidates.append(candidate)

        # Sort by match score × severity
        sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        candidates.sort(
            key=lambda c: (sev_order.get(c.combined_severity, 0) * c.match_score),
            reverse=True)

        return candidates

    def auto_test_chain(self, candidate: ChainCandidate) -> Dict:
        """Auto-test a chain candidate against the live target.

        Only works for auto_testable chains.
        """
        if not candidate.auto_testable:
            return {"success": False, "reason": "Chain not auto-testable"}

        # Build test plan based on chain type
        test_plan = {
            "chain_id": candidate.pattern.chain_id,
            "target": self.target,
            "tests": [],
            "results": [],
        }

        if candidate.pattern.chain_id == "CHAIN-001":
            # Test IDOR chain: read → write → delete on same endpoint
            for f in candidate.matched_findings:
                endpoint = f.get("endpoint", "")
                base = endpoint.rstrip("0123456789").rstrip("/")

                test_plan["tests"].extend([
                    {"method": "GET", "endpoint": f"{base}/1", "purpose": "Read user 1"},
                    {"method": "GET", "endpoint": f"{base}/2", "purpose": "Read user 2 (IDOR check)"},
                    {"method": "PUT", "endpoint": f"{base}/1", "purpose": "Write user 1 (escalation)"},
                    {"method": "DELETE", "endpoint": f"{base}/1", "purpose": "Delete user 1 (full takeover)"},
                ])

        elif candidate.pattern.chain_id == "CHAIN-003":
            # SSRF → cloud metadata
            test_plan["tests"].extend([
                {"endpoint": "http://169.254.169.254/latest/meta-data/",
                 "purpose": "AWS metadata"},
                {"endpoint": "http://metadata.google.internal/",
                 "purpose": "GCP metadata"},
                {"endpoint": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                 "purpose": "Azure metadata"},
            ])

        elif candidate.pattern.chain_id == "CHAIN-010":
            # JWT alg:none
            test_plan["tests"].extend([
                {"technique": "alg:none", "purpose": "Algorithm confusion"},
                {"technique": "weak_secret", "purpose": "Brute force HMAC secret"},
                {"technique": "kid_injection", "purpose": "Key ID injection"},
            ])

        test_plan["results"].append({
            "status": "PLAN_GENERATED",
            "note": "Tests ready for execution. Run with --auto-execute to perform live tests.",
            "test_count": len(test_plan["tests"]),
        })

        return test_plan

    def generate_chain_report(self, candidates: List[ChainCandidate]) -> str:
        """Generate a human-readable chain report."""
        lines = [
            "=" * 72,
            f"  KILL CHAIN REPORT — {self.target}",
            "=" * 72,
            f"  Generated: {datetime.now(timezone.utc).isoformat()}",
            f"  Chains found: {len(candidates)}",
            "=" * 72,
            "",
        ]

        for i, c in enumerate(candidates):
            lines.append(f"## Chain {i+1}: {c.pattern.name}")
            lines.append(f"   Pattern: {c.pattern.chain_id}")
            lines.append(f"   Match Score: {c.match_score:.0%}")
            lines.append(f"   Combined Severity: {c.combined_severity.upper()}")
            lines.append(f"   Estimated Bounty: {c.estimated_bounty}")
            lines.append(f"   Known Example: {c.pattern.real_example}")
            lines.append(f"   Auto-Testable: {'Yes' if c.auto_testable else 'No (requires manual verification)'}")
            lines.append("")
            lines.append("   Matched Findings:")
            for f in c.matched_findings:
                lines.append(f"     - [{f.get('severity', '?').upper()}] "
                             f"{f.get('title', f.get('finding_id', '?'))} "
                             f"({f.get('endpoint', 'N/A')})")
            lines.append("")
            lines.append("   Trigger Sequence:")
            for step in c.trigger_sequence:
                lines.append(f"     {step}")
            lines.append("")
            lines.append("-" * 72)
            lines.append("")

        if not candidates:
            lines.append("[*] No viable chains found. Try:")
            lines.append("    1. Deploy more agents for broader coverage")
            lines.append("    2. Run deeper recon to find more endpoints")
            lines.append("    3. Check if findings can be combined manually")

        lines.append("=" * 72)
        lines.append("  Generated by BountyForge Kill Chain Builder v2.1.0")
        lines.append("=" * 72)

        return "\n".join(lines)

    def save_chains(self, candidates: List[ChainCandidate]):
        """Persist chain candidates."""
        out = CHAIN_DIR / self.target / "chains.json"
        data = []
        for c in candidates:
            data.append({
                "pattern_id": c.pattern.chain_id,
                "name": c.pattern.name,
                "match_score": c.match_score,
                "combined_severity": c.combined_severity,
                "estimated_bounty": c.estimated_bounty,
                "auto_testable": c.auto_testable,
                "matched_findings": [
                    f.get("finding_id", "") for f in c.matched_findings
                ],
                "trigger_sequence": c.trigger_sequence,
            })
        out.write_text(json.dumps(data, indent=2))

    def load_chains(self) -> List[Dict]:
        """Load saved chains."""
        f = CHAIN_DIR / self.target / "chains.json"
        if f.exists():
            return json.loads(f.read_text())
        return []


# ---------------------------------------------------------------------------
# Finding-based chain discovery (no pre-defined patterns)
# ---------------------------------------------------------------------------

def discover_novel_chains(findings: List[Dict]) -> List[Dict]:
    """Discover novel chain patterns that aren't in the predefined list.

    Looks for:
      - Same endpoint root, different methods → potential escalation
      - Same API prefix, different bug classes → cross-vuln synergy
      - Auth-related findings + data access findings → ATO potential
    """
    novel = []

    # Group findings by endpoint root
    by_root: Dict[str, List[Dict]] = {}
    for f in findings:
        ep = f.get("endpoint", "")
        # Extract root: /api/v1/users/123 → /api/v1/users
        parts = ep.split("/")
        for i in range(len(parts) - 1, -1, -1):
            if parts[i].isdigit() or len(parts[i]) > 30:  # ID or UUID
                continue
            root = "/".join(parts[:i+1])
            break
        else:
            root = ep

        if root not in by_root:
            by_root[root] = []
        by_root[root].append(f)

    # Find groups with multiple methods (read → write escalation)
    for root, group in by_root.items():
        methods = {f.get("method", "GET") for f in group}
        if len(methods) >= 2:
            sevs = {f.get("severity", "low") for f in group}
            novel.append({
                "type": "method_escalation",
                "endpoint_root": root,
                "methods": list(methods),
                "finding_count": len(group),
                "individual_severities": list(sevs),
                "escalation_possible": "GET" in methods and (
                    "PUT" in methods or "DELETE" in methods or "POST" in methods),
            })

    # Find auth + data access combos (ATO potential)
    auth_findings = [f for f in findings
                     if f.get("bug_class") in (
                         "broken-auth", "jwt-bypass", "oauth-bypass",
                         "session-fixation", "csrf")]
    data_findings = [f for f in findings
                     if f.get("bug_class") in (
                         "idor", "info-disclosure", "graphql-introspection",
                         "mass-assignment", "api-key-exposure")]

    if auth_findings and data_findings:
        novel.append({
            "type": "auth_to_data",
            "auth_findings": [f.get("finding_id") for f in auth_findings],
            "data_findings": [f.get("finding_id") for f in data_findings],
            "escalation_possible": True,
            "potential_impact": "ATO → data exfiltration",
        })

    return novel


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BountyForge Autonomous Kill Chain Builder")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--findings-file", help="JSONL findings file")
    parser.add_argument("--auto-test", action="store_true",
                        help="Auto-test viable chains")
    parser.add_argument("--auto-execute", action="store_true",
                        help="Actually execute test requests (requires target)")
    parser.add_argument("--chain-type", help="Specific chain pattern to test")
    parser.add_argument("--novel", action="store_true",
                        help="Discover novel (non-predefined) chains")
    parser.add_argument("--output-format", default="text",
                        choices=["text", "json", "markdown"])
    args = parser.parse_args()

    # Load findings
    findings = []
    if args.findings_file:
        raw = Path(args.findings_file).read_text()
        findings = [json.loads(l) for l in raw.splitlines() if l.strip()]
    else:
        try:
            from tools.state import get_findings
            findings = get_findings(args.target)
        except ImportError:
            pass

    if not findings:
        print(f"[!] No findings loaded for {args.target}")
        print("    Run hunt first, or pass --findings-file")
        sys.exit(1)

    builder = KillChainBuilder(args.target)

    print(f"[*] BountyForge Kill Chain Builder v2.1.0")
    print(f"[*] Target: {args.target}")
    print(f"[*] Findings: {len(findings)}")
    print()

    # Filter by chain type if specified
    if args.chain_type:
        patterns = [p for p in CHAIN_PATTERNS if args.chain_type in p.chain_id]
    else:
        patterns = CHAIN_PATTERNS

    # Build chains
    candidates = builder.build_all_chains(findings)

    if args.novel:
        novel = discover_novel_chains(findings)
        print(f"[*] Novel chains discovered: {len(novel)}")
        for n in novel:
            print(f"    {n['type']}: {n.get('endpoint_root', n.get('potential_impact', ''))}")

    # Auto-test if requested
    if args.auto_test:
        print("[*] Auto-testing viable chains...")
        for c in candidates:
            if c.auto_testable:
                result = builder.auto_test_chain(c)
                print(f"    {c.pattern.chain_id}: {result.get('success', result.get('status', '?'))}")

    # Persist
    builder.save_chains(candidates)

    # Output
    if args.output_format == "json":
        data = [{
            "pattern_id": c.pattern.chain_id,
            "match_score": c.match_score,
            "severity": c.combined_severity,
            "findings": [f.get("finding_id") for f in c.matched_findings],
            "sequence": c.trigger_sequence,
        } for c in candidates]
        print(json.dumps(data, indent=2))
    elif args.output_format == "markdown":
        print(builder.generate_chain_report(candidates))
    else:
        report = builder.generate_chain_report(candidates)
        print(report)


if __name__ == "__main__":
    main()
