#!/usr/bin/env python3
"""
Agent Isolation Checker — verifies each BountyForge agent operates within
its defined boundaries. Prevents cross-contamination, scope creep, and
false findings from agents operating outside their domain.

Integrated from:
- SIS-MD Security Intelligence SkillMD (passive-only boundary enforcement)
- Bug Bounty Intelligence MCP (scope-aware filtering lesson from Slither benchmark)
"""

import json
import hashlib
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class PermissionLevel(Enum):
    PASSIVE_ONLY = "passive_only"
    READ_ONLY_PROBING = "read_only_probing"
    ACTIVE_TESTING = "active_testing"
    DESTRUCTIVE_TESTING = "destructive_testing"


class ViolationSeverity(Enum):
    CRITICAL = "critical"  # Kill finding immediately
    HIGH = "high"  # Quarantine, needs review
    MEDIUM = "medium"  # Flag for manual review
    LOW = "low"  # Note but accept


@dataclass
class AgentDomain:
    """Defines what an agent owns, can query, and must never touch."""
    agent_name: str
    owns: list[str]  # Bug classes this agent is authoritative for
    queries: list[str]  # Bug classes this agent can investigate but not report
    never_touches: list[str]  # Bug classes this agent MUST NOT touch
    permission_level: PermissionLevel = PermissionLevel.ACTIVE_TESTING
    requires_auth: bool = True  # Whether agent needs explicit auth to operate


@dataclass
class IsolationViolation:
    agent_name: str
    check_type: str  # domain, scope, execution, data, context
    severity: ViolationSeverity
    description: str
    evidence: str
    recommendation: str


@dataclass
class IsolationReport:
    agent_name: str
    passed: bool
    violations: list[IsolationViolation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# Agent domain registry — mirrors shared-rules.md Agent Directory
AGENT_DOMAINS: dict[str, AgentDomain] = {
    "recon-agent": AgentDomain(
        agent_name="recon-agent",
        owns=["subdomain-enum", "exposed-services", "cloud-misconfig", "technology-fingerprint"],
        queries=["credential-leak", "infrastructure-misconfig"],
        never_touches=["injection", "xss", "ssrf", "auth-bypass", "smart-contract", "economic-attack"],
        permission_level=PermissionLevel.PASSIVE_ONLY,
    ),
    "web-api-agent": AgentDomain(
        agent_name="web-api-agent",
        owns=["injection", "xss", "ssrf", "auth-bypass", "csrf", "ssti", "xxe", "path-traversal",
              "deserialization", "prototype-pollution", "response-splitting", "open-redirect"],
        queries=["idor", "rate-limit", "waf-bypass", "cache-poisoning"],
        never_touches=["smart-contract", "economic-attack", "crypto-math"],
        permission_level=PermissionLevel.ACTIVE_TESTING,
    ),
    "access-control-agent": AgentDomain(
        agent_name="access-control-agent",
        owns=["idor", "privilege-escalation", "role-bypass", "sso-bypass", "authz-bypass",
              "confused-deputy", "proxy-admin", "init-hijack"],
        queries=["auth-bypass", "session-management"],
        never_touches=["injection", "xss", "smart-contract", "economic-attack"],
        permission_level=PermissionLevel.ACTIVE_TESTING,
    ),
    "business-logic-agent": AgentDomain(
        agent_name="business-logic-agent",
        owns=["state-machine", "payment-logic", "workflow-abuse", "limit-bypass",
              "account-abuse", "coupon-abuse", "referral-abuse"],
        queries=["race-condition", "idor"],
        never_touches=["injection", "xss", "crypto-math", "smart-contract"],
        permission_level=PermissionLevel.ACTIVE_TESTING,
    ),
    "crypto-math-agent": AgentDomain(
        agent_name="crypto-math-agent",
        owns=["overflow", "precision-loss", "signature-replay", "eip-712", "nonce-issues",
              "rounding-error", "divide-before-multiply"],
        queries=["reentrancy", "access-control"],
        never_touches=["injection", "xss", "ssrf", "web-auth"],
        permission_level=PermissionLevel.READ_ONLY_PROBING,
    ),
    "race-condition-agent": AgentDomain(
        agent_name="race-condition-agent",
        owns=["toctou", "front-running", "sandwich", "concurrency", "rotation-window"],
        queries=["business-logic", "payment-logic"],
        never_touches=["injection", "xss", "crypto-math"],
        permission_level=PermissionLevel.ACTIVE_TESTING,
    ),
    "economic-security-agent": AgentDomain(
        agent_name="economic-security-agent",
        owns=["flash-loan", "oracle-manipulation", "inflation-attack", "tokenomics",
              "liquidation", "collateral", "interest-rate"],
        queries=["governance", "access-control"],
        never_touches=["injection", "xss", "ssrf", "web-auth"],
        permission_level=PermissionLevel.READ_ONLY_PROBING,
    ),
    "credential-leak-agent": AgentDomain(
        agent_name="credential-leak-agent",
        owns=["github-token", "env-secret", "build-log-secret", "js-bundle-secret",
              "cloud-credential", "api-key-exposure"],
        queries=["infrastructure-misconfig"],
        never_touches=["injection", "xss", "active-exploitation"],
        permission_level=PermissionLevel.PASSIVE_ONLY,
    ),
    "graphql-agent": AgentDomain(
        agent_name="graphql-agent",
        owns=["graphql-introspection", "graphql-batching", "graphql-auth", "graphql-injection"],
        queries=["idor", "auth-bypass"],
        never_touches=["smart-contract", "economic-attack", "rest-injection"],
        permission_level=PermissionLevel.ACTIVE_TESTING,
    ),
    "supply-chain-agent": AgentDomain(
        agent_name="supply-chain-agent",
        owns=["dependency-squatting", "cicd-poisoning", "unpinned-action", "malicious-package"],
        queries=["credential-leak", "infrastructure-misconfig"],
        never_touches=["injection", "xss", "smart-contract"],
        permission_level=PermissionLevel.PASSIVE_ONLY,
    ),
    "http-smuggling-agent": AgentDomain(
        agent_name="http-smuggling-agent",
        owns=["cl-te-desync", "te-cl-desync", "session-hijack", "request-smuggling"],
        queries=["cache-poisoning", "waf-bypass"],
        never_touches=["injection", "xss", "smart-contract"],
        permission_level=PermissionLevel.ACTIVE_TESTING,
    ),
    "cache-poisoning-agent": AgentDomain(
        agent_name="cache-poisoning-agent",
        owns=["unkeyed-header", "csp-bypass", "cache-deception", "web-cache-poisoning"],
        queries=["http-smuggling", "xss"],
        never_touches=["smart-contract", "economic-attack"],
        permission_level=PermissionLevel.ACTIVE_TESTING,
    ),
    "waf-bypass-agent": AgentDomain(
        agent_name="waf-bypass-agent",
        owns=["waf-detection", "waf-bypass", "filter-evasion", "encoding-bypass"],
        queries=["injection", "xss", "ssrf"],
        never_touches=["smart-contract", "economic-attack"],
        permission_level=PermissionLevel.ACTIVE_TESTING,
    ),
    "mobile-client-agent": AgentDomain(
        agent_name="mobile-client-agent",
        owns=["apk-analysis", "ipa-analysis", "electron-app", "deep-link", "mobile-api"],
        queries=["credential-leak", "auth-bypass", "cert-pinning"],
        never_touches=["smart-contract", "server-side-injection"],
        permission_level=PermissionLevel.READ_ONLY_PROBING,
    ),
    "smart-contract-agent": AgentDomain(
        agent_name="smart-contract-agent",
        owns=["reentrancy", "overflow", "access-control", "storage-collision", "delegatecall",
              "upgradeable-proxy", "signature-validation", "flash-loan-defense"],
        queries=["economic-attack", "oracle-manipulation"],
        never_touches=["web-injection", "xss", "csrf", "ssrf"],
        permission_level=PermissionLevel.READ_ONLY_PROBING,
    ),
}

# Patterns that indicate scope violations
SCOPE_VIOLATION_PATTERNS = [
    (r"(?:lib|interfaces|mocks|test|node_modules)/", "Testing excluded dependency directory"),
    (r"(?:\.t\.sol|Test\.sol|Mock\.sol|\.spec\.|\.test\.)", "Testing test/mock file"),
    (r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0)", "Testing localhost (not target infrastructure)"),
]

# Patterns that indicate cross-contamination
CONTAMINATION_PATTERNS = [
    (r"(?:as reported by|agent \w+ found|from \w+-agent)", "Cross-agent finding reference without handoff signal"),
    (r"(?:same vulnerability as|copied from|duplicate of)", "Potential finding copy without verification"),
]


class AgentIsolationChecker:
    """
    Verifies agent findings stay within defined boundaries.

    Usage:
        checker = AgentIsolationChecker(target="example.com")
        report = checker.check_finding(
            agent_name="web-api-agent",
            finding={"class": "reentrancy", "endpoint": "..."}
        )
        if not report.passed:
            for v in report.violations:
                print(f"{v.severity.value}: {v.description}")
    """

    def __init__(self, target: str = "", scope_file: Optional[str] = None):
        self.target = target
        self.scope_domains: list[str] = []
        self.scope_exclusions: list[str] = []
        if scope_file:
            self._load_scope(scope_file)
        self.state_dir = Path("state/isolation")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.reports: list[IsolationReport] = []

    def _load_scope(self, scope_file: str) -> None:
        """Load program scope from file."""
        path = Path(scope_file)
        if path.exists():
            data = json.loads(path.read_text())
            self.scope_domains = data.get("in_scope", [])
            self.scope_exclusions = data.get("out_of_scope", [])

    def check_domain(self, agent_name: str, finding: dict) -> list[IsolationViolation]:
        """Check if finding is in the agent's owned domain."""
        violations = []
        domain = AGENT_DOMAINS.get(agent_name)
        if not domain:
            return [IsolationViolation(
                agent_name=agent_name,
                check_type="domain",
                severity=ViolationSeverity.CRITICAL,
                description=f"Unknown agent: {agent_name}",
                evidence=f"Agent name '{agent_name}' not in AGENT_DOMAINS registry",
                recommendation="Register agent domain or fix agent name",
            )]

        bug_class = finding.get("class", finding.get("type", finding.get("vulnerability_type", "")))

        # Check if this bug class is in never_touches
        for forbidden in domain.never_touches:
            if self._class_matches(bug_class, forbidden):
                violations.append(IsolationViolation(
                    agent_name=agent_name,
                    check_type="domain",
                    severity=ViolationSeverity.CRITICAL,
                    description=f"Agent '{agent_name}' reported '{bug_class}' which is in its never_touches list",
                    evidence=f"Finding class '{bug_class}' matches forbidden domain '{forbidden}'",
                    recommendation=f"Kill finding. If legitimate, signal correct agent via AgentBus handoff.",
                ))
                return violations

        # Check if bug class is in owns
        in_domain = False
        for owned in domain.owns:
            if self._class_matches(bug_class, owned):
                in_domain = True
                break

        # Check if bug class is in queries (allowed to investigate but not report)
        if not in_domain:
            for queryable in domain.queries:
                if self._class_matches(bug_class, queryable):
                    violations.append(IsolationViolation(
                        agent_name=agent_name,
                        check_type="domain",
                        severity=ViolationSeverity.MEDIUM,
                        description=f"Agent '{agent_name}' reported '{bug_class}' which is in queries (not owns)",
                        evidence=f"Finding class '{bug_class}' is queryable but not owned by '{agent_name}'",
                        recommendation="Hand off to the owning agent via AgentBus before reporting.",
                    ))
                    return violations

        if not in_domain and not any(
            self._class_matches(bug_class, q) for q in domain.queries
        ):
            violations.append(IsolationViolation(
                agent_name=agent_name,
                check_type="domain",
                severity=ViolationSeverity.HIGH,
                description=f"Agent '{agent_name}' reported '{bug_class}' outside its domain",
                evidence=f"Finding class '{bug_class}' not in owns or queries for '{agent_name}'",
                recommendation="Quarantine finding. Check if another agent should own this.",
            ))

        return violations

    def check_scope(self, agent_name: str, finding: dict) -> list[IsolationViolation]:
        """Check if finding is in program scope."""
        violations = []
        endpoint = finding.get("endpoint", finding.get("location", finding.get("target", "")))

        # Check for excluded paths
        for pattern, reason in SCOPE_VIOLATION_PATTERNS:
            if re.search(pattern, str(endpoint), re.IGNORECASE):
                violations.append(IsolationViolation(
                    agent_name=agent_name,
                    check_type="scope",
                    severity=ViolationSeverity.CRITICAL,
                    description=f"Finding in excluded path: {reason}",
                    evidence=f"Endpoint '{endpoint}' matches exclusion pattern '{pattern}'",
                    recommendation="Kill finding immediately. Excluded from scope.",
                ))
                return violations

        # Check against explicit scope if loaded
        if self.scope_domains:
            in_scope = any(
                d in str(endpoint) for d in self.scope_domains
            )
            if not in_scope:
                violations.append(IsolationViolation(
                    agent_name=agent_name,
                    check_type="scope",
                    severity=ViolationSeverity.CRITICAL,
                    description=f"Finding outside program scope",
                    evidence=f"Endpoint '{endpoint}' not in scope domains: {self.scope_domains}",
                    recommendation="Kill finding. Out of scope.",
                ))

        return violations

    def check_execution(self, agent_name: str, finding: dict) -> list[IsolationViolation]:
        """Check if agent stayed within its permission level."""
        violations = []
        domain = AGENT_DOMAINS.get(agent_name)
        if not domain:
            return violations

        method = finding.get("method", finding.get("http_method", "GET"))
        has_payload = bool(finding.get("payload", finding.get("attack_payload", "")))
        has_active_exploit = finding.get("exploited", finding.get("confirmed_exploit", False))

        if domain.permission_level == PermissionLevel.PASSIVE_ONLY:
            if has_payload or has_active_exploit:
                violations.append(IsolationViolation(
                    agent_name=agent_name,
                    check_type="execution",
                    severity=ViolationSeverity.CRITICAL,
                    description=f"Passive-only agent '{agent_name}' performed active exploitation",
                    evidence=f"Finding contains attack payload or exploitation confirmation",
                    recommendation="Kill finding. Passive-only agents must not send active probes.",
                ))
            if method not in ("GET", "HEAD", "OPTIONS"):
                violations.append(IsolationViolation(
                    agent_name=agent_name,
                    check_type="execution",
                    severity=ViolationSeverity.HIGH,
                    description=f"Passive-only agent used non-read HTTP method: {method}",
                    evidence=f"HTTP method '{method}' exceeds passive-only permission",
                    recommendation="Quarantine finding. Passive agents may only use GET/HEAD/OPTIONS.",
                ))

        if domain.permission_level == PermissionLevel.READ_ONLY_PROBING:
            if has_active_exploit:
                violations.append(IsolationViolation(
                    agent_name=agent_name,
                    check_type="execution",
                    severity=ViolationSeverity.HIGH,
                    description=f"Read-only agent '{agent_name}' confirmed exploitation",
                    evidence="Finding marked as exploited/confirmed",
                    recommendation="Quarantine finding. Read-only agents should not confirm exploitation.",
                ))

        return violations

    def check_data_integrity(self, agent_name: str, finding: dict) -> list[IsolationViolation]:
        """Check for cross-contamination and data integrity issues."""
        violations = []
        finding_id = finding.get("id", "")

        # Check for agent prefix in finding ID
        if finding_id and not finding_id.startswith(agent_name.replace("-agent", "")):
            violations.append(IsolationViolation(
                agent_name=agent_name,
                check_type="data",
                severity=ViolationSeverity.LOW,
                description=f"Finding ID '{finding_id}' missing agent prefix",
                evidence=f"ID should start with '{agent_name.replace('-agent', '')}'",
                recommendation="Add agent prefix for traceability.",
            ))

        # Check for cross-contamination patterns in description
        description = finding.get("description", finding.get("summary", ""))
        for pattern, reason in CONTAMINATION_PATTERNS:
            if re.search(pattern, str(description), re.IGNORECASE):
                violations.append(IsolationViolation(
                    agent_name=agent_name,
                    check_type="data",
                    severity=ViolationSeverity.MEDIUM,
                    description=f"Potential cross-contamination: {reason}",
                    evidence=f"Pattern '{pattern}' found in finding description",
                    recommendation="Verify this finding was independently discovered.",
                ))

        return violations

    def check_context_safety(self, agent_name: str, finding: dict) -> list[IsolationViolation]:
        """Check for prompt injection and context safety issues."""
        violations = []
        description = finding.get("description", finding.get("summary", ""))

        # Check for prompt injection patterns in finding data
        injection_patterns = [
            (r"(?:ignore|forget|disregard)\s+(?:all |previous |above )?(?:instructions|rules|constraints)", "Potential prompt injection in finding"),
            (r"(?:you are now|act as|pretend to be|roleplay as)", "Role-switching prompt in finding data"),
            (r"\[SYSTEM\].*\[/SYSTEM\]", "System prompt injection attempt"),
        ]
        for pattern, reason in injection_patterns:
            if re.search(pattern, str(description), re.IGNORECASE):
                violations.append(IsolationViolation(
                    agent_name=agent_name,
                    check_type="context",
                    severity=ViolationSeverity.CRITICAL,
                    description=reason,
                    evidence=f"Injection pattern found in agent output",
                    recommendation="Kill finding. Sanitize agent input and re-run.",
                ))

        return violations

    def _class_matches(self, bug_class: str, domain_class: str) -> bool:
        """Fuzzy match a bug class against a domain class."""
        bug_lower = bug_class.lower().replace("_", "-").replace(" ", "-")
        domain_lower = domain_class.lower().replace("_", "-").replace(" ", "-")
        return bug_lower == domain_lower or domain_lower in bug_lower or bug_lower in domain_lower

    def check_finding(self, agent_name: str, finding: dict) -> IsolationReport:
        """Run all isolation checks on a single finding."""
        all_violations = []
        all_violations.extend(self.check_domain(agent_name, finding))
        all_violations.extend(self.check_scope(agent_name, finding))
        all_violations.extend(self.check_execution(agent_name, finding))
        all_violations.extend(self.check_data_integrity(agent_name, finding))
        all_violations.extend(self.check_context_safety(agent_name, finding))

        criticals = [v for v in all_violations if v.severity == ViolationSeverity.CRITICAL]
        warnings = [v.description for v in all_violations if v.severity in (ViolationSeverity.LOW,)]

        report = IsolationReport(
            agent_name=agent_name,
            passed=len(criticals) == 0,
            violations=all_violations,
            warnings=warnings,
        )
        self.reports.append(report)
        return report

    def check_all_findings(self, findings_by_agent: dict[str, list[dict]]) -> dict[str, list[IsolationReport]]:
        """Run isolation checks on all findings from all agents."""
        results = {}
        for agent_name, findings in findings_by_agent.items():
            results[agent_name] = []
            for finding in findings:
                report = self.check_finding(agent_name, finding)
                results[agent_name].append(report)
        return results

    def summary(self) -> dict:
        """Generate a summary of all isolation checks."""
        total = sum(len(r.violations) for r in self.reports)
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in self.reports:
            for v in r.violations:
                by_severity[v.severity.value] += 1

        return {
            "total_findings_checked": len(self.reports),
            "passed": sum(1 for r in self.reports if r.passed),
            "failed": sum(1 for r in self.reports if not r.passed),
            "total_violations": total,
            "by_severity": by_severity,
            "agents_checked": list(set(r.agent_name for r in self.reports)),
        }

    def persist(self) -> str:
        """Persist isolation reports to state directory."""
        report_path = self.state_dir / f"isolation-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json"
        data = {
            "target": self.target,
            "summary": self.summary(),
            "reports": [
                {
                    "agent_name": r.agent_name,
                    "passed": r.passed,
                    "violations": [
                        {
                            "check_type": v.check_type,
                            "severity": v.severity.value,
                            "description": v.description,
                            "recommendation": v.recommendation,
                        }
                        for v in r.violations
                    ],
                    "warnings": r.warnings,
                    "checked_at": r.checked_at,
                }
                for r in self.reports
            ],
        }
        report_path.write_text(json.dumps(data, indent=2))
        return str(report_path)


# CLI entry point
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 tools/agent_isolation.py <findings.json> [--target T] [--scope scope.json]")
        print("       python3 tools/agent_isolation.py --list-agents")
        sys.exit(1)

    if sys.argv[1] == "--list-agents":
        for name, domain in AGENT_DOMAINS.items():
            print(f"\n{name}:")
            print(f"  Owns: {', '.join(domain.owns)}")
            print(f"  Queries: {', '.join(domain.queries)}")
            print(f"  Never touches: {', '.join(domain.never_touches)}")
            print(f"  Permission: {domain.permission_level.value}")
        sys.exit(0)

    target = ""
    scope_file = None
    args = sys.argv[1:]
    findings_file = args[0]

    for i, arg in enumerate(args):
        if arg == "--target" and i + 1 < len(args):
            target = args[i + 1]
        elif arg == "--scope" and i + 1 < len(args):
            scope_file = args[i + 1]

    findings_path = Path(findings_file)
    if not findings_path.exists():
        print(f"Error: {findings_file} not found")
        sys.exit(1)

    data = json.loads(findings_path.read_text())

    # Support two formats: {"agent_name": [findings]} or {"findings": [{"agent": "name", ...}]}
    if isinstance(data, dict) and "findings" in data:
        by_agent: dict[str, list[dict]] = {}
        for f in data["findings"]:
            agent = f.get("agent", f.get("agent_name", "unknown"))
            by_agent.setdefault(agent, []).append(f)
    else:
        by_agent = data

    checker = AgentIsolationChecker(target=target, scope_file=scope_file)
    results = checker.check_all_findings(by_agent)

    # Print summary
    summary = checker.summary()
    print(f"\n=== Agent Isolation Report ===")
    print(f"Target: {target or '(not specified)'}")
    print(f"Findings checked: {summary['total_findings_checked']}")
    print(f"Passed: {summary['passed']} | Failed: {summary['failed']}")
    print(f"Violations: {summary['total_violations']}")
    if summary['total_violations'] > 0:
        print(f"  Critical: {summary['by_severity']['critical']}")
        print(f"  High: {summary['by_severity']['high']}")
        print(f"  Medium: {summary['by_severity']['medium']}")
        print(f"  Low: {summary['by_severity']['low']}")

    # Print failed findings
    for agent_name, reports in results.items():
        for report in reports:
            if not report.passed:
                print(f"\n--- FAILED: {agent_name} ---")
                for v in report.violations:
                    print(f"  [{v.severity.value.upper()}] {v.check_type}: {v.description}")
                    print(f"    Recommendation: {v.recommendation}")

    # Persist
    path = checker.persist()
    print(f"\nFull report: {path}")
