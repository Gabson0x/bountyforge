#!/usr/bin/env python3
"""
BountyForge Program-Fit Gate v3.0.0

The discipline: don't bury a report in noise. A valid finding that doesn't match
program scope is still true — it gets logged to the ledger but silenced in the
report. This gate checks every surviving finding against program rules before
it reaches the output.

Checks:
  - Scope match: is the asset in scope for this program?
  - Severity threshold: does the program pay for this severity level?
  - Bug class acceptance: does the program accept this bug class?
  - Duplication: has this exact finding already been found in this session?
  - Bounty alignment: does the finding type match what this program pays for?

Usage:
  python3 tools/program_fit.py --target example.com --program h1:security
  python3 tools/program_fit.py --target example.com --check-scope
  python3 tools/program_fit.py --finding-file findings.jsonl --program bugcrowd:myprogram
  python3 tools/program_fit.py --target example.com --gate-all
"""

import json
import sys
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PROGRAM_FIT_DIR = ROOT / "state" / "program_fit"

# ---------------------------------------------------------------------------
# Program definitions
# ---------------------------------------------------------------------------

class Platform(str, Enum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    IMMUNEFI = "immunefi"
    YESWEHACK = "yeswehack"
    GENERIC = "generic"


class EngagementContext(str, Enum):
    BUG_BOUNTY_PLATFORM = "bug_bounty_platform"       # Platform-based (H1, Bugcrowd, Immunefi)
    DIRECT_VENDOR_DISCLOSURE = "direct_vendor_disclosure" # Independent research / advisory
    INTERNAL_RED_TEAM = "internal_red_team"           # Corporate network / codebase pentest


class FitResult(str, Enum):
    INCLUDE = "include"         # Fits program — include in report
    EXCLUDE = "exclude"         # Out of scope or not accepted — log only
    NEEDS_REVIEW = "needs_review"  # Uncertain — human should check
    DUPLICATE = "duplicate"     # Already found in this session
    OUT_OF_SEVERITY = "out_of_severity"  # Below program's payout threshold


# ---------------------------------------------------------------------------
# Program scope models
# ---------------------------------------------------------------------------

@dataclass
class ProgramScope:
    program_id: str
    platform: Platform
    name: str = ""
    in_scope_domains: List[str] = field(default_factory=list)
    in_scope_wildcards: List[str] = field(default_factory=list)  # *.example.com
    out_of_scope_domains: List[str] = field(default_factory=list)
    in_scope_assets: List[str] = field(default_factory=list)  # Specific URLs/APIs
    out_of_scope_assets: List[str] = field(default_factory=list)
    accepted_bug_classes: List[str] = field(default_factory=list)
    excluded_bug_classes: List[str] = field(default_factory=list)
    min_severity: str = "low"  # minimum severity they pay for
    max_severity: str = "critical"
    bounty_range: str = ""  # e.g. "$500 - $50,000"
    platform_specific_rules: Dict = field(default_factory=dict)
    requires_poc: bool = True
    requires_cvss: bool = False
    application_type: str = ""  # web, mobile, api, smart_contract, all

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["platform"] = self.platform.value
        return d


# Known program rules per platform
PLATFORM_DEFAULTS = {
    Platform.IMMUNEFI: {
        "excluded_bug_classes": [
            "missing-best-practices", "centralization-risk",
            "gas-optimization", "linter-warning", "missing-natspec",
            "logout-csrf", "self-xss", "clickjacking-standalone",
            "missing-rate-limiting", "weak-captcha",
        ],
        "min_severity": "medium",
        "accepted_bug_classes": [
            "reentrancy", "access-control-bypass", "integer-overflow",
            "precision-loss", "oracle-manipulation", "flash-loan-attack",
            "signature-replay", "race-condition-sc", "accounting-desync",
            "incomplete-path", "off-by-one", "erc4626-vault-inflation",
            "slippage-manipulation", "unauthorized-upgrade",
            "storage-collision", "proxy-storage-clash",
        ],
    },
    Platform.HACKERONE: {
        "excluded_bug_classes": [
            "missing-best-practices", "logout-csrf", "self-xss",
            "clickjacking-without-impact", "missing-dmarc",
            "weak-captcha-without-impact",
        ],
        "min_severity": "low",
        "accepted_bug_classes": [
            "xss-reflected", "xss-stored", "xss-dom", "sqli",
            "idor", "ssrf", "open-redirect", "csrf", "broken-auth",
            "rce", "command-injection", "path-traversal",
            "file-inclusion", "xxe", "deserialization",
            "business-logic", "race-condition-web",
            "information-disclosure", "api-key-exposure",
            "subdomain-takeover", "cache-poisoning",
            "request-smuggling", "oauth-bypass",
            "mass-assignment", "prototype-pollution",
            "jwt-bypass", "graphql-introspection",
            "cors-misconfiguration", "host-header-injection",
            "websocket-hijack",
        ],
    },
    Platform.BUGCROWD: {
        "excluded_bug_classes": [
            "missing-best-practices", "self-xss", "logout-csrf",
            "clickjacking-standalone",
        ],
        "min_severity": "low",
    },
}

# Bug class → severity mapping (for programs that don't specify)
DEFAULT_SEVERITY_MAP = {
    "reentrancy": "critical",
    "rce": "critical",
    "command-injection": "critical",
    "sqli": "critical",
    "xxe": "high",
    "deserialization": "high",
    "ssrf": "high",
    "idor": "high",
    "broken-auth": "high",
    "oauth-bypass": "high",
    "jwt-bypass": "high",
    "request-smuggling": "high",
    "cache-poisoning": "high",
    "xss-stored": "high",
    "xss-reflected": "medium",
    "xss-dom": "medium",
    "csrf": "medium",
    "open-redirect": "low",
    "information-disclosure": "low",
    "missing-rate-limiting": "low",
    "clickjacking": "low",
}

# Bug classes that programs NEVER pay for
ALWAYS_EXCLUDED = [
    "missing-best-practices",
    "linter-warning",
    "compiler-suggestion",
    "gas-optimization",
    "missing-natspec",
    "missing-event-emission",
    "centralization-risk-without-exploit",
    "admin-privilege-as-designed",
    "logout-csrf-without-session-fixation",
    "self-xss-without-escalation",
]


# ---------------------------------------------------------------------------
# Program-Fit Engine
# ---------------------------------------------------------------------------

class ProgramFitGate:
    """Checks findings against program scope and acceptance rules."""

    def __init__(self, target: str):
        self.target = target
        safe = target.replace("/", "_").replace(":", "_").replace("*", "WILDCARD")
        self._dir = PROGRAM_FIT_DIR / safe
        self._dir.mkdir(parents=True, exist_ok=True)
        self._scope_file = self._dir / "scope.json"
        self._gated_file = self._dir / "gated_findings.json"

    def set_scope(self, scope: ProgramScope):
        """Define the program scope for this target."""
        self._scope_file.write_text(json.dumps(scope.to_dict(), indent=2))

    def get_scope(self) -> Optional[ProgramScope]:
        if self._scope_file.exists():
            data = json.loads(self._scope_file.read_text())
            data["platform"] = Platform(data["platform"])
            return ProgramScope(**data)
        return None

    def load_scope_from_platform(self, platform: Platform,
                                  program_name: str = "") -> ProgramScope:
        """Load default scope rules for a platform."""
        defaults = PLATFORM_DEFAULTS.get(platform, {})

        scope = ProgramScope(
            program_id=f"{platform.value}:{program_name or 'default'}",
            platform=platform,
            name=program_name or platform.value,
            excluded_bug_classes=defaults.get("excluded_bug_classes", []),
            accepted_bug_classes=defaults.get("accepted_bug_classes", []),
            min_severity=defaults.get("min_severity", "low"),
        )

        self.set_scope(scope)
        return scope

    def gate_finding(self, finding: Dict) -> Tuple[FitResult, str]:
        """Run a single finding through the program-fit gate.

        Returns (FitResult, reason).
        """
        scope = self.get_scope()
        if not scope:
            # No scope defined — include everything, warn
            return FitResult.INCLUDE, "No program scope defined — including by default"

        # Check 1: Bug class exclusion
        bug_class = finding.get("bug_class", "").lower()
        if bug_class in ALWAYS_EXCLUDED:
            return FitResult.EXCLUDE, f"Bug class '{bug_class}' is always excluded"

        if bug_class in scope.excluded_bug_classes:
            return FitResult.EXCLUDE, (
                f"Bug class '{bug_class}' excluded by program rules")

        # Check 2: Bug class acceptance (if program specifies accepted classes)
        if scope.accepted_bug_classes:
            if bug_class not in [a.lower() for a in scope.accepted_bug_classes]:
                # Map common aliases
                aliases = {
                    "xss": "xss-reflected",
                    "sql-injection": "sqli",
                    "command-execution": "command-injection",
                    "auth-bypass": "broken-auth",
                }
                mapped = aliases.get(bug_class, bug_class)
                if mapped not in [a.lower() for a in scope.accepted_bug_classes]:
                    return FitResult.NEEDS_REVIEW, (
                        f"Bug class '{bug_class}' not in program's accepted list. "
                        f"May be accepted under a different name.")

        # Check 3: Severity threshold
        severity = finding.get("severity", "info").lower()
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_sev = severity_order.get(scope.min_severity.lower(), 0)
        finding_sev = severity_order.get(severity, 0)

        if finding_sev < min_sev:
            return FitResult.OUT_OF_SEVERITY, (
                f"Severity '{severity}' below program minimum '{scope.min_severity}'")

        # Check 4: Scope domain/asset match
        endpoint = finding.get("endpoint", "")
        if endpoint and scope.in_scope_domains:
            in_scope = False
            for domain in scope.in_scope_domains:
                if domain in endpoint:
                    in_scope = True
                    break
            for wildcard in scope.in_scope_wildcards:
                # *.example.com → matches subdomain.example.com
                suffix = wildcard.lstrip("*")
                if suffix in endpoint:
                    in_scope = True
                    break
            if not in_scope and scope.in_scope_domains:
                return FitResult.EXCLUDE, (
                    f"Endpoint '{endpoint}' not in scope domains: "
                    f"{', '.join(scope.in_scope_domains)}")

        if endpoint and scope.out_of_scope_domains:
            for domain in scope.out_of_scope_domains:
                if domain in endpoint:
                    return FitResult.EXCLUDE, (
                        f"Endpoint '{endpoint}' is out of scope ({domain})")

        # Check 5: Platform-specific requirements
        if scope.platform == Platform.IMMUNEFI:
            if not finding.get("proof_of_concept") and scope.requires_poc:
                return FitResult.NEEDS_REVIEW, "Immunefi requires PoC — none provided"

        # Check 6: Duplication
        gated = self._load_gated()
        for g in gated:
            if (g.get("bug_class") == finding.get("bug_class") and
                    g.get("endpoint") == finding.get("endpoint") and
                    g.get("parameter", "") == finding.get("parameter", "")):
                return FitResult.DUPLICATE, (
                    f"Duplicate of finding {g.get('finding_id', '?')}")

        # Passed all gates
        return FitResult.INCLUDE, "Fits program scope and severity requirements"

    def gate_all(self, findings: List[Dict]) -> Dict:
        """Run all findings through the gate.

        Returns:
            {
                "include": [...],     # fit for report
                "exclude": [...],     # logged, not reported
                "needs_review": [...],  # human should check
                "duplicate": [...],
                "out_of_severity": [...],
                "summary": {...}
            }
        """
        results = {
            "include": [],
            "exclude": [],
            "needs_review": [],
            "duplicate": [],
            "out_of_severity": [],
            "summary": {
                "total": len(findings),
                "passed": 0,
                "filtered": 0,
                "noise_ratio": 0.0,
                "gated_at": datetime.now(timezone.utc).isoformat(),
            },
        }

        for finding in findings:
            fit, reason = self.gate_finding(finding)
            entry = {
                **finding,
                "fit_result": fit.value,
                "fit_reason": reason,
                "gated_at": datetime.now(timezone.utc).isoformat(),
            }

            if fit == FitResult.INCLUDE:
                results["include"].append(entry)
            elif fit == FitResult.EXCLUDE:
                results["exclude"].append(entry)
            elif fit == FitResult.NEEDS_REVIEW:
                results["needs_review"].append(entry)
            elif fit == FitResult.DUPLICATE:
                results["duplicate"].append(entry)
            elif fit == FitResult.OUT_OF_SEVERITY:
                results["out_of_severity"].append(entry)

        results["summary"]["passed"] = len(results["include"])
        results["summary"]["filtered"] = len(findings) - len(results["include"])
        results["summary"]["noise_ratio"] = (
            results["summary"]["filtered"] / max(len(findings), 1))

        # Persist gated findings
        self._save_gated(
            results["include"] + results["exclude"] +
            results["needs_review"] + results["duplicate"] +
            results["out_of_severity"]
        )

        return results

    def get_reportable(self, findings: List[Dict]) -> List[Dict]:
        """Return only findings that should go into the report."""
        gated = self.gate_all(findings)
        return gated["include"]

    def get_noise(self, findings: List[Dict]) -> List[Dict]:
        """Return findings filtered out (logged but not reported)."""
        gated = self.gate_all(findings)
        return (gated["exclude"] + gated["duplicate"] +
                gated["out_of_severity"])

    def generate_report(self) -> str:
        scope = self.get_scope()
        gated = self._load_gated()

        lines = [
            "=" * 72,
            f"  PROGRAM-FIT GATE REPORT — {self.target}",
            "=" * 72,
            f"  Generated: {datetime.now(timezone.utc).isoformat()}",
        ]

        if scope:
            lines.extend([
                f"  Program: {scope.name} ({scope.platform.value})",
                f"  Min severity: {scope.min_severity}",
                f"  Bounty range: {scope.bounty_range or 'Not specified'}",
                f"  In-scope domains: {len(scope.in_scope_domains)}",
                f"  Accepted bug classes: {len(scope.accepted_bug_classes)}",
                f"  Excluded bug classes: {len(scope.excluded_bug_classes)}",
            ])
        else:
            lines.append("  No program scope defined — all findings pass")

        lines.extend([
            "=" * 72,
            "",
        ])

        by_result = defaultdict(list)
        for g in gated:
            by_result[g.get("fit_result", "unknown")].append(g)

        lines.append(f"Total findings gated: {len(gated)}")
        lines.append("")
        for result, findings in by_result.items():
            icon = {
                "include": "✅",
                "exclude": "🔇",
                "needs_review": "⚠️",
                "duplicate": "🔄",
                "out_of_severity": "⬇️",
            }.get(result, "❓")
            lines.append(f"  {icon} {result}: {len(findings)}")

        lines.append("")

        if by_result.get("include"):
            lines.append("## Included in Report")
            lines.append("")
            for f in by_result["include"]:
                lines.append(f"  [{f.get('severity', '?').upper()}] {f.get('title', f.get('finding_id', '?'))}")
                lines.append(f"    {f.get('endpoint', 'N/A')} ({f.get('bug_class', '?')})")
            lines.append("")

        if by_result.get("exclude"):
            lines.append("## Excluded (Logged Only)")
            lines.append("")
            for f in by_result["exclude"]:
                lines.append(f"  {f.get('title', '?')}")
                lines.append(f"    Reason: {f.get('fit_reason', '?')}")
            lines.append("")

        noise = len(gated) - len(by_result.get("include", []))
        noise_pct = (noise / max(len(gated), 1)) * 100
        lines.append(f"Noise filtered: {noise}/{len(gated)} ({noise_pct:.0f}%)")
        lines.append("")
        lines.append("=" * 72)
        lines.append("  Generated by BountyForge Program-Fit Gate v3.0.0")
        lines.append("=" * 72)

        return "\n".join(lines)

    # ---- Persistence ----

    def _load_gated(self) -> List[Dict]:
        if self._gated_file.exists():
            return json.loads(self._gated_file.read_text())
        return []

    def _save_gated(self, gated: List[Dict]):
        self._gated_file.write_text(json.dumps(gated, indent=2))

    def delete_all(self):
        for f in [self._scope_file, self._gated_file]:
            if f.exists():
                f.unlink()


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def gate_findings_for_program(target: str, findings: List[Dict],
                               platform: Platform = None,
                               program_name: str = "") -> Dict:
    """Quick gate: load platform defaults, gate all findings."""
    gate = ProgramFitGate(target)

    if platform:
        gate.load_scope_from_platform(platform, program_name)

    return gate.gate_all(findings)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="BountyForge Program-Fit Gate")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--program", help="Platform:program_name (e.g. h1:myprogram)")
    parser.add_argument("--set-scope", help="Set program scope (JSON file or inline)")
    parser.add_argument("--finding-file", help="JSONL findings file to gate")
    parser.add_argument("--finding-json", help="Single finding as JSON")
    parser.add_argument("--gate-all", action="store_true",
                        help="Gate all findings in state for this target")
    parser.add_argument("--reportable-only", action="store_true",
                        help="Output only reportable findings")
    parser.add_argument("--noise-only", action="store_true",
                        help="Output only filtered (noise) findings")
    parser.add_argument("--report", action="store_true",
                        help="Generate program-fit report")
    parser.add_argument("--output-format", default="text", choices=["text", "json"])
    args = parser.parse_args()

    gate = ProgramFitGate(args.target)

    # Load scope
    if args.program:
        platform_name, _, program_name = args.program.partition(":")
        platform_map = {
            "h1": Platform.HACKERONE, "hackerone": Platform.HACKERONE,
            "bc": Platform.BUGCROWD, "bugcrowd": Platform.BUGCROWD,
            "immunefi": Platform.IMMUNEFI,
            "intigriti": Platform.INTIGRITI,
            "ywh": Platform.YESWEHACK, "yeswehack": Platform.YESWEHACK,
        }
        platform = platform_map.get(platform_name.lower(), Platform.GENERIC)
        gate.load_scope_from_platform(platform, program_name)
        print(f"[+] Loaded scope: {platform.value}" + (
            f" ({program_name})" if program_name else ""))

    elif args.set_scope:
        scope_data = json.loads(args.set_scope)
        scope_data["platform"] = Platform(scope_data.get("platform", "generic"))
        scope = ProgramScope(**scope_data)
        gate.set_scope(scope)
        print(f"[+] Custom scope set: {scope.program_id}")

    # Load findings
    findings = []
    if args.finding_file:
        raw = Path(args.finding_file).read_text()
        findings = [json.loads(l) for l in raw.splitlines() if l.strip()]
    elif args.finding_json:
        findings = [json.loads(args.finding_json)]
    elif args.gate_all:
        try:
            from tools.state import get_findings
            findings = get_findings(args.target)
        except ImportError:
            print("[!] state module not available, use --finding-file")
            sys.exit(1)

    if not findings:
        print("[!] No findings to gate")
        sys.exit(1)

    print(f"[*] BountyForge Program-Fit Gate v3.0.0")
    print(f"[*] Target: {args.target}")
    print(f"[*] Findings: {len(findings)}")
    print()

    if len(findings) == 1 and not args.gate_all:
        fit, reason = gate.gate_finding(findings[0])
        icons = {
            FitResult.INCLUDE: "✅",
            FitResult.EXCLUDE: "🔇",
            FitResult.NEEDS_REVIEW: "⚠️",
            FitResult.DUPLICATE: "🔄",
            FitResult.OUT_OF_SEVERITY: "⬇️",
        }
        print(f"  {icons.get(fit, '❓')} {fit.value}: {reason}")
    else:
        results = gate.gate_all(findings)

        if args.reportable_only:
            if args.output_format == "json":
                print(json.dumps(results["include"], indent=2))
            else:
                for f in results["include"]:
                    print(f"✅ [{f.get('severity', '?').upper()}] {f.get('title', '?')}")

        elif args.noise_only:
            noise = results["exclude"] + results["duplicate"] + results["out_of_severity"]
            if args.output_format == "json":
                print(json.dumps(noise, indent=2))
            else:
                for f in noise:
                    print(f"🔇 {f.get('title', '?')}: {f.get('fit_reason', '?')}")

        else:
            s = results["summary"]
            print(f"  ✅ Include:        {len(results['include'])}")
            print(f"  🔇 Exclude:        {len(results['exclude'])}")
            print(f"  ⚠️  Needs review:   {len(results['needs_review'])}")
            print(f"  🔄 Duplicate:      {len(results['duplicate'])}")
            print(f"  ⬇️  Below severity: {len(results['out_of_severity'])}")
            print(f"  📊 Noise ratio:    {s['noise_ratio']:.0%}")

    if args.report:
        print("\n" + gate.generate_report())


if __name__ == "__main__":
    main()
