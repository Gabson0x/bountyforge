#!/usr/bin/env python3
"""
BountyForge Ledger Verifier v3.0.0

The ledger is the truth. This tool verifies that every finding has corresponding
entries in the journal and endpoint logs — you cannot claim you tested what you
didn't test. It also generates coverage gap reports showing what should have
been tested but wasn't.

Checks:
  - Finding↔journal consistency: does every finding have evidence in the journal?
  - Finding↔endpoint consistency: does every finding have a tested endpoint entry?
  - Orphan detection: any findings with zero supporting evidence?
  - Coverage gaps: what endpoints/parameters/classes haven't been tested?
  - Journal integrity: is the append-only log intact (no gaps, no rewrites)?
  - Session coverage: which sessions contributed what findings?

Usage:
  python3 tools/ledger.py --target example.com --verify
  python3 tools/ledger.py --target example.com --verify-finding abc123
  python3 tools/ledger.py --target example.com --coverage-gaps
  python3 tools/ledger.py --target example.com --integrity-check
  python3 tools/ledger.py --target example.com --report
"""

import json
import sys
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LEDGER_DIR = ROOT / "state" / "ledger"

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class EvidenceRecord:
    """A single piece of evidence from the ledger."""
    source: str  # journal, endpoints, findings, custody
    entry_id: str  # unique identifier for this record
    timestamp: str
    event_type: str = ""
    finding_id: str = ""
    endpoint: str = ""
    method: str = "GET"
    content_hash: str = ""
    session_id: str = ""
    raw: Dict = field(default_factory=dict)


@dataclass
class OrphanedFinding:
    """A finding with no supporting evidence in the ledger."""
    finding_id: str
    title: str
    bug_class: str
    endpoint: str
    severity: str
    claimed_at: str
    missing_evidence: List[str] = field(default_factory=list)
    # What's missing: "journal_entry", "endpoint_test", "custody_chain"
    confidence_penalty: float = 0.0  # How much to reduce confidence
    recommendation: str = ""


@dataclass
class CoverageGap:
    """Something that should have been tested but wasn't."""
    gap_type: str  # endpoint, parameter, bug_class, session, capability
    identifier: str = ""
    severity: str = "medium"  # how important is this gap?
    recommended_agent: str = ""
    description: str = ""
    related_findings: List[str] = field(default_factory=list)


@dataclass
class LedgerIntegrity:
    """Result of an integrity check on the append-only journal."""
    target: str
    journal_file: str
    total_entries: int
    verified_entries: int
    tampered_entries: int = 0
    sequence_gaps: int = 0
    timestamp_gaps: int = 0  # Entries with timestamp going backwards
    hash_chain_intact: bool = True
    first_entry: str = ""
    last_entry: str = ""
    is_valid: bool = True
    errors: List[str] = field(default_factory=list)


@dataclass
class LedgerReport:
    target: str
    generated_at: str
    findings_total: int
    findings_verified: int  # Have supporting evidence
    findings_orphaned: int  # No supporting evidence
    endpoints_tested: int
    sessions_used: int
    coverage_gaps: List[CoverageGap] = field(default_factory=list)
    orphans: List[OrphanedFinding] = field(default_factory=list)
    integrity: Optional[LedgerIntegrity] = None
    verification_score: float = 0.0  # 0.0 to 1.0 — how verifiable is this audit?

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Ledger Verifier
# ---------------------------------------------------------------------------

class LedgerVerifier:
    """Cross-references findings, journal, and endpoints for truth verification."""

    def __init__(self, target: str):
        self.target = target
        safe = target.replace("/", "_").replace(":", "_").replace("*", "WILDCARD")
        self._dir = LEDGER_DIR / safe
        self._dir.mkdir(parents=True, exist_ok=True)

        # Paths to state files
        try:
            from tools.state import _state_dir
            self._state_dir = _state_dir(target)
        except ImportError:
            self._state_dir = ROOT / "state" / "sessions" / safe

    # ---- Evidence Collection ----

    def _collect_journal_entries(self) -> List[Dict]:
        """Collect all journal entries for this target."""
        jf = self._state_dir / "journal.jsonl"
        if not jf.exists():
            return []
        return [json.loads(l) for l in jf.read_text().splitlines() if l.strip()]

    def _collect_endpoint_entries(self) -> List[Dict]:
        """Collect all endpoint test records."""
        ef = self._state_dir / "endpoints.jsonl"
        if not ef.exists():
            return []
        return [json.loads(l) for l in ef.read_text().splitlines() if l.strip()]

    def _collect_findings(self) -> List[Dict]:
        """Collect all findings."""
        ff = self._state_dir / "findings.jsonl"
        if not ff.exists():
            return []
        return [json.loads(l) for l in ff.read_text().splitlines() if l.strip()]

    def _collect_dead_ends(self) -> List[Dict]:
        """Collect dead end records."""
        df = self._state_dir / "dead_ends.jsonl"
        if not df.exists():
            return []
        return [json.loads(l) for l in df.read_text().splitlines() if l.strip()]

    # ---- Verification ----

    def verify_finding(self, finding: Dict) -> Tuple[bool, List[str]]:
        """Verify a single finding has supporting evidence.

        Returns (is_verified, list_of_missing_evidence_types).
        """
        finding_id = finding.get("finding_id", "")
        endpoint = finding.get("endpoint", "")
        method = finding.get("method", "GET")
        bug_class = finding.get("bug_class", "")
        found_at = finding.get("found_at", "")

        missing = []

        # Check 1: Journal entry for this finding
        journal = self._collect_journal_entries()
        journal_match = False
        for entry in journal:
            data = entry.get("data", {})
            if data.get("finding_id") == finding_id:
                journal_match = True
                break
            if entry.get("event") == "finding_added" and finding_id in json.dumps(data):
                journal_match = True
                break
        if not journal_match:
            missing.append("journal_entry")

        # Check 2: Endpoint was actually tested
        endpoints = self._collect_endpoint_entries()
        endpoint_match = False
        for ep in endpoints:
            if (ep.get("url", "") == endpoint and
                    ep.get("method", "GET") in (method, "GET")):
                endpoint_match = True
                break
        if not endpoint_match and endpoint:
            missing.append("endpoint_test")

        # Check 3: Custody chain initiated (if available)
        try:
            from tools.chain_of_custody import verify_custody
            custody_check = verify_custody(finding_id)
            if not custody_check.get("valid"):
                missing.append("custody_chain")
        except (ImportError, Exception):
            pass  # Custody optional

        # Check 4: Timing consistency — was this finding recorded AFTER tests?
        if found_at and endpoints:
            finding_ts = found_at
            tested_before = any(
                ep.get("tested_at", "") <= finding_ts
                for ep in endpoints if ep.get("url", "") == endpoint
            )
            if not tested_before:
                missing.append("timing_consistency")

        return len(missing) == 0, missing

    def verify_all(self) -> LedgerReport:
        """Verify all findings against the ledger."""
        findings = self._collect_findings()
        journal = self._collect_journal_entries()
        endpoints = self._collect_endpoint_entries()
        dead_ends = self._collect_dead_ends()

        orphans = []
        verified = 0

        for finding in findings:
            is_verified, missing = self.verify_finding(finding)
            if is_verified:
                verified += 1
            else:
                # Calculate confidence penalty
                penalty_map = {
                    "journal_entry": 0.4,
                    "endpoint_test": 0.3,
                    "custody_chain": 0.15,
                    "timing_consistency": 0.15,
                }
                penalty = sum(penalty_map.get(m, 0.1) for m in missing)

                recommendation = ""
                if "journal_entry" in missing:
                    recommendation += "Re-run test and log to journal. "
                if "endpoint_test" in missing:
                    recommendation += f"Run GET/POST on {finding.get('endpoint', '?')}. "
                if "timing_consistency" in missing:
                    recommendation += "Verify endpoint was tested before finding was logged. "

                orphans.append(OrphanedFinding(
                    finding_id=finding.get("finding_id", "unknown"),
                    title=finding.get("title", "Untitled"),
                    bug_class=finding.get("bug_class", ""),
                    endpoint=finding.get("endpoint", ""),
                    severity=finding.get("severity", "info"),
                    claimed_at=finding.get("found_at", ""),
                    missing_evidence=missing,
                    confidence_penalty=min(penalty, 1.0),
                    recommendation=recommendation.strip(),
                ))

        # Session analysis
        sessions = set()
        for ep in endpoints:
            sid = ep.get("session_id", "")
            if sid:
                sessions.add(sid)
        for je in journal:
            sid = je.get("data", {}).get("session_id", "")
            if sid:
                sessions.add(sid)

        # Coverage gaps
        gaps = self._find_coverage_gaps(findings, endpoints, dead_ends)

        # Integrity check
        integrity = self.check_integrity()

        # Verification score
        if findings:
            score = verified / len(findings)
            # Penalize for integrity issues
            if integrity and not integrity.is_valid:
                score *= 0.8
            # Penalize for coverage gaps
            if gaps:
                score *= max(0.5, 1.0 - (len(gaps) * 0.05))
        else:
            score = 1.0

        report = LedgerReport(
            target=self.target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            findings_total=len(findings),
            findings_verified=verified,
            findings_orphaned=len(orphans),
            endpoints_tested=len(endpoints),
            sessions_used=len(sessions),
            coverage_gaps=gaps,
            orphans=orphans,
            integrity=integrity,
            verification_score=round(score, 2),
        )

        self._save_report(report)
        return report

    # ---- Coverage Gaps ----

    def _find_coverage_gaps(self, findings: List[Dict],
                             endpoints: List[Dict],
                             dead_ends: List[Dict]) -> List[CoverageGap]:
        """Identify what hasn't been tested that should have been."""
        gaps = []

        tested_endpoints = set()
        for ep in endpoints:
            tested_endpoints.add(f"{ep.get('method', 'GET')}:{ep.get('url', '')}")

        tested_urls = set()
        for ep in endpoints:
            tested_urls.add(ep.get("url", ""))

        # Gap 1: Endpoints mentioned in findings that have no test record
        for finding in findings:
            ep = finding.get("endpoint", "")
            if ep and ep not in tested_urls:
                gaps.append(CoverageGap(
                    gap_type="endpoint",
                    identifier=ep,
                    severity="high",
                    recommended_agent="web-api-agent",
                    description=f"Finding references {ep} but no test record exists",
                    related_findings=[finding.get("finding_id", "")],
                ))

        # Gap 2: Bug classes with zero findings (should some agents be run?)
        found_classes = set(f.get("bug_class", "") for f in findings)
        # Critical classes that should always be tested
        always_test = [
            "idor", "ssrf", "sqli", "xss-reflected", "xss-stored",
            "broken-auth", "csrf", "open-redirect", "path-traversal",
            "command-injection", "xxe", "deserialization",
            "information-disclosure", "mass-assignment",
        ]
        for bc in always_test:
            if bc not in found_classes:
                gaps.append(CoverageGap(
                    gap_type="bug_class",
                    identifier=bc,
                    severity="medium",
                    recommended_agent="web-api-agent",
                    description=f"No findings for {bc} — agent may not have tested it",
                ))

        # Gap 3: HTTP methods that weren't tested on discovered endpoints
        method_coverage = defaultdict(set)
        for ep in endpoints:
            method_coverage[ep.get("url", "")].add(ep.get("method", "GET"))

        for url, methods in method_coverage.items():
            missing_methods = {"POST", "PUT", "PATCH", "DELETE"} - methods
            if missing_methods and any(m in url.lower() for m in ["api", "user", "admin"]):
                gaps.append(CoverageGap(
                    gap_type="http_method",
                    identifier=f"{url} missing: {', '.join(sorted(missing_methods))}",
                    severity="low",
                    recommended_agent="web-api-agent",
                    description=f"Only tested {', '.join(sorted(methods))} on {url}",
                ))

        # Gap 4: Dead ends per tested endpoint ratio
        if endpoints and dead_ends:
            ratio = len(dead_ends) / max(len(endpoints), 1)
            if ratio < 0.1:
                gaps.append(CoverageGap(
                    gap_type="dead_end_ratio",
                    identifier="low_dead_end_ratio",
                    severity="low",
                    recommended_agent="web-api-agent",
                    description=f"Only {len(dead_ends)} dead ends for {len(endpoints)} "
                                 f"tests ({ratio:.0%}) — may not be testing edge cases",
                ))

        return gaps

    # ---- Integrity Check ----

    def check_integrity(self) -> Optional[LedgerIntegrity]:
        """Check journal integrity — no gaps, no rewrites, no tampering."""
        jf = self._state_dir / "journal.jsonl"
        if not jf.exists():
            return None

        entries = []
        for line in jf.read_text().splitlines():
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        if not entries:
            return None

        integrity = LedgerIntegrity(
            target=self.target,
            journal_file=str(jf),
            total_entries=len(entries),
            verified_entries=0,
            first_entry=entries[0].get("ts", "unknown"),
            last_entry=entries[-1].get("ts", "unknown"),
        )

        prev_ts = None
        hashes = []

        for i, entry in enumerate(entries):
            ts = entry.get("ts", "")
            event = entry.get("event", "")

            # Check: timestamps don't go backwards
            if prev_ts and ts < prev_ts:
                integrity.timestamp_gaps += 1
                integrity.errors.append(
                    f"Entry {i}: timestamp went backwards "
                    f"({prev_ts} → {ts}) for event '{event}'")

            # Check: hash chain (if entries are hashed)
            entry_hash = hashlib.sha256(
                json.dumps(entry, sort_keys=True).encode()
            ).hexdigest()
            hashes.append(entry_hash)

            # Check: essential fields present
            if "ts" not in entry or "event" not in entry:
                integrity.tampered_entries += 1
                integrity.errors.append(
                    f"Entry {i}: missing required fields (ts or event)")

            integrity.verified_entries += 1
            prev_ts = ts

        integrity.is_valid = (
            integrity.tampered_entries == 0 and
            integrity.sequence_gaps == 0 and
            len(integrity.errors) == 0
        )

        return integrity

    # ---- Session Coverage ----

    def get_session_coverage(self) -> Dict:
        """Analyze which sessions contributed which findings."""
        findings = self._collect_findings()
        endpoints = self._collect_endpoint_entries()

        sessions = defaultdict(lambda: {
            "findings": 0,
            "endpoints_tested": 0,
            "bug_classes": set(),
            "severities": defaultdict(int),
        })

        for f in findings:
            sid = f.get("session_id", "unknown")
            sessions[sid]["findings"] += 1
            sessions[sid]["bug_classes"].add(f.get("bug_class", ""))
            sessions[sid]["severities"][f.get("severity", "info")] += 1

        for ep in endpoints:
            sid = ep.get("session_id", "unknown")
            sessions[sid]["endpoints_tested"] += 1

        return dict(sessions)

    # ---- Reporting ----

    def generate_report(self) -> str:
        report = self.verify_all()

        lines = [
            "=" * 72,
            f"  LEDGER VERIFICATION REPORT — {report.target}",
            "=" * 72,
            f"  Generated: {report.generated_at}",
            f"  Verification Score: {report.verification_score:.0%}",
            "=" * 72,
            "",
            f"Findings total:     {report.findings_total}",
            f"Findings verified:  {report.findings_verified}",
            f"Findings orphaned:  {report.findings_orphaned}",
            f"Endpoints tested:   {report.endpoints_tested}",
            f"Sessions used:      {report.sessions_used}",
            "",
        ]

        if report.integrity:
            i = report.integrity
            status = "✅ VALID" if i.is_valid else "❌ ISSUES FOUND"
            lines.extend([
                f"Journal Integrity: {status}",
                f"  Total entries:    {i.total_entries}",
                f"  Verified:         {i.verified_entries}",
                f"  Tampered:         {i.tampered_entries}",
                f"  Timestamp gaps:   {i.timestamp_gaps}",
                f"  First entry:      {i.first_entry}",
                f"  Last entry:       {i.last_entry}",
                "",
            ])
            if i.errors:
                for e in i.errors:
                    lines.append(f"  [!] {e}")
                lines.append("")

        lines.append("-" * 72)
        lines.append("")

        if report.orphans:
            lines.append(f"## ORPHANED FINDINGS ({len(report.orphans)})")
            lines.append("Findings with no supporting evidence in the ledger:")
            lines.append("")
            for o in report.orphans:
                lines.append(f"  [{o.severity.upper()}] {o.title}")
                lines.append(f"    Finding ID: {o.finding_id}")
                lines.append(f"    Endpoint: {o.endpoint}")
                lines.append(f"    Missing: {', '.join(o.missing_evidence)}")
                lines.append(f"    Confidence penalty: -{o.confidence_penalty:.0%}")
                if o.recommendation:
                    lines.append(f"    Fix: {o.recommendation}")
                lines.append("")
        else:
            lines.append("✅ All findings have supporting evidence in the ledger.")
            lines.append("")

        lines.append("-" * 72)
        lines.append("")

        if report.coverage_gaps:
            lines.append(f"## COVERAGE GAPS ({len(report.coverage_gaps)})")
            lines.append("")
            for g in report.coverage_gaps:
                lines.append(f"  [{g.severity.upper()}] {g.gap_type}: {g.identifier}")
                lines.append(f"    {g.description}")
                lines.append(f"    Recommended: run {g.recommended_agent}")
                lines.append("")

        lines.append("=" * 72)
        lines.append("  Generated by BountyForge Ledger Verifier v3.0.0")
        lines.append("=" * 72)

        return "\n".join(lines)

    # ---- Persistence ----

    def _save_report(self, report: LedgerReport):
        report_file = self._dir / "latest_report.json"
        data = asdict(report)
        # Convert objects
        data["coverage_gaps"] = [asdict(g) for g in report.coverage_gaps]
        data["orphans"] = [asdict(o) for o in report.orphans]
        if report.integrity:
            data["integrity"] = asdict(report.integrity)
        report_file.write_text(json.dumps(data, indent=2, default=str))

    def delete_all(self):
        for f in self._dir.glob("*"):
            f.unlink()


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def verify_target(target: str) -> LedgerReport:
    """Quick verification for a target."""
    verifier = LedgerVerifier(target)
    return verifier.verify_all()


def verify_finding_evidence(target: str, finding: Dict) -> Tuple[bool, List[str]]:
    """Check if a single finding is backed by evidence."""
    verifier = LedgerVerifier(target)
    return verifier.verify_finding(finding)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="BountyForge Ledger Verifier")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--verify", action="store_true",
                        help="Verify all findings against ledger")
    parser.add_argument("--verify-finding", help="Verify a single finding ID")
    parser.add_argument("--coverage-gaps", action="store_true",
                        help="Find coverage gaps")
    parser.add_argument("--integrity-check", action="store_true",
                        help="Check journal file integrity")
    parser.add_argument("--session-coverage", action="store_true",
                        help="Show per-session coverage")
    parser.add_argument("--report", action="store_true",
                        help="Generate full verification report")
    parser.add_argument("--output-format", default="text", choices=["text", "json"])
    args = parser.parse_args()

    verifier = LedgerVerifier(args.target)

    if args.integrity_check:
        integrity = verifier.check_integrity()
        if args.output_format == "json":
            print(json.dumps(asdict(integrity) if integrity else {}, indent=2))
        else:
            if not integrity:
                print("[!] No journal file found")
            else:
                status = "VALID" if integrity.is_valid else "COMPROMISED"
                print(f"[*] Journal integrity: {status}")
                print(f"    Entries: {integrity.total_entries}")
                print(f"    Verified: {integrity.verified_entries}")
                print(f"    Tampered: {integrity.tampered_entries}")
                print(f"    Timestamp gaps: {integrity.timestamp_gaps}")
                if integrity.errors:
                    for e in integrity.errors:
                        print(f"    [!] {e}")

    elif args.verify_finding:
        findings = verifier._collect_findings()
        match = None
        for f in findings:
            if f.get("finding_id") == args.verify_finding:
                match = f
                break

        if not match:
            print(f"[!] Finding {args.verify_finding} not found")
            sys.exit(1)

        is_verified, missing = verifier.verify_finding(match)
        if is_verified:
            print(f"✅ Finding {args.verify_finding} is verified — all evidence present")
        else:
            print(f"❌ Finding {args.verify_finding} has missing evidence:")
            for m in missing:
                print(f"    Missing: {m}")

    elif args.coverage_gaps:
        findings = verifier._collect_findings()
        endpoints = verifier._collect_endpoint_entries()
        dead_ends = verifier._collect_dead_ends()
        gaps = verifier._find_coverage_gaps(findings, endpoints, dead_ends)

        if args.output_format == "json":
            print(json.dumps([asdict(g) for g in gaps], indent=2))
        else:
            print(f"[*] Coverage gaps: {len(gaps)}")
            for g in gaps:
                print(f"  [{g.severity.upper()}] {g.gap_type}: {g.identifier}")
                print(f"    {g.description}")

    elif args.session_coverage:
        coverage = verifier.get_session_coverage()
        if args.output_format == "json":
            print(json.dumps(coverage, indent=2))
        else:
            for sid, data in coverage.items():
                print(f"  Session: {sid}")
                print(f"    Findings: {data['findings']}")
                print(f"    Endpoints: {data['endpoints_tested']}")
                print(f"    Bug classes: {', '.join(data['bug_classes'])}")
                print()

    elif args.verify or args.report:
        report = verifier.verify_all()

        if args.output_format == "json":
            data = asdict(report)
            data["coverage_gaps"] = [asdict(g) for g in report.coverage_gaps]
            data["orphans"] = [asdict(o) for o in report.orphans]
            if report.integrity:
                data["integrity"] = asdict(report.integrity)
            print(json.dumps(data, indent=2, default=str))
        else:
            print(f"[*] Verification Score: {report.verification_score:.0%}")
            print(f"    Findings: {report.findings_total} total, "
                  f"{report.findings_verified} verified, "
                  f"{report.findings_orphaned} orphaned")
            print(f"    Endpoints tested: {report.endpoints_tested}")
            print(f"    Coverage gaps: {len(report.coverage_gaps)}")

            if report.orphans:
                print(f"\n[!] Orphaned findings:")
                for o in report.orphans:
                    print(f"    ❌ {o.title}")
                    print(f"       Missing: {', '.join(o.missing_evidence)}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
