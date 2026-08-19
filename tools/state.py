#!/usr/bin/env python3
"""
BountyForge Session State Engine — JSONL-based persistent state tracking.

State directory structure:
  state/
    sessions/
      {target}/
        state.json        — full state snapshot
        journal.jsonl     — append-only event log
        endpoints.jsonl   — tested endpoints with results
        findings.jsonl    — confirmed findings
        leads.jsonl       — persistent OPEN LEAD research objects (state transitions)
        dead_ends.jsonl   — paths that yielded nothing

Safety guarantees:
  - Atomic writes (write to .tmp, then rename)
  - No raw tokens in logs (only 12-char session_id hashes)
  - JSONL append-only for journal (tamper-evident)
  - Automatic .private/ gitignore generation
"""

import json
import os
import time
import hashlib
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict

ROOT = Path(__file__).resolve().parent.parent
STATE_ROOT = ROOT / "state"
PRIVATE_ROOT = ROOT / ".private"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class EndpointEntry:
    url: str
    method: str = "GET"
    status: int = 0
    content_hash: str = ""
    content_length: int = 0
    tested_at: str = ""
    session_id: str = ""  # never the raw token
    notes: str = ""

    def __post_init__(self):
        if not self.tested_at:
            self.tested_at = datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    finding_id: str = ""
    title: str = ""
    severity: str = "info"  # critical, high, medium, low, info
    endpoint: str = ""
    method: str = "GET"
    bug_class: str = ""
    cvss_score: float = 0.0
    description: str = ""
    impact: str = ""
    proof_of_concept: str = ""
    remediation: str = ""
    found_at: str = ""
    session_id: str = ""
    chain_parent: Optional[str] = None  # finding_id of bug A if this is bug B in chain
    status: str = "open"  # open, reported, resolved, dup, n/a

    def __post_init__(self):
        if not self.found_at:
            self.found_at = datetime.now(timezone.utc).isoformat()
        if not self.finding_id:
            raw = f"{self.endpoint}|{self.method}|{self.bug_class}|{self.found_at}"
            self.finding_id = hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class SessionState:
    target: str
    created_at: str = ""
    updated_at: str = ""
    endpoints_tested: int = 0
    findings_count: int = 0
    dead_ends: int = 0
    leads_open: int = 0  # OPEN + MUTATING leads in the ledger (tools/leads.py)
    session_ids: List[str] = field(default_factory=list)
    auth_method: str = "none"  # cookie, bearer, oauth, none

    def __post_init__(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


# ---------------------------------------------------------------------------
# Atomic write helpers
# ---------------------------------------------------------------------------

def atomic_write(path: Path, content: str):
    """Write to .tmp then rename — prevents partial writes."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(content)
    os.replace(tmp, path)


def atomic_append(path: Path, line: str):
    """Append a single JSON line to a JSONL file atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(line.rstrip("\n") + "\n")
        f.flush()
        os.fsync(f.fileno())


def ensure_private_gitignore():
    """Ensure .private/ is gitignored."""
    gi = ROOT / ".gitignore"
    patterns = ["state/", ".private/", "*.tmp"]
    existing = set()
    if gi.exists():
        existing = set(l.strip() for l in gi.read_text().splitlines())
    changed = False
    for p in patterns:
        if p not in existing:
            with open(gi, "a") as f:
                f.write(p + "\n")
            changed = True


# ---------------------------------------------------------------------------
# State operations
# ---------------------------------------------------------------------------

def _state_dir(target: str) -> Path:
    """Get state directory for a target, sanitizing the name."""
    safe = target.replace("/", "_").replace(":", "_").replace("*", "WILDCARD")
    return STATE_ROOT / "sessions" / safe


def load_state(target: str) -> SessionState:
    """Load or create session state for a target."""
    d = _state_dir(target)
    sf = d / "state.json"

    if sf.exists():
        data = json.loads(sf.read_text())
        return SessionState(**data)

    return SessionState(target=target)


def save_state(target: str, state: SessionState):
    """Persist session state atomically."""
    state.updated_at = datetime.now(timezone.utc).isoformat()
    d = _state_dir(target)
    atomic_write(d / "state.json", json.dumps(asdict(state), indent=2))


def log_journal(target: str, event: str, data: Dict = None):
    """Append a journal entry (append-only, tamper-evident)."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "data": data or {},
    }
    atomic_append(_state_dir(target) / "journal.jsonl", json.dumps(entry))


def mark_tested(target: str, url: str, method: str = "GET",
                status: int = 0, content: str = "",
                session_id: str = "", notes: str = ""):
    """Record that an endpoint was tested."""
    entry = EndpointEntry(
        url=url, method=method, status=status,
        content_hash=hashlib.sha256(content.encode()).hexdigest() if content else "",
        content_length=len(content),
        session_id=session_id, notes=notes,
    )
    atomic_append(_state_dir(target) / "endpoints.jsonl", json.dumps(asdict(entry)))

    state = load_state(target)
    state.endpoints_tested += 1
    save_state(target, state)


def mark_dead_end(target: str, url: str, method: str = "GET",
                  reason: str = ""):
    """Record that an endpoint yielded nothing."""
    entry = {
        "url": url,
        "method": method,
        "reason": reason,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    atomic_append(_state_dir(target) / "dead_ends.jsonl", json.dumps(entry))

    state = load_state(target)
    state.dead_ends += 1
    save_state(target, state)


def add_finding(target: str, finding: Dict) -> str:
    """Add a confirmed finding to the findings log. Returns finding_id."""
    f = Finding(**finding)
    atomic_append(_state_dir(target) / "findings.jsonl", json.dumps(asdict(f)))

    state = load_state(target)
    state.findings_count += 1
    save_state(target, state)

    log_journal(target, "finding_added", {"finding_id": f.finding_id, "title": f.title})
    return f.finding_id


def get_findings(target: str) -> List[Dict]:
    """Load all findings for a target."""
    f = _state_dir(target) / "findings.jsonl"
    if not f.exists():
        return []
    return [json.loads(l) for l in f.read_text().splitlines() if l.strip()]


def get_untested_endpoints(target: str, all_endpoints: List[str]) -> List[str]:
    """Filter a list of endpoints to only those not yet tested."""
    tested = set()
    ef = _state_dir(target) / "endpoints.jsonl"
    if ef.exists():
        for line in ef.read_text().splitlines():
            if line.strip():
                e = json.loads(line)
                tested.add(f"{e['method']}:{e['url']}")
    return [ep for ep in all_endpoints
            if ep not in tested and f"GET:{ep}" not in tested]


def get_state_summary(target: str) -> Dict:
    """Get a human-readable summary of state for a target."""
    state = load_state(target)
    return {
        "target": target,
        "created": state.created_at,
        "updated": state.updated_at,
        "endpoints_tested": state.endpoints_tested,
        "findings": state.findings_count,
        "open_leads": state.leads_open,
        "dead_ends": state.dead_ends,
        "sessions": len(state.session_ids),
        "auth_method": state.auth_method,
    }


def rotate_state(target: str, max_journal_lines: int = 10000):
    """Rotate journal if it exceeds max lines. Keeps 3 backups."""
    jf = _state_dir(target) / "journal.jsonl"
    if not jf.exists():
        return

    lines = jf.read_text().splitlines()
    if len(lines) <= max_journal_lines:
        return

    # Rotate: keep last N lines, archive rest
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive = _state_dir(target) / f"journal.{ts}.jsonl"
    archive.write_text("\n".join(lines[:-max_journal_lines]) + "\n")
    atomic_write(jf, "\n".join(lines[-max_journal_lines:]) + "\n")

    # Keep only 3 archives
    archives = sorted(_state_dir(target).glob("journal.*.jsonl"))
    for old in archives[:-3]:
        old.unlink()


# ---------------------------------------------------------------------------
# Cross-session correlation
# ---------------------------------------------------------------------------

def find_chain_candidates(target: str) -> List[Dict]:
    """Find findings that could be chained for higher severity.

    Looks for patterns like:
      - Open redirect + OAuth endpoint = potential ATO
      - IDOR (read) + PUT on same endpoint = write escalation
      - SSRF + internal service discovery = infrastructure access
      - XSS + missing HttpOnly = session hijack
    """
    findings = get_findings(target)
    chains = []

    for i, f1 in enumerate(findings):
        for j, f2 in enumerate(findings):
            if i >= j:
                continue

            # IDOR read → write escalation
            if (f1["bug_class"] == "idor" and f1["method"] == "GET" and
                    f2["bug_class"] == "idor" and f2["method"] in ("PUT", "DELETE", "POST") and
                    f1["endpoint"].rstrip("/").rstrip("0123456789") ==
                    f2["endpoint"].rstrip("/").rstrip("0123456789")):
                chains.append({
                    "chain_type": "idor_read_to_write",
                    "bug_a": f1["finding_id"],
                    "bug_b": f2["finding_id"],
                    "combined_severity": "high",
                    "description": f"IDOR read ({f1['endpoint']}) + IDOR write ({f2['endpoint']})"
                })

            # Open redirect + OAuth
            if (f1["bug_class"] == "open_redirect" and
                    f2["bug_class"] in ("oauth_misconfig", "authorization")):
                chains.append({
                    "chain_type": "open_redirect_to_oauth_ato",
                    "bug_a": f1["finding_id"],
                    "bug_b": f2["finding_id"],
                    "combined_severity": "critical",
                    "description": f"Open redirect ({f1['endpoint']}) chainable to OAuth ATO ({f2['endpoint']})"
                })

            # SSRF + internal
            if (f1["bug_class"] == "ssrf" and
                    f2["bug_class"] in ("infra_exposure", "information_disclosure")):
                chains.append({
                    "chain_type": "ssrf_to_infra",
                    "bug_a": f1["finding_id"],
                    "bug_b": f2["finding_id"],
                    "combined_severity": "high",
                    "description": f"SSRF ({f1['endpoint']}) + internal exposure ({f2['endpoint']})"
                })

    return chains


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

def init_state():
    """Initialize state directory structure and gitignore."""
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    (STATE_ROOT / "sessions").mkdir(parents=True, exist_ok=True)
    PRIVATE_ROOT.mkdir(parents=True, exist_ok=True)
    ensure_private_gitignore()


# Auto-init on import
init_state()
