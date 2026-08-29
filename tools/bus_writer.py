#!/usr/bin/env python3
"""
bus_writer.py — Persist Python engine findings to the BountyForge state bus.

The TypeScript StateBus (sandbox/runtime/state-bus.ts) owns the bus at:
    {BF_STATE_DIR}/bus/{safe_target}/findings.jsonl

Engines call save_finding() after confirming a vulnerability. Each line is a
JSON object using the TS Finding schema, plus alias fields (bug_class,
endpoint, finding_id) so kill_chain.py scoring works unmodified.

Writes are single append() calls under PIPE_BUF (4096 bytes) so concurrent
engine processes can't interleave lines (POSIX atomic append guarantee).
"""

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Optional

PIPE_BUF_SAFE = 3800  # stay under 4096 with margin


def _state_root() -> str:
    return os.environ.get("BF_STATE_DIR", "/home/sandbox/state")


def _safe_target(target: str) -> str:
    # Must match state-bus.ts: target.replace(/[/:*]/g, '_')
    return target.replace("/", "_").replace(":", "_").replace("*", "_")


def _findings_file(target: str) -> Path:
    d = Path(_state_root()) / "bus" / _safe_target(target)
    d.mkdir(parents=True, exist_ok=True)
    return d / "findings.jsonl"


def save_finding(
    target: str,
    *,
    type: str,
    severity: str,
    title: str,
    url: str,
    evidence: str,
    source: str,
    param: Optional[str] = None,
    payload: Optional[str] = None,
    description: Optional[str] = None,
    reproducible: bool = True,
    cvss_score: Optional[float] = None,
) -> str:
    """Append a confirmed finding to the state bus. Returns the finding id."""
    ts_ms = int(time.time() * 1000)
    fid = hashlib.sha256(
        f"{url}|{type}|{source}|{ts_ms}|{uuid.uuid4()}".encode()
    ).hexdigest()[:16]

    sev = (severity or "medium").lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "medium"

    finding = {
        # TS Finding schema (state-bus.ts)
        "id": fid,
        "type": type,
        "severity": sev,
        "title": title,
        "url": url,
        "param": param,
        "payload": payload,
        "evidence": evidence,
        "source": source,
        "timestamp": ts_ms,
        "reproducible": reproducible,
        "description": description or title,
        # kill_chain.py aliases (scores on bug_class / endpoint / finding_id)
        "bug_class": type,
        "endpoint": url,
        "finding_id": fid,
    }
    if cvss_score is not None:
        finding["cvss_score"] = cvss_score

    line = json.dumps(finding, default=str)
    if len(line) > PIPE_BUF_SAFE:
        # Truncate evidence to keep the append atomic
        overflow = len(line) - PIPE_BUF_SAFE
        finding["evidence"] = evidence[: max(0, len(evidence) - overflow - 40)] + "…[truncated]"
        line = json.dumps(finding, default=str)

    path = _findings_file(target)
    with open(path, "a") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())

    return fid


def save_findings(target: str, findings: list, source: str) -> int:
    """
    Persist a list of engine finding dicts (from Finding.to_dict()).
    Normalizes engine-specific fields into the bus schema.
    Returns the number of findings written.
    """
    count = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        try:
            save_finding(
                target,
                type=f.get("type", "unknown"),
                severity=f.get("severity", "medium"),
                title=f.get("title", "Untitled finding"),
                url=f.get("url", target),
                evidence=str(f.get("evidence", "")),
                source=f.get("source", source),
                param=f.get("param") or None,
                payload=f.get("payload") or None,
                description=f.get("description") or f.get("title"),
                reproducible=bool(f.get("reproducible", True)),
                cvss_score=f.get("cvss_score") or None,
            )
            count += 1
        except Exception as e:
            print(f"[bus_writer] failed to save finding: {e}")
    if count:
        print(f"[bus_writer] {count} finding(s) saved to state bus")
    return count
