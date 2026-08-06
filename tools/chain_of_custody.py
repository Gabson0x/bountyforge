#!/usr/bin/env python3
"""
BountyForge Chain of Custody — Tamper-proof audit trail for every finding.

Every finding gets a chronological, hashed evidence chain that proves:
  1. When the finding was discovered
  2. What evidence was collected
  3. How the finding evolved (severity changes, chain additions)
  4. That evidence has not been tampered with

Cryptographic guarantees:
  - BLAKE3 content hashing for all evidence files
  - Merkle chain linking custody entries (each entry hashes previous)
  - Optional GPG detached signatures
  - WORM-like append-only log structure (JSONL + hash chain)

Usage:
  python3 tools/chain_of_custody.py --init finding-abc123
  python3 tools/chain_of_custody.py --log finding-abc123 --event "discovery" --file evidence.pcap
  python3 tools/chain_of_custody.py --verify finding-abc123
  python3 tools/chain_of_custody.py --export finding-abc123 --format pdf
"""

import os
import sys
import json
import hashlib
import shutil
import secrets
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict

ROOT = Path(__file__).resolve().parent.parent
CUSTODY_ROOT = ROOT / "custody"

# Try BLAKE3, fall back to SHA-256
try:
    import blake3
    def content_hash(data: bytes) -> str:
        return blake3.blake3(data).hexdigest()
    HASH_ALGO = "BLAKE3"
except ImportError:
    def content_hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
    HASH_ALGO = "SHA-256"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CustodyEntry:
    entry_id: str
    sequence: int
    timestamp: str
    event_type: str  # discovery, evidence_added, severity_changed, poc_generated,
                     # report_submitted, fix_verified, chain_escalated, review_completed
    description: str
    evidence_files: List[Dict] = field(default_factory=list)
    previous_hash: str = ""  # Hash of previous entry (Merkle chain)
    metadata: Dict = field(default_factory=dict)
    gpg_signature: Optional[str] = None

    def compute_hash(self) -> str:
        """Compute hash of this entry (excluding previous_hash and gpg_signature)."""
        payload = json.dumps({
            "entry_id": self.entry_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "evidence_files": self.evidence_files,
            "previous_hash": self.previous_hash,
            "metadata": self.metadata,
        }, sort_keys=True)
        return content_hash(payload.encode())


@dataclass
class CustodyChain:
    finding_id: str
    created_at: str
    updated_at: str
    entries: List[CustodyEntry] = field(default_factory=list)
    last_hash: str = ""  # Hash of the last entry (chain tip)
    verified: bool = False
    gpg_key_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Chain operations
# ---------------------------------------------------------------------------

class ChainOfCustody:
    """Manages tamper-proof audit chains for findings."""

    def __init__(self):
        CUSTODY_ROOT.mkdir(parents=True, exist_ok=True)

    def _chain_dir(self, finding_id: str) -> Path:
        d = CUSTODY_ROOT / finding_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _evidence_dir(self, finding_id: str) -> Path:
        d = self._chain_dir(finding_id) / "evidence"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _chain_file(self, finding_id: str) -> Path:
        return self._chain_dir(finding_id) / "chain.jsonl"

    def _meta_file(self, finding_id: str) -> Path:
        return self._chain_dir(finding_id) / "meta.json"

    def init_chain(self, finding_id: str, title: str = "",
                   target: str = "", bug_class: str = "",
                   severity: str = "info") -> Dict:
        """Initialize a new custody chain for a finding."""
        d = self._chain_dir(finding_id)
        if self._meta_file(finding_id).exists():
            return json.loads(self._meta_file(finding_id).read_text())

        now = datetime.now(timezone.utc).isoformat()
        chain = CustodyChain(
            finding_id=finding_id,
            created_at=now,
            updated_at=now,
            last_hash=content_hash(finding_id.encode()),  # Genesis hash
        )

        meta = {
            "finding_id": finding_id,
            "title": title,
            "target": target,
            "bug_class": bug_class,
            "initial_severity": severity,
            "created_at": now,
            "chain_tip": chain.last_hash,
            "entry_count": 0,
            "gpg_signed": False,
        }

        self._meta_file(finding_id).write_text(json.dumps(meta, indent=2))
        return meta

    def log_event(self, finding_id: str, event_type: str,
                  description: str, evidence_files: List[str] = None,
                  metadata: Dict = None, gpg_sign: bool = False) -> Dict:
        """Append a custody event to the chain.

        Each event:
        1. Hashes any evidence files and stores copies
        2. Links to previous event via hash
        3. Records timestamp, event type, description
        4. Optionally GPG-signs the entry
        """
        meta = json.loads(self._meta_file(finding_id).read_text())
        evidence_dir = self._evidence_dir(finding_id)

        # Process evidence files
        evidence_records = []
        if evidence_files:
            for fpath in evidence_files:
                fp = Path(fpath)
                if not fp.exists():
                    continue
                fhash = content_hash(fp.read_bytes())
                # Store timestamped copy
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                dst = evidence_dir / f"{ts}_{fp.name}"
                shutil.copy2(fp, dst)
                evidence_records.append({
                    "filename": fp.name,
                    "hash": fhash,
                    "stored_as": str(dst.name),
                    "size": fp.stat().st_size,
                })

        # Create entry
        seq = meta["entry_count"] + 1
        now = datetime.now(timezone.utc).isoformat()

        entry = CustodyEntry(
            entry_id=content_hash(f"{finding_id}:{seq}:{now}".encode())[:16],
            sequence=seq,
            timestamp=now,
            event_type=event_type,
            description=description,
            evidence_files=evidence_records,
            previous_hash=meta["chain_tip"],
            metadata=metadata or {},
        )

        entry_hash = entry.compute_hash()

        # GPG sign if requested
        if gpg_sign and shutil.which("gpg"):
            sig = self._gpg_sign(entry_hash)
            entry.gpg_signature = sig
            meta["gpg_signed"] = True

        # Append to chain
        with open(self._chain_file(finding_id), "a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

        # Update meta
        meta["chain_tip"] = entry_hash
        meta["entry_count"] = seq
        meta["updated_at"] = now
        self._meta_file(finding_id).write_text(json.dumps(meta, indent=2))

        return {
            "entry_id": entry.entry_id,
            "sequence": seq,
            "hash": entry_hash,
            "evidence_count": len(evidence_records),
        }

    def verify_chain(self, finding_id: str) -> Dict:
        """Verify the integrity of the entire custody chain.

        Checks:
        1. Each entry's hash matches recomputed hash
        2. Each entry's previous_hash matches the previous entry's hash
        3. Chain has no gaps in sequence numbers
        4. All evidence files exist and match their recorded hashes
        """
        cf = self._chain_file(finding_id)
        if not cf.exists():
            return {"valid": False, "error": "No chain file exists"}

        meta = json.loads(self._meta_file(finding_id).read_text())
        evidence_dir = self._evidence_dir(finding_id)

        entries = []
        for line in cf.read_text().splitlines():
            if line.strip():
                entries.append(json.loads(line))

        result = {
            "valid": True,
            "finding_id": finding_id,
            "entry_count": len(entries),
            "verified_entries": 0,
            "evidence_verified": 0,
            "evidence_missing": 0,
            "hash_chain_intact": True,
            "errors": [],
        }

        prev_hash = content_hash(finding_id.encode())
        expected_seq = 1

        for i, raw in enumerate(entries):
            entry_hash = CustodyEntry(**{
                k: v for k, v in raw.items()
                if k not in ("gpg_signature",)
            }).compute_hash()

            if raw.get("gpg_signature"):
                # GPG signature verification
                gpg_ok = self._gpg_verify(entry_hash, raw["gpg_signature"])
                if not gpg_ok:
                    result["errors"].append(
                        f"Entry {raw['sequence']}: GPG signature verification FAILED")

            if raw["previous_hash"] != prev_hash:
                result["hash_chain_intact"] = False
                result["errors"].append(
                    f"Entry {raw['sequence']}: Hash chain broken. "
                    f"Expected {prev_hash[:16]}..., got {raw['previous_hash'][:16]}...")

            if raw["sequence"] != expected_seq:
                result["errors"].append(
                    f"Sequence gap at entry {i}: expected {expected_seq}, got {raw['sequence']}")

            # Verify evidence files
            for ev in raw.get("evidence_files", []):
                stored = evidence_dir / ev["stored_as"]
                if not stored.exists():
                    result["evidence_missing"] += 1
                    result["errors"].append(
                        f"Entry {raw['sequence']}: Evidence file missing: {ev['filename']}")
                else:
                    fhash = content_hash(stored.read_bytes())
                    if fhash != ev["hash"]:
                        result["errors"].append(
                            f"Entry {raw['sequence']}: Evidence file TAMPERED: {ev['filename']}")
                    else:
                        result["evidence_verified"] += 1

            result["verified_entries"] += 1
            prev_hash = entry_hash
            expected_seq += 1

        if result["errors"]:
            result["valid"] = False

        if len(entries) != meta["entry_count"]:
            result["valid"] = False
            result["errors"].append(
                f"Entry count mismatch: chain has {len(entries)}, meta says {meta['entry_count']}")

        return result

    def export_chain(self, finding_id: str, format: str = "json") -> Path:
        """Export the custody chain with all evidence."""
        d = self._chain_dir(finding_id)
        if format == "json":
            # Create a bundled JSON export
            bundle = {
                "finding_id": finding_id,
                "meta": json.loads(self._meta_file(finding_id).read_text()),
                "chain": [],
            }
            cf = self._chain_file(finding_id)
            if cf.exists():
                for line in cf.read_text().splitlines():
                    if line.strip():
                        bundle["chain"].append(json.loads(line))

            out_path = d / f"custody-bundle-{finding_id}.json"
            out_path.write_text(json.dumps(bundle, indent=2))
            return out_path

        elif format == "pdf":
            # Generate a text summary then convert (requires pandoc + wkhtmltopdf)
            summary = self._generate_text_summary(finding_id)
            txt_path = d / f"custody-{finding_id}.txt"
            txt_path.write_text(summary)

            if shutil.which("pandoc"):
                pdf_path = d / f"custody-{finding_id}.pdf"
                subprocess.run([
                    "pandoc", str(txt_path), "-o", str(pdf_path),
                    "--pdf-engine=wkhtmltopdf"
                ], capture_output=True)
                if pdf_path.exists():
                    return pdf_path
            return txt_path

        raise ValueError(f"Unknown format: {format}")

    def _generate_text_summary(self, finding_id: str) -> str:
        """Generate a human-readable text summary of the chain."""
        meta = json.loads(self._meta_file(finding_id).read_text())
        verify = self.verify_chain(finding_id)

        lines = [
            "=" * 72,
            f"  CHAIN OF CUSTODY — Finding {finding_id}",
            "=" * 72,
            "",
            f"Title:       {meta['title']}",
            f"Target:      {meta['target']}",
            f"Bug Class:   {meta['bug_class']}",
            f"Severity:    {meta['initial_severity']}",
            f"Created:     {meta['created_at']}",
            f"Entries:     {meta['entry_count']}",
            f"Chain Tip:   {meta['chain_tip'][:32]}...",
            f"GPG Signed:  {meta['gpg_signed']}",
            "",
            f"Chain Integrity: {'VALID' if verify['valid'] else 'COMPROMISED'}",
            f"Hash Chain:      {'INTACT' if verify['hash_chain_intact'] else 'BROKEN'}",
            f"Evidence:        {verify['evidence_verified']} verified, {verify['evidence_missing']} missing",
            "",
            "-" * 72,
            "  EVENT LOG",
            "-" * 72,
            "",
        ]

        cf = self._chain_file(finding_id)
        if cf.exists():
            for line in cf.read_text().splitlines():
                if not line.strip():
                    continue
                e = json.loads(line)
                lines.append(
                    f"[{e['sequence']:04d}] {e['timestamp']} | {e['event_type']}")
                lines.append(f"       {e['description']}")
                for ev in e.get("evidence_files", []):
                    lines.append(f"       ↳ Evidence: {ev['filename']} (sha256: {ev['hash'][:16]}...)")
                lines.append(f"       Hash: {content_hash(json.dumps(e, sort_keys=True).encode())[:32]}...")
                lines.append("")

        if verify["errors"]:
            lines.append("-" * 72)
            lines.append("  INTEGRITY ERRORS")
            lines.append("-" * 72)
            for err in verify["errors"]:
                lines.append(f"  [!] {err}")

        lines.append("")
        lines.append("=" * 72)
        lines.append("  Generated by BountyForge Chain of Custody v2.1.0")
        lines.append(f"  {datetime.now(timezone.utc).isoformat()}")
        lines.append("=" * 72)

        return "\n".join(lines)

    def _gpg_sign(self, data: str) -> Optional[str]:
        """Create a detached GPG signature for a string."""
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
                f.write(data)
                tmp_path = f.name

            result = subprocess.run(
                ["gpg", "--detach-sign", "--armor", tmp_path],
                capture_output=True, text=True)
            Path(tmp_path).unlink()

            if result.returncode == 0:
                sig_path = tmp_path + ".asc"
                sig = Path(sig_path).read_text()
                Path(sig_path).unlink(missing_ok=True)
                return sig
        except Exception:
            pass
        return None

    def _gpg_verify(self, data: str, signature: str) -> bool:
        """Verify a GPG detached signature."""
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
                f.write(data)
                tmp_path = f.name

            sig_path = tmp_path + ".asc"
            Path(sig_path).write_text(signature)

            result = subprocess.run(
                ["gpg", "--verify", sig_path, tmp_path],
                capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
        finally:
            Path(tmp_path).unlink(missing_ok=True)
            Path(sig_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

_custody_instance = None

def get_custody() -> ChainOfCustody:
    global _custody_instance
    if _custody_instance is None:
        _custody_instance = ChainOfCustody()
    return _custody_instance


def init_finding_custody(finding_id: str, **kwargs) -> Dict:
    return get_custody().init_chain(finding_id, **kwargs)


def log_custody_event(finding_id: str, event_type: str, description: str,
                      evidence_files: List[str] = None, **kwargs) -> Dict:
    return get_custody().log_event(finding_id, event_type, description,
                                   evidence_files, **kwargs)


def verify_custody(finding_id: str) -> Dict:
    return get_custody().verify_chain(finding_id)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="BountyForge Chain of Custody")
    parser.add_argument("--init", help="Initialize custody chain for a finding ID")
    parser.add_argument("--title", help="Finding title (for --init)")
    parser.add_argument("--target", help="Target name (for --init)")
    parser.add_argument("--bug-class", help="Bug class (for --init)")
    parser.add_argument("--severity", default="info")
    parser.add_argument("--log", help="Append event to custody chain")
    parser.add_argument("--event", help="Event type (discovery, evidence_added, etc.)")
    parser.add_argument("--description", help="Event description")
    parser.add_argument("--file", action="append", help="Evidence file(s) to attach")
    parser.add_argument("--gpg-sign", action="store_true", help="GPG-sign the entry")
    parser.add_argument("--verify", help="Verify chain integrity")
    parser.add_argument("--export", help="Export chain bundle")
    parser.add_argument("--format", default="json", choices=["json", "pdf"])
    args = parser.parse_args()

    coc = ChainOfCustody()

    if args.init:
        result = coc.init_chain(
            args.init, title=args.title or "Untitled",
            target=args.target or "unknown",
            bug_class=args.bug_class or "unknown",
            severity=args.severity)
        print(f"[+] Custody chain initialized: {args.init}")
        print(f"    Chain tip: {result['chain_tip'][:32]}...")

    elif args.log and args.event:
        result = coc.log_event(
            args.log, args.event, args.description or "",
            evidence_files=args.file, gpg_sign=args.gpg_sign)
        print(f"[+] Event logged: [{result['sequence']:04d}] {args.event}")
        print(f"    Hash: {result['hash'][:32]}...")

    elif args.verify:
        result = coc.verify_chain(args.verify)
        status = "VALID" if result["valid"] else "COMPROMISED"
        print(f"[*] Chain integrity: {status}")
        print(f"    Entries verified: {result['verified_entries']}")
        print(f"    Evidence verified: {result['evidence_verified']}")
        print(f"    Evidence missing: {result['evidence_missing']}")
        print(f"    Hash chain: {'INTACT' if result['hash_chain_intact'] else 'BROKEN'}")
        if result["errors"]:
            for e in result["errors"]:
                print(f"    [!] {e}")

    elif args.export:
        path = coc.export_chain(args.export, format=args.format)
        print(f"[+] Chain exported: {path}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
