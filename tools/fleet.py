#!/usr/bin/env python3
"""
BountyForge Fleet Mode — Parallel multi-target hunting.

Runs concurrent hunt sessions across multiple targets with:
  - Shared triage queue (one finding across all targets goes to one reviewer)
  - Shared pattern memory (what works on target A is tried on target B)
  - Shared exploit library (PoCs are portable across targets)
  - Resource-aware concurrency limiting
  - Per-target state isolation

Usage:
  python3 tools/fleet.py --targets targets.txt
  python3 tools/fleet.py --targets target1.com,target2.com,target3.com
  python3 tools/fleet.py --targets targets.txt --concurrency 5
  python3 tools/fleet.py --targets targets.txt --mode recon-only
  python3 tools/fleet.py --targets targets.txt --mode hunt-only (requires prior recon)
"""

import os
import sys
import json
import time
import signal
import hashlib
import subprocess
import threading
import queue
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FLEET_DIR = ROOT / "state" / "fleet"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FleetTarget:
    name: str
    mode: str = "full"  # recon-only, hunt-only, full
    recon_status: str = "pending"
    hunt_status: str = "pending"
    live_hosts: int = 0
    urls_found: int = 0
    findings_count: int = 0
    errors: List[str] = field(default_factory=list)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    auth_file: Optional[str] = None

    def status(self) -> str:
        if self.errors:
            return "error"
        if self.recon_status == "completed" and self.hunt_status == "completed":
            return "completed"
        if self.recon_status in ("running", "completed") or \
           self.hunt_status == "running":
            return "running"
        return "pending"


@dataclass
class FleetSession:
    session_id: str
    targets: List[FleetTarget]
    concurrency: int = 3
    mode: str = "full"
    started_at: str = ""
    completed_at: Optional[str] = None
    total_findings: int = 0
    shared_patterns: List[Dict] = field(default_factory=list)

    def __post_init__(self):
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()
        if not self.session_id:
            raw = f"fleet:{len(self.targets)}:{self.started_at}"
            self.session_id = hashlib.sha256(raw.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Pattern memory (shared across targets)
# ---------------------------------------------------------------------------

class PatternMemory:
    """Cross-target pattern memory. What works on one target gets tried on others."""

    def __init__(self):
        FLEET_DIR.mkdir(parents=True, exist_ok=True)
        self._file = FLEET_DIR / "pattern-memory.jsonl"

    def add(self, pattern: Dict):
        """Record a successful pattern."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "pattern": pattern,
        }
        with open(self._file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def get_all(self) -> List[Dict]:
        """Get all known patterns."""
        if not self._file.exists():
            return []
        return [json.loads(l)["pattern"]
                for l in self._file.read_text().splitlines() if l.strip()]

    def get_for_target(self, tech_stack: List[str]) -> List[Dict]:
        """Get patterns relevant to a target's technology stack."""
        all_patterns = self.get_all()
        # Filter by tech stack relevance
        relevant = []
        for p in all_patterns:
            for tech in tech_stack:
                if tech.lower() in json.dumps(p).lower():
                    relevant.append(p)
                    break
        return relevant or all_patterns[-50:]  # Return last 50 if no match


# ---------------------------------------------------------------------------
# Target execution
# ---------------------------------------------------------------------------

def run_recon(target: FleetTarget) -> bool:
    """Run recon on a single target."""
    recon_script = ROOT / "tools" / "recon_engine.sh"
    if not recon_script.exists():
        target.errors.append("recon_engine.sh not found")
        return False

    try:
        target.recon_status = "running"
        result = subprocess.run(
            ["bash", str(recon_script), target.name],
            capture_output=True, text=True, timeout=600)

        if result.returncode == 0:
            # Count results
            recon_dir = ROOT / "recon" / target.name
            if recon_dir.exists():
                live_file = recon_dir / "live-hosts.txt"
                urls_file = recon_dir / "urls.txt"
                if live_file.exists():
                    target.live_hosts = len(live_file.read_text().splitlines())
                if urls_file.exists():
                    target.urls_found = len(urls_file.read_text().splitlines())
            target.recon_status = "completed"
            return True
        else:
            target.errors.append(f"Recon failed: {result.stderr[-200:]}")
            target.recon_status = "failed"
            return False
    except subprocess.TimeoutExpired:
        target.errors.append("Recon timeout (600s)")
        target.recon_status = "failed"
        return False
    except Exception as e:
        target.errors.append(f"Recon error: {e}")
        target.recon_status = "failed"
        return False


def run_hunt(target: FleetTarget) -> bool:
    """Run hunt on a single target."""
    hunt_script = ROOT / "tools" / "hunt.py"
    if not hunt_script.exists():
        target.errors.append("hunt.py not found")
        return False

    try:
        target.hunt_status = "running"
        cmd = [sys.executable, str(hunt_script), "--target", target.name, "--quick"]

        if target.auth_file:
            cmd.extend(["--auth-file", target.auth_file])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            target.hunt_status = "completed"
            # Try to load findings count
            try:
                from tools.state import get_findings
                findings = get_findings(target.name)
                target.findings_count = len(findings)
            except ImportError:
                pass
            return True
        else:
            target.errors.append(f"Hunt failed: {result.stderr[-200:]}")
            target.hunt_status = "failed"
            return False
    except subprocess.TimeoutExpired:
        target.errors.append("Hunt timeout (300s)")
        target.hunt_status = "failed"
        return False
    except Exception as e:
        target.errors.append(f"Hunt error: {e}")
        target.hunt_status = "failed"
        return False


# ---------------------------------------------------------------------------
# Fleet executor
# ---------------------------------------------------------------------------

class FleetExecutor:
    """Manages parallel execution across multiple targets."""

    def __init__(self, session: FleetSession):
        self.session = session
        self.pattern_memory = PatternMemory()
        self._executor = ThreadPoolExecutor(max_workers=session.concurrency)
        self._futures = {}
        self._lock = threading.Lock()
        self._shutdown_flag = False

    def execute(self) -> Dict:
        """Run the fleet. Returns summary dict."""
        futures = []

        for target in self.session.targets:
            if self._shutdown_flag:
                break

            if self.session.mode in ("recon-only", "full"):
                target.started_at = datetime.now(timezone.utc).isoformat()
                f = self._executor.submit(self._run_target_pipeline, target)
                futures.append(f)

            elif self.session.mode == "hunt-only":
                target.started_at = datetime.now(timezone.utc).isoformat()
                f = self._executor.submit(run_hunt, target)
                futures.append(f)

        # Wait for all to complete
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                print(f"[!] Target execution error: {e}")

        self._executor.shutdown(wait=True)
        self.session.completed_at = datetime.now(timezone.utc).isoformat()

        # Aggregate findings
        total = 0
        for t in self.session.targets:
            if t.findings_count:
                total += t.findings_count
        self.session.total_findings = total

        return self.summary()

    def _run_target_pipeline(self, target: FleetTarget):
        """Full pipeline: recon → hunt for one target."""
        print(f"  [{target.name}] Starting recon...")
        if run_recon(target):
            print(f"  [{target.name}] Recon complete ({target.live_hosts} live hosts)")
            print(f"  [{target.name}] Starting hunt...")
            if run_hunt(target):
                print(f"  [{target.name}] Hunt complete ({target.findings_count} findings)")
            else:
                print(f"  [{target.name}] Hunt failed: {'; '.join(target.errors)}")
        else:
            print(f"  [{target.name}] Recon failed: {'; '.join(target.errors)}")
        target.completed_at = datetime.now(timezone.utc).isoformat()

    def shutdown(self):
        self._shutdown_flag = True
        self._executor.shutdown(wait=False)

    def summary(self) -> Dict:
        """Generate fleet execution summary."""
        completed = [t for t in self.session.targets
                     if t.status() == "completed"]
        failed = [t for t in self.session.targets if t.status() == "error"]
        running = [t for t in self.session.targets if t.status() == "running"]
        pending = [t for t in self.session.targets if t.status() == "pending"]

        return {
            "session_id": self.session.session_id,
            "started": self.session.started_at,
            "completed": self.session.completed_at,
            "total_targets": len(self.session.targets),
            "completed": len(completed),
            "failed": len(failed),
            "running": len(running),
            "pending": len(pending),
            "total_findings": self.session.total_findings,
            "live_hosts_total": sum(t.live_hosts for t in self.session.targets),
            "urls_total": sum(t.urls_found for t in self.session.targets),
            "errors": [{"target": t.name, "errors": t.errors}
                       for t in self.session.targets if t.errors],
        }


# ---------------------------------------------------------------------------
# Target file parsing
# ---------------------------------------------------------------------------

def parse_targets(source: str) -> List[FleetTarget]:
    """Parse targets from comma-separated list or file."""
    if os.path.isfile(source):
        lines = Path(source).read_text().splitlines()
    else:
        lines = [t.strip() for t in source.split(",")]

    targets = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Parse: target.com or target.com:auth.json
        parts = line.split(":", 1)
        name = parts[0]
        auth_file = parts[1] if len(parts) > 1 else None

        targets.append(FleetTarget(name=name, auth_file=auth_file))

    return targets


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="BountyForge Fleet Mode")
    parser.add_argument("--targets", required=True,
                        help="Target list (comma-separated or file path)")
    parser.add_argument("--concurrency", type=int, default=3,
                        help="Max parallel targets (default: 3)")
    parser.add_argument("--mode", default="full",
                        choices=["full", "recon-only", "hunt-only"],
                        help="Execution mode (default: full)")
    parser.add_argument("--output", help="Output file for session summary (JSON)")
    args = parser.parse_args()

    targets = parse_targets(args.targets)
    if not targets:
        print("[!] No targets parsed")
        sys.exit(1)

    print(f"[*] BountyForge Fleet Mode v2.1.0")
    print(f"[*] Targets: {len(targets)}")
    print(f"[*] Concurrency: {args.concurrency}")
    print(f"[*] Mode: {args.mode}")
    print()

    for i, t in enumerate(targets):
        print(f"  [{i+1}] {t.name}" + (f" (auth: {t.auth_file})" if t.auth_file else ""))

    session = FleetSession(
        targets=targets,
        concurrency=args.concurrency,
        mode=args.mode,
    )

    executor = FleetExecutor(session)

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print("\n[*] Shutting down fleet...")
        executor.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    print()
    summary = executor.execute()

    print(f"\n[*] Fleet session complete: {session.session_id}")
    print(f"    Completed: {summary['completed']}/{summary['total_targets']} targets")
    print(f"    Findings:  {summary['total_findings']}")
    print(f"    Live hosts: {summary['live_hosts_total']}")
    print(f"    URLs:      {summary['urls_total']}")

    if summary["errors"]:
        print(f"\n[!] Errors:")
        for e in summary["errors"]:
            print(f"    {e['target']}: {', '.join(e['errors'])}")

    if args.output:
        Path(args.output).write_text(json.dumps(summary, indent=2))
        print(f"\n[*] Summary written to {args.output}")


if __name__ == "__main__":
    main()
