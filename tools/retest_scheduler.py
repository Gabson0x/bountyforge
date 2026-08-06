#!/usr/bin/env python3
"""
BountyForge Autonomous Retest Scheduler v2.1.0

Automatically re-tests targets when conditions change:
  1. Scope change detected → rescan new assets
  2. Dependency update → retest affected findings
  3. CVE published → check if target is vulnerable
  4. New feature detected → pre-deploy hunt
  5. Time-based retest → periodic re-validation of all findings

Triggers can be:
  - Cron-based (periodic checks)
  - Event-driven (webhook, file watch)
  - Manual (CLI invocation)

Usage:
  python3 tools/retest_scheduler.py --daemon              (run continuously)
  python3 tools/retest_scheduler.py --check target.com    (one-shot check)
  python3 tools/retest_scheduler.py --cron "0 */6 * * *"  (via cron job)
"""

import os
import sys
import json
import time
import hashlib
import subprocess
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict
from urllib.request import urlopen, Request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RETEST_DIR = ROOT / "state" / "retest"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class RetestJob:
    job_id: str
    target: str
    trigger: str  # scope_change, dependency_update, cve_published, new_feature, periodic
    trigger_detail: str = ""
    created_at: str = ""
    scheduled_for: str = ""
    status: str = "pending"  # pending, running, completed, failed
    last_result: Optional[Dict] = None
    retry_count: int = 0
    max_retries: int = 3

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.job_id:
            raw = f"{self.target}:{self.trigger}:{self.created_at}"
            self.job_id = hashlib.sha256(raw.encode()).hexdigest()[:12]


@dataclass
class WatchConfig:
    target: str
    scope_urls: List[str] = field(default_factory=list)  # H1/Bugcrowd scope pages
    cve_keywords: List[str] = field(default_factory=list)  # tech stack keywords
    dependency_files: List[str] = field(default_factory=list)  # package.json, etc.
    feature_flags_url: Optional[str] = None  # changelog or feature flag endpoint
    periodic_interval_hours: int = 24
    last_scope_check: Optional[str] = None
    last_cve_check: Optional[str] = None
    last_dep_check: Optional[str] = None


# ---------------------------------------------------------------------------
# Trigger: Scope Change Detection
# ---------------------------------------------------------------------------

def fetch_scope_hash(scope_urls: List[str]) -> str:
    """Fetch scope pages and compute a hash of their content."""
    contents = []
    for url in scope_urls:
        try:
            req = Request(url, headers={"User-Agent": "BountyForge/2.1"})
            with urlopen(req, timeout=30) as resp:
                contents.append(resp.read().decode("utf-8", errors="ignore"))
        except Exception as e:
            contents.append(f"ERROR: {e}")

    return hashlib.sha256("\n".join(contents).encode()).hexdigest()


def check_scope_changes(target: str, config: WatchConfig) -> List[RetestJob]:
    """Compare current scope hash to stored hash. If changed, create retest jobs."""
    scope_file = RETEST_DIR / f"{target}-scope-hash.txt"
    current_hash = fetch_scope_hash(config.scope_urls)

    jobs = []
    if scope_file.exists():
        old_hash = scope_file.read_text().strip()
        if old_hash != current_hash:
            jobs.append(RetestJob(
                target=target,
                trigger="scope_change",
                trigger_detail=f"Scope hash changed: {old_hash[:12]}... → {current_hash[:12]}...",
            ))

    scope_file.write_text(current_hash)
    config.last_scope_check = datetime.now(timezone.utc).isoformat()
    save_config(target, config)

    return jobs


# ---------------------------------------------------------------------------
# Trigger: CVE Detection
# ---------------------------------------------------------------------------

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_recent_cves(keywords: List[str], days_back: int = 7) -> List[Dict]:
    """Fetch recently published CVEs matching tech stack keywords.

    Keywords are matched against CVE descriptions. E.g.:
      - "nginx" → CVEs affecting nginx
      - "express" → CVEs affecting Express.js
      - "django" → CVEs affecting Django
    """
    matches = []
    pub_end = datetime.now(timezone.utc)
    pub_start = pub_end - timedelta(days=days_back)

    for keyword in keywords:
        params = (
            f"?keywordSearch={keyword}"
            f"&pubStartDate={pub_start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
            f"&pubEndDate={pub_end.strftime('%Y-%m-%dT%H:%M:%S.000')}"
        )
        try:
            req = Request(NVD_API + params,
                          headers={"User-Agent": "BountyForge/2.1"})
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    desc = cve.get("descriptions", [{}])[0].get("value", "")

                    # Check severity
                    metrics = cve.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", [{}])[0]
                    cvss_data = cvss_v31.get("cvssData", {})
                    base_score = cvss_data.get("baseScore", 0)

                    matches.append({
                        "cve_id": cve_id,
                        "description": desc[:300],
                        "cvss_score": base_score,
                        "published": cve.get("published", ""),
                        "matched_keyword": keyword,
                    })
        except Exception as e:
            print(f"  [!] NVD API error for '{keyword}': {e}")

    # Sort by CVSS score descending
    matches.sort(key=lambda x: x["cvss_score"], reverse=True)
    return matches


def check_cves(target: str, config: WatchConfig) -> List[RetestJob]:
    """Check for new CVEs matching the target's tech stack."""
    cve_file = RETEST_DIR / f"{target}-cve-checkpoint.json"
    last_check = None
    if cve_file.exists():
        last_check = json.loads(cve_file.read_text())
        last_seen = last_check.get("last_cve_id", "")

    recent = fetch_recent_cves(config.cve_keywords, days_back=7)
    if not recent:
        return []

    jobs = []
    for cve in recent:
        if cve["cvss_score"] >= 7.0:  # High or Critical only
            jobs.append(RetestJob(
                target=target,
                trigger="cve_published",
                trigger_detail=f"{cve['cve_id']} (CVSS {cve['cvss_score']}): "
                               f"{cve['description'][:100]}",
            ))

    # Save checkpoint
    cve_file.write_text(json.dumps({
        "last_check": datetime.now(timezone.utc).isoformat(),
        "last_cve_id": recent[0]["cve_id"] if recent else "",
        "cves_found": len(recent),
    }))

    config.last_cve_check = datetime.now(timezone.utc).isoformat()
    save_config(target, config)

    return jobs


# ---------------------------------------------------------------------------
# Trigger: Dependency Updates
# ---------------------------------------------------------------------------

def check_dependency_changes(target: str, config: WatchConfig) -> List[RetestJob]:
    """Check if monitored dependency files have changed."""
    jobs = []
    for dep_path in config.dependency_files:
        p = Path(dep_path)
        if not p.exists():
            continue

        hash_file = RETEST_DIR / f"{target}-dep-{p.name}.hash"
        current = hashlib.sha256(p.read_bytes()).hexdigest()

        if hash_file.exists():
            old = hash_file.read_text().strip()
            if old != current:
                jobs.append(RetestJob(
                    target=target,
                    trigger="dependency_update",
                    trigger_detail=f"{p.name} changed: {old[:12]}... → {current[:12]}...",
                ))

        hash_file.write_text(current)

    config.last_dep_check = datetime.now(timezone.utc).isoformat()
    save_config(target, config)
    return jobs


# ---------------------------------------------------------------------------
# Trigger: Periodic Retest
# ---------------------------------------------------------------------------

def create_periodic_job(target: str, config: WatchConfig) -> List[RetestJob]:
    """Create a periodic retest job if enough time has passed."""
    periodic_file = RETEST_DIR / f"{target}-last-periodic.txt"

    should_run = True
    if periodic_file.exists():
        last_str = periodic_file.read_text().strip()
        try:
            last_run = datetime.fromisoformat(last_str)
            delta = datetime.now(timezone.utc) - last_run
            if delta.total_seconds() < config.periodic_interval_hours * 3600:
                should_run = False
        except ValueError:
            pass

    if should_run:
        periodic_file.write_text(datetime.now(timezone.utc).isoformat())
        return [RetestJob(
            target=target,
            trigger="periodic",
            trigger_detail=f"Periodic retest (every {config.periodic_interval_hours}h)",
        )]
    return []


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

def load_config(target: str) -> WatchConfig:
    cfg_file = RETEST_DIR / f"{target}-watch.json"
    if cfg_file.exists():
        data = json.loads(cfg_file.read_text())
        return WatchConfig(**data)
    return WatchConfig(target=target)


def save_config(target: str, config: WatchConfig):
    RETEST_DIR.mkdir(parents=True, exist_ok=True)
    cfg_file = RETEST_DIR / f"{target}-watch.json"
    cfg_file.write_text(json.dumps(asdict(config), indent=2))


# ---------------------------------------------------------------------------
# Job queue
# ---------------------------------------------------------------------------

def enqueue_jobs(jobs: List[RetestJob]):
    """Enqueue retest jobs."""
    queue_file = RETEST_DIR / "queue.jsonl"
    RETEST_DIR.mkdir(parents=True, exist_ok=True)
    with open(queue_file, "a") as f:
        for job in jobs:
            f.write(json.dumps(asdict(job)) + "\n")


def dequeue_jobs(status: str = "pending") -> List[RetestJob]:
    """Dequeue jobs by status."""
    queue_file = RETEST_DIR / "queue.jsonl"
    if not queue_file.exists():
        return []

    jobs = []
    remaining = []
    for line in queue_file.read_text().splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            if data.get("status") == status:
                jobs.append(RetestJob(**data))
            else:
                remaining.append(line)
        except json.JSONDecodeError:
            pass

    queue_file.write_text("\n".join(remaining) + "\n")
    return jobs


def execute_job(job: RetestJob) -> Dict:
    """Execute a retest job by running the hunt engine against the target."""
    hunt_script = ROOT / "tools" / "hunt.py"
    if not hunt_script.exists():
        return {"success": False, "error": "hunt.py not found"}

    try:
        result = subprocess.run(
            [sys.executable, str(hunt_script), "--target", job.target, "--quick"],
            capture_output=True, text=True, timeout=300)

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout[-500:],
            "stderr": result.stderr[-200:],
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timeout after 300s"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def run_pending_jobs() -> int:
    """Execute all pending jobs. Returns count of executed jobs."""
    jobs = dequeue_jobs("pending")
    executed = 0

    for job in jobs:
        print(f"  [{job.job_id}] {job.trigger}: {job.target}")
        result = execute_job(job)
        job.status = "completed" if result.get("success") else "failed"
        job.last_result = result

        # Re-enqueue with updated status
        RETEST_DIR.mkdir(parents=True, exist_ok=True)
        with open(RETEST_DIR / "completed.jsonl", "a") as f:
            f.write(json.dumps(asdict(job)) + "\n")

        executed += 1

        if job.status == "failed" and job.retry_count < job.max_retries:
            job.retry_count += 1
            job.status = "pending"
            enqueue_jobs([job])

    return executed


# ---------------------------------------------------------------------------
# Daemon mode
# ---------------------------------------------------------------------------

class RetestDaemon:
    """Background daemon that periodically checks triggers and executes jobs."""

    def __init__(self, check_interval: int = 300):
        self.check_interval = check_interval  # seconds between trigger checks
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print(f"[*] Retest daemon started (check every {self.check_interval}s)")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)

    def _loop(self):
        while self._running:
            try:
                # Check all configured targets
                for cfg_file in RETEST_DIR.glob("*-watch.json"):
                    target = cfg_file.stem.replace("-watch", "")
                    config = load_config(target)

                    all_jobs = []
                    all_jobs.extend(check_scope_changes(target, config))
                    all_jobs.extend(check_cves(target, config))
                    all_jobs.extend(check_dependency_changes(target, config))
                    all_jobs.extend(create_periodic_job(target, config))

                    if all_jobs:
                        print(f"[*] {target}: {len(all_jobs)} new retest job(s)")
                        enqueue_jobs(all_jobs)

                # Execute pending jobs
                count = run_pending_jobs()
                if count:
                    print(f"[*] Executed {count} retest job(s)")

            except Exception as e:
                print(f"[!] Daemon error: {e}")

            time.sleep(self.check_interval)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="BountyForge Retest Scheduler")
    parser.add_argument("--daemon", action="store_true", help="Run as background daemon")
    parser.add_argument("--interval", type=int, default=300,
                        help="Daemon check interval in seconds (default: 300)")
    parser.add_argument("--check", help="One-shot check for a target")
    parser.add_argument("--watch-scope", nargs="+", help="Scope URLs to monitor")
    parser.add_argument("--watch-cve", nargs="+", help="Tech keywords for CVE matching")
    parser.add_argument("--watch-deps", nargs="+", help="Dependency files to monitor")
    parser.add_argument("--periodic", type=int, default=24,
                        help="Periodic retest interval in hours (default: 24)")
    parser.add_argument("--run-jobs", action="store_true", help="Execute all pending jobs")
    parser.add_argument("--list-jobs", action="store_true", help="List pending jobs")
    args = parser.parse_args()

    RETEST_DIR.mkdir(parents=True, exist_ok=True)

    if args.daemon:
        daemon = RetestDaemon(check_interval=args.interval)
        daemon.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            daemon.stop()

    elif args.check:
        config = load_config(args.check)
        if args.watch_scope:
            config.scope_urls = args.watch_scope
        if args.watch_cve:
            config.cve_keywords = args.watch_cve
        if args.watch_deps:
            config.dependency_files = args.watch_deps
        if args.periodic:
            config.periodic_interval_hours = args.periodic
        save_config(args.check, config)

        jobs = []
        jobs.extend(check_scope_changes(args.check, config))
        jobs.extend(check_cves(args.check, config))
        jobs.extend(check_dependency_changes(args.check, config))
        jobs.extend(create_periodic_job(args.check, config))

        if jobs:
            print(f"[*] {len(jobs)} retest job(s) created:")
            for j in jobs:
                print(f"  [{j.job_id}] {j.trigger}: {j.trigger_detail}")
            enqueue_jobs(jobs)
        else:
            print(f"[*] No retests needed for {args.check}")

    elif args.run_jobs:
        count = run_pending_jobs()
        print(f"[*] Executed {count} job(s)")

    elif args.list_jobs:
        queue_file = RETEST_DIR / "queue.jsonl"
        if queue_file.exists():
            jobs = [json.loads(l) for l in queue_file.read_text().splitlines() if l.strip()]
            print(f"[*] {len(jobs)} pending job(s):")
            for j in jobs:
                print(f"  [{j.get('job_id', '?')}] {j.get('trigger')}: "
                      f"{j.get('target')} — {j.get('trigger_detail', '')[:80]}")
        else:
            print("[*] No pending jobs")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
