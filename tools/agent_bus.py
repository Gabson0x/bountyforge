#!/usr/bin/env python3
"""
BountyForge Agent Communication Bus — Cross-agent signal passing.

Enables autonomous chain building by letting agents broadcast structured
signals to each other. Signals are persisted as JSONL and replayed when
the receiving agent starts its hunt.

Usage:
  from tools.agent_bus import AgentBus, Signal
  bus = AgentBus("target.com")
  bus.send(Signal(signal_type="discovery", from_agent="web-api-agent",
                   to_agents=["access-control-agent"], ...))
  signals = bus.receive("access-control-agent")
"""

import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict

ROOT = Path(__file__).resolve().parent.parent
SIGNALS_ROOT = ROOT / "state" / "signals"


@dataclass
class Signal:
    signal_type: str  # discovery, handoff, chain, alert, request, promotion
    from_agent: str
    to_agents: List[str]  # ["*"] means all agents
    priority: str  # critical, high, medium, low
    finding_ref: Optional[str] = None  # finding_id or lead_id
    signal_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    signal_id: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.signal_id:
            import hashlib
            raw = f"{self.from_agent}:{self.signal_type}:{self.timestamp}"
            self.signal_id = hashlib.sha256(raw.encode()).hexdigest()[:12]

    def to_context(self) -> str:
        """Render as a context block for the receiving agent."""
        return f"""
[CROSS-AGENT SIGNAL | {self.priority.upper()} | {self.signal_type}]
From: {self.from_agent}
To: {', '.join(self.to_agents)}
Finding: {self.finding_ref or 'N/A'}
Signal ID: {self.signal_id}
Data: {json.dumps(self.signal_data, indent=2)}
"""


class AgentBus:
    """Persistent message bus for agent-to-agent communication."""

    def __init__(self, target: str):
        self.target = target
        safe = target.replace("/", "_").replace(":", "_").replace("*", "WILDCARD")
        self._dir = SIGNALS_ROOT / safe
        self._dir.mkdir(parents=True, exist_ok=True)
        self._inbox = self._dir / "inbox.jsonl"
        self._processed = self._dir / "processed.jsonl"

    def send(self, signal: Signal):
        """Broadcast a signal. Persisted to inbox for all receiving agents."""
        line = json.dumps(asdict(signal))
        with open(self._inbox, "a") as f:
            f.write(line + "\n")

    def receive(self, agent_name: str, mark_processed: bool = True) -> List[Signal]:
        """Get all signals addressed to this agent (including '*' broadcasts).

        If mark_processed=True, moves them to the processed log after reading.
        """
        if not self._inbox.exists():
            return []

        signals = []
        remaining = []

        for line in self._inbox.read_text().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                to_agents = data.get("to_agents", [])
                if "*" in to_agents or agent_name in to_agents:
                    signals.append(Signal(**data))
                else:
                    remaining.append(line)
            except (json.JSONDecodeError, TypeError):
                remaining.append(line)

        if mark_processed and signals:
            # Append processed to archive
            with open(self._processed, "a") as f:
                for s in signals:
                    f.write(json.dumps(asdict(s)) + "\n")
            # Rewrite inbox with remaining
            self._inbox.write_text("\n".join(remaining) + ("\n" if remaining else ""))

        return signals

    def receive_all(self, agent_name: str) -> List[Signal]:
        """Get all signals (including already-processed)."""
        signals = []
        for path in [self._inbox, self._processed]:
            if path.exists():
                for line in path.read_text().splitlines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        to_agents = data.get("to_agents", [])
                        if "*" in to_agents or agent_name in to_agents:
                            signals.append(Signal(**data))
                    except (json.JSONDecodeError, TypeError):
                        pass
        return signals

    def find_chains(self) -> List[Dict]:
        """Analyze signals for potential exploit chains.

        Looks for CHAIN-type signals and DISCOVERY pairs that combine
        into higher severity.
        """
        chains = []
        all_signals = []

        for path in [self._inbox, self._processed]:
            if path.exists():
                for line in path.read_text().splitlines():
                    if not line.strip():
                        continue
                    try:
                        all_signals.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        # Extract explicit CHAIN signals
        for s in all_signals:
            if s.get("signal_type") == "chain":
                chains.append({
                    "type": "explicit_chain",
                    "chain_type": s.get("signal_data", {}).get("chain_type"),
                    "combined_severity": s.get("signal_data", {}).get("combined_severity"),
                    "bug_a": s.get("signal_data", {}).get("bug_a"),
                    "bug_b": s.get("signal_data", {}).get("bug_b"),
                    "signal_id": s.get("signal_id"),
                })

        # Look for implicit chains (discovery + discovery from different agents
        # targeting the same endpoint)
        discoveries = [s for s in all_signals if s.get("signal_type") == "discovery"]
        for i, d1 in enumerate(discoveries):
            for d2 in discoveries[i+1:]:
                if d1.get("from_agent") == d2.get("from_agent"):
                    continue
                d1_endpoint = d1.get("signal_data", {}).get("endpoint", "")
                d2_endpoint = d2.get("signal_data", {}).get("endpoint", "")
                # Same endpoint root = potential chain
                if d1_endpoint and d2_endpoint:
                    root1 = d1_endpoint.rstrip("0123456789").rstrip("/")
                    root2 = d2_endpoint.rstrip("0123456789").rstrip("/")
                    if root1 == root2 and root1:
                        chains.append({
                            "type": "implicit_chain",
                            "agent_a": d1.get("from_agent"),
                            "agent_b": d2.get("from_agent"),
                            "endpoint_root": root1,
                            "pattern_a": d1.get("signal_data", {}).get("pattern"),
                            "pattern_b": d2.get("signal_data", {}).get("pattern"),
                        })

        return chains

    def get_pending_for(self, agent_name: str) -> List[Signal]:
        """Get only unread signals for an agent."""
        return self.receive(agent_name, mark_processed=False)

    def clear_processed(self):
        """Clear the processed signal archive."""
        if self._processed.exists():
            self._processed.unlink()

    def stats(self) -> Dict:
        """Return signal statistics for this target."""
        inbox_count = 0
        processed_count = 0
        if self._inbox.exists():
            inbox_count = len(self._inbox.read_text().splitlines())
        if self._processed.exists():
            processed_count = len(self._processed.read_text().splitlines())

        chains = self.find_chains()

        return {
            "target": self.target,
            "pending": inbox_count,
            "processed": processed_count,
            "chains_detected": len(chains),
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="BountyForge Agent Bus")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--send", help="JSON signal to send")
    parser.add_argument("--receive", help="Agent name to receive signals for")
    parser.add_argument("--chains", action="store_true", help="Show detected chains")
    parser.add_argument("--stats", action="store_true", help="Show bus stats")
    args = parser.parse_args()

    bus = AgentBus(args.target)

    if args.send:
        data = json.loads(args.send)
        signal = Signal(**data)
        bus.send(signal)
        print(f"[+] Signal sent: {signal.signal_id} ({signal.signal_type})")

    elif args.receive:
        signals = bus.receive(args.receive)
        if not signals:
            print(f"[*] No signals for {args.receive}")
        for s in signals:
            print(f"  [{s.priority.upper()}] {s.signal_type} from {s.from_agent}")
            if s.signal_data:
                print(f"    {json.dumps(s.signal_data, indent=4)[:200]}")

    elif args.chains:
        chains = bus.find_chains()
        if not chains:
            print("[*] No chains detected")
        for c in chains:
            print(f"  [{c['type']}] {c.get('endpoint_root', c.get('bug_a', '?'))}")

    elif args.stats:
        stats = bus.stats()
        for k, v in stats.items():
            print(f"  {k}: {v}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
