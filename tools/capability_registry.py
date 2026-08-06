#!/usr/bin/env python3
"""
BountyForge Capability Registry v3.0.0

Structured catalog of every discovered primitive. A capability is NOT a
vulnerability — it's a building block: "I can control this parameter,"
"I can reach this sink," "I can forge this header."

The registry is queryable by trust boundary, component, capability type,
and discovering agent. It feeds both the trust map and the agent bus.

Usage:
  python3 tools/capability_registry.py --target example.com --register
  python3 tools/capability_registry.py --target example.com --query type=input_control
  python3 tools/capability_registry.py --target example.com --find-cross-boundary-chains
  python3 tools/capability_registry.py --target example.com --report
"""

import json
import sys
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REGISTRY_DIR = ROOT / "state" / "capabilities"

# ---------------------------------------------------------------------------
# Capability taxonomy (from zerodays.md hunting primitives)
# ---------------------------------------------------------------------------

class CapabilityType(str, Enum):
    # Input Control
    PARAMETER_FORGE = "parameter_forge"
    HEADER_FORGE = "header_forge"
    BODY_FORGE = "body_forge"
    METHOD_OVERRIDE = "method_override"
    CONTENT_TYPE_SWITCH = "content_type_switch"
    PATH_SEGMENT_CONTROL = "path_segment_control"

    # Trust Boundary
    AUTH_HEADER_PASSTHROUGH = "auth_header_passthrough"
    ORIGIN_REFLECTION = "origin_reflection"
    COOKIE_SCOPE_LEAK = "cookie_scope_leak"
    REDIRECT_TRUST = "redirect_trust"
    IP_BASED_TRUST = "ip_based_trust"
    INTERNAL_DNS_RESOLUTION = "internal_dns_resolution"

    # Data Flow
    SINK_REACH = "sink_reach"
    REFLECTION_POINT = "reflection_point"
    PERSISTENCE_POINT = "persistence_point"
    DESERIALIZATION_POINT = "deserialization_point"
    TEMPLATE_INJECTION_POINT = "template_injection_point"
    LOG_INJECTION_POINT = "log_injection_point"

    # Side Channel
    TIMING_ORACLE = "timing_oracle"
    ERROR_ORACLE = "error_oracle"
    DNS_ORACLE = "dns_oracle"
    HTTP_CALLBACK = "http_callback"
    CACHE_ORACLE = "cache_oracle"

    # Infrastructure
    METADATA_REACH = "metadata_reach"
    INTERNAL_PORT_OPEN = "internal_port_open"
    FILE_READ_PRIMITIVE = "file_read_primitive"
    FILE_WRITE_PRIMITIVE = "file_write_primitive"
    COMMAND_PRIMITIVE = "command_primitive"
    CI_CD_TRIGGER = "ci_cd_trigger"


# Category mapping for query convenience
CAPABILITY_CATEGORIES = {
    "input_control": [
        CapabilityType.PARAMETER_FORGE, CapabilityType.HEADER_FORGE,
        CapabilityType.BODY_FORGE, CapabilityType.METHOD_OVERRIDE,
        CapabilityType.CONTENT_TYPE_SWITCH, CapabilityType.PATH_SEGMENT_CONTROL,
    ],
    "trust_boundary": [
        CapabilityType.AUTH_HEADER_PASSTHROUGH, CapabilityType.ORIGIN_REFLECTION,
        CapabilityType.COOKIE_SCOPE_LEAK, CapabilityType.REDIRECT_TRUST,
        CapabilityType.IP_BASED_TRUST, CapabilityType.INTERNAL_DNS_RESOLUTION,
    ],
    "data_flow": [
        CapabilityType.SINK_REACH, CapabilityType.REFLECTION_POINT,
        CapabilityType.PERSISTENCE_POINT, CapabilityType.DESERIALIZATION_POINT,
        CapabilityType.TEMPLATE_INJECTION_POINT, CapabilityType.LOG_INJECTION_POINT,
    ],
    "side_channel": [
        CapabilityType.TIMING_ORACLE, CapabilityType.ERROR_ORACLE,
        CapabilityType.DNS_ORACLE, CapabilityType.HTTP_CALLBACK,
        CapabilityType.CACHE_ORACLE,
    ],
    "infrastructure": [
        CapabilityType.METADATA_REACH, CapabilityType.INTERNAL_PORT_OPEN,
        CapabilityType.FILE_READ_PRIMITIVE, CapabilityType.FILE_WRITE_PRIMITIVE,
        CapabilityType.COMMAND_PRIMITIVE, CapabilityType.CI_CD_TRIGGER,
    ],
}

# Trust boundary crossing potential per capability
# (how likely this capability is to cross a trust boundary when chained)
BOUNDARY_CROSSING_POTENTIAL = {
    CapabilityType.AUTH_HEADER_PASSTHROUGH: 0.95,
    CapabilityType.REDIRECT_TRUST: 0.90,
    CapabilityType.IP_BASED_TRUST: 0.85,
    CapabilityType.HEADER_FORGE: 0.80,
    CapabilityType.METADATA_REACH: 0.85,
    CapabilityType.INTERNAL_DNS_RESOLUTION: 0.80,
    CapabilityType.INTERNAL_PORT_OPEN: 0.80,
    CapabilityType.COOKIE_SCOPE_LEAK: 0.75,
    CapabilityType.FILE_READ_PRIMITIVE: 0.65,
    CapabilityType.SINK_REACH: 0.50,
    CapabilityType.COMMAND_PRIMITIVE: 0.50,
    CapabilityType.CI_CD_TRIGGER: 0.70,
    CapabilityType.PARAMETER_FORGE: 0.30,
    CapabilityType.BODY_FORGE: 0.30,
}

# Chain multipliers: when capability type A meets B, what's the severity escalation?
CHAIN_COMPATIBILITY = {
    (CapabilityType.PARAMETER_FORGE, CapabilityType.SINK_REACH): "high",
    (CapabilityType.HEADER_FORGE, CapabilityType.AUTH_HEADER_PASSTHROUGH): "critical",
    (CapabilityType.REDIRECT_TRUST, CapabilityType.ORIGIN_REFLECTION): "high",
    (CapabilityType.HEADER_FORGE, CapabilityType.PERSISTENCE_POINT): "high",
    (CapabilityType.BODY_FORGE, CapabilityType.DESERIALIZATION_POINT): "critical",
    (CapabilityType.METADATA_REACH, CapabilityType.COMMAND_PRIMITIVE): "critical",
    (CapabilityType.FILE_READ_PRIMITIVE, CapabilityType.INTERNAL_PORT_OPEN): "high",
    (CapabilityType.FILE_WRITE_PRIMITIVE, CapabilityType.COMMAND_PRIMITIVE): "critical",
    (CapabilityType.SINK_REACH, CapabilityType.TEMPLATE_INJECTION_POINT): "critical",
    (CapabilityType.INTERNAL_PORT_OPEN, CapabilityType.CI_CD_TRIGGER): "high",
    (CapabilityType.COOKIE_SCOPE_LEAK, CapabilityType.ORIGIN_REFLECTION): "high",
    (CapabilityType.DNS_ORACLE, CapabilityType.METADATA_REACH): "medium",
    (CapabilityType.PARAMETER_FORGE, CapabilityType.REDIRECT_TRUST): "high",
    (CapabilityType.PATH_SEGMENT_CONTROL, CapabilityType.FILE_READ_PRIMITIVE): "high",
    (CapabilityType.PATH_SEGMENT_CONTROL, CapabilityType.FILE_WRITE_PRIMITIVE): "critical",
    (CapabilityType.LOG_INJECTION_POINT, CapabilityType.SINK_REACH): "medium",
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Capability:
    cap_id: str
    cap_type: CapabilityType
    category: str  # input_control, trust_boundary, data_flow, side_channel, infrastructure
    component: str  # endpoint, service, or component name
    parameter: str = ""  # specific parameter/header/field
    value_example: str = ""  # example value that demonstrates the capability
    evidence_hash: str = ""  # BLAKE3/SHA256 of evidence file
    confidence: float = 1.0  # 0.0 to 1.0
    discovering_agent: str = ""
    session_id: str = ""
    endpoint: str = ""
    method: str = "GET"
    trust_boundary: str = ""  # which trust boundary this sits on (if any)
    is_cross_boundary: bool = False  # can this capability cross a trust boundary?
    boundary_crossing_potential: float = 0.0
    notes: str = ""
    discovered_at: str = ""
    metadata: Dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.discovered_at:
            self.discovered_at = datetime.now(timezone.utc).isoformat()
        if not self.cap_id:
            raw = f"{self.component}:{self.cap_type.value}:{self.parameter}:{self.discovered_at}"
            self.cap_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        # Auto-set category from type
        for cat, types in CAPABILITY_CATEGORIES.items():
            if self.cap_type in types:
                self.category = cat
                break
        # Auto-set boundary crossing potential
        if self.boundary_crossing_potential == 0.0:
            self.boundary_crossing_potential = BOUNDARY_CROSSING_POTENTIAL.get(
                self.cap_type, 0.2)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["cap_type"] = self.cap_type.value
        return d


@dataclass
class CapabilityChain:
    """A chain of capabilities that together form an exploit."""
    chain_id: str
    capabilities: List[str]  # cap_ids in order
    chain_type: str = ""  # pre-defined chain pattern or "novel"
    severity: str = "medium"
    description: str = ""
    trust_boundaries_crossed: int = 0
    discovered_at: str = ""
    confirmed: bool = False  # has this chain survived refutation?

    def __post_init__(self):
        if not self.discovered_at:
            self.discovered_at = datetime.now(timezone.utc).isoformat()
        if not self.chain_id:
            raw = "+".join(self.capabilities) + self.discovered_at
            self.chain_id = hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Capability Registry Engine
# ---------------------------------------------------------------------------

class CapabilityRegistry:
    """Structured catalog and chain analysis for capabilities."""

    def __init__(self, target: str):
        self.target = target
        safe = target.replace("/", "_").replace(":", "_").replace("*", "WILDCARD")
        self._dir = REGISTRY_DIR / safe
        self._dir.mkdir(parents=True, exist_ok=True)
        self._caps_file = self._dir / "capabilities.json"
        self._chains_file = self._dir / "chains.json"

    # ---- Registration ----

    def register(self, cap: Capability) -> Capability:
        """Register a discovered capability."""
        caps = self._load_capabilities()

        # Deduplicate: same type + component + parameter = update confidence
        for existing_id, existing in caps.items():
            if (existing.cap_type == cap.cap_type and
                    existing.component == cap.component and
                    existing.parameter == cap.parameter):
                # Update existing — multi-agent confirmation increases confidence
                existing.confidence = min(1.0, existing.confidence + 0.1)
                existing.metadata["confirmed_by"] = (
                    existing.metadata.get("confirmed_by", []) +
                    [cap.discovering_agent]
                )
                caps[existing_id] = existing
                self._save_capabilities(caps)

                # Emit signal if confidence crossed threshold
                if existing.confidence >= 0.9:
                    self._emit_capability_signal(existing, "promotion")
                return existing

        caps[cap.cap_id] = cap
        self._save_capabilities(caps)
        self._emit_capability_signal(cap, "discovery")
        return cap

    def register_batch(self, capabilities: List[Capability]) -> List[Capability]:
        """Register multiple capabilities at once."""
        return [self.register(c) for c in capabilities]

    def get(self, cap_id: str) -> Optional[Capability]:
        return self._load_capabilities().get(cap_id)

    # ---- Querying ----

    def query(self,
              cap_type: CapabilityType = None,
              category: str = None,
              component: str = None,
              agent: str = None,
              min_confidence: float = 0.0,
              is_cross_boundary: bool = None,
              min_boundary_potential: float = 0.0) -> List[Capability]:
        """Query capabilities with filters."""
        caps = self._load_capabilities().values()
        results = []

        for c in caps:
            if cap_type and c.cap_type != cap_type:
                continue
            if category and c.category != category:
                continue
            if component and component not in c.component:
                continue
            if agent and c.discovering_agent != agent:
                continue
            if c.confidence < min_confidence:
                continue
            if is_cross_boundary is not None and c.is_cross_boundary != is_cross_boundary:
                continue
            if c.boundary_crossing_potential < min_boundary_potential:
                continue
            results.append(c)

        return sorted(results, key=lambda c: c.confidence, reverse=True)

    def get_by_component(self, component: str) -> List[Capability]:
        return self.query(component=component)

    def get_by_agent(self, agent: str) -> List[Capability]:
        return self.query(agent=agent)

    def get_high_confidence(self, threshold: float = 0.8) -> List[Capability]:
        return self.query(min_confidence=threshold)

    def get_cross_boundary_capabilities(self) -> List[Capability]:
        return self.query(is_cross_boundary=True)

    def get_untrusted(self) -> List[Capability]:
        """Capabilities that haven't been confirmed by multiple agents."""
        caps = self._load_capabilities().values()
        return [c for c in caps
                if len(c.metadata.get("confirmed_by", [])) < 1
                and c.confidence < 0.8]

    # ---- Chain Discovery ----

    def find_chains(self) -> List[CapabilityChain]:
        """Discover exploit chains from registered capabilities.

        A chain exists when two capabilities from different components
        have a known chain compatibility.
        """
        caps = list(self._load_capabilities().values())
        chains = []
        seen_pairs = set()

        for i, cap_a in enumerate(caps):
            for j, cap_b in enumerate(caps):
                if i >= j:
                    continue
                if cap_a.component == cap_b.component:
                    continue  # Same component — not a cross-service chain

                pair = (cap_a.cap_type, cap_b.cap_type)
                reverse_pair = (cap_b.cap_type, cap_a.cap_type)

                # Check known compatibility
                severity = None
                if pair in CHAIN_COMPATIBILITY:
                    severity = CHAIN_COMPATIBILITY[pair]
                elif reverse_pair in CHAIN_COMPATIBILITY:
                    severity = CHAIN_COMPATIBILITY[reverse_pair]

                if severity and pair not in seen_pairs:
                    seen_pairs.add(pair)
                    seen_pairs.add(reverse_pair)

                    boundaries = (1 if cap_a.is_cross_boundary else 0) + \
                                 (1 if cap_b.is_cross_boundary else 0)

                    chain = CapabilityChain(
                        chain_id="",
                        capabilities=[cap_a.cap_id, cap_b.cap_id],
                        chain_type="known_compatible",
                        severity=severity,
                        description=(
                            f"{cap_a.cap_type.value} ({cap_a.component}) + "
                            f"{cap_b.cap_type.value} ({cap_b.component}) = "
                            f"{severity.upper()} exploit chain"
                        ),
                        trust_boundaries_crossed=boundaries,
                    )
                    chains.append(chain)

        # Also discover novel chains (high boundary-crossing potential pairs)
        cross_caps = [c for c in caps if c.boundary_crossing_potential >= 0.7]
        for i, cap_a in enumerate(cross_caps):
            for cap_b in cross_caps[i+1:]:
                if cap_a.component == cap_b.component:
                    continue
                pair = (cap_a.cap_type, cap_b.cap_type)
                reverse_pair = (cap_b.cap_type, cap_a.cap_type)
                if pair in seen_pairs or reverse_pair in seen_pairs:
                    continue

                # Novel chain: two high-boundary-crossing capabilities
                avg_potential = (cap_a.boundary_crossing_potential +
                                 cap_b.boundary_crossing_potential) / 2
                if avg_potential >= 0.8:
                    seen_pairs.add(pair)
                    chain = CapabilityChain(
                        chain_id="",
                        capabilities=[cap_a.cap_id, cap_b.cap_id],
                        chain_type="novel_high_potential",
                        severity="high" if avg_potential >= 0.85 else "medium",
                        description=(
                            f"NOVEL: {cap_a.cap_type.value} ({cap_a.component}) + "
                            f"{cap_b.cap_type.value} ({cap_b.component}) — "
                            f"high boundary crossing potential ({avg_potential:.0%})"
                        ),
                        trust_boundaries_crossed=1,
                    )
                    chains.append(chain)

        self._save_chains(chains)

        # Emit chain signals to agent bus
        for chain in chains:
            if chain.severity in ("critical", "high"):
                self._emit_chain_signal(chain)

        return sorted(chains, key=lambda c: (
            {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(c.severity, 1)
        ), reverse=True)

    def get_chains(self) -> List[CapabilityChain]:
        return self._load_chains()

    def get_chains_by_severity(self, severity: str) -> List[CapabilityChain]:
        return [c for c in self._load_chains() if c.severity == severity]

    # ---- Coverage Analysis ----

    def get_coverage(self) -> Dict:
        """Return capability coverage across all categories."""
        caps = self._load_capabilities().values()
        coverage = {
            "total_capabilities": len(caps),
            "by_category": defaultdict(int),
            "by_type": defaultdict(int),
            "by_agent": defaultdict(int),
            "by_component": defaultdict(int),
            "high_confidence": 0,
            "cross_boundary": 0,
            "gaps": [],
        }

        for c in caps:
            coverage["by_category"][c.category] += 1
            coverage["by_type"][c.cap_type.value] += 1
            coverage["by_agent"][c.discovering_agent] += 1
            coverage["by_component"][c.component] += 1
            if c.confidence >= 0.8:
                coverage["high_confidence"] += 1
            if c.is_cross_boundary:
                coverage["cross_boundary"] += 1

        # Find gaps: categories with zero capabilities
        for category in CAPABILITY_CATEGORIES:
            if category not in coverage["by_category"]:
                coverage["gaps"].append({
                    "category": category,
                    "severity": "high",
                    "message": f"No capabilities discovered in {category}. "
                               f"Deploy relevant agent.",
                })

        # Find types with zero capabilities
        for cat, types in CAPABILITY_CATEGORIES.items():
            for t in types:
                if t.value not in coverage["by_type"]:
                    coverage["gaps"].append({
                        "type": t.value,
                        "category": cat,
                        "severity": "medium",
                        "message": f"No {t.value} capability discovered.",
                    })

        return dict(coverage)

    # ---- Reporting ----

    def generate_report(self) -> str:
        caps = self._load_capabilities().values()
        chains = self._load_chains()
        coverage = self.get_coverage()

        lines = [
            "=" * 72,
            f"  CAPABILITY REGISTRY REPORT — {self.target}",
            "=" * 72,
            f"  Generated: {datetime.now(timezone.utc).isoformat()}",
            f"  Total capabilities: {coverage['total_capabilities']}",
            f"  High confidence (≥0.8): {coverage['high_confidence']}",
            f"  Cross-boundary: {coverage['cross_boundary']}",
            f"  Chains discovered: {len(chains)}",
            "=" * 72,
            "",
            "## Capabilities by Category",
            "",
        ]

        for cat, types in CAPABILITY_CATEGORIES.items():
            cat_caps = [c for c in caps if c.category == cat]
            if cat_caps:
                lines.append(f"### {cat.replace('_', ' ').title()} ({len(cat_caps)})")
                for c in sorted(cat_caps, key=lambda x: x.confidence, reverse=True):
                    conf_bar = "█" * int(c.confidence * 10) + "░" * (10 - int(c.confidence * 10))
                    cross = " ⚡CROSS" if c.is_cross_boundary else ""
                    lines.append(
                        f"  [{c.confidence:.1f}] {conf_bar} "
                        f"{c.cap_type.value} @ {c.component}{cross}")
                    if c.parameter:
                        lines.append(f"      param: {c.parameter}")
                    lines.append(f"      agent: {c.discovering_agent}")
                lines.append("")

        lines.append("## Exploit Chains")
        lines.append("")
        if chains:
            for c in sorted(chains, key=lambda x: (
                {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(x.severity, 1)
            ), reverse=True):
                lines.append(f"  [{c.severity.upper()}] {c.chain_type}")
                lines.append(f"    {c.description}")
                lines.append(f"    Boundaries crossed: {c.trust_boundaries_crossed}")
                lines.append("")
        else:
            lines.append("  No chains discovered yet.")
            lines.append("  Register more capabilities across different components.")
            lines.append("")

        lines.append("## Coverage Gaps")
        lines.append("")
        if coverage["gaps"]:
            for gap in coverage["gaps"]:
                lines.append(f"  [{gap.get('severity', 'medium').upper()}] {gap['message']}")
        else:
            lines.append("  All capability categories have at least one entry.")
        lines.append("")

        lines.append("=" * 72)
        lines.append("  Generated by BountyForge Capability Registry v3.0.0")
        lines.append("=" * 72)

        return "\n".join(lines)

    # ---- Persistence ----

    def _load_capabilities(self) -> Dict[str, Capability]:
        if self._caps_file.exists():
            raw = json.loads(self._caps_file.read_text())
            caps = {}
            for k, v in raw.items():
                if "cap_type" in v and isinstance(v["cap_type"], str):
                    v["cap_type"] = CapabilityType(v["cap_type"])
                caps[k] = Capability(**v)
            return caps
        return {}

    def _save_capabilities(self, caps: Dict[str, Capability]):
        data = {k: asdict(v) for k, v in caps.items()}
        # Convert enum values back to strings for JSON
        for v in data.values():
            if isinstance(v.get("cap_type"), CapabilityType):
                v["cap_type"] = v["cap_type"].value
        self._caps_file.write_text(json.dumps(data, indent=2))

    def _load_chains(self) -> List[CapabilityChain]:
        if self._chains_file.exists():
            raw = json.loads(self._chains_file.read_text())
            return [CapabilityChain(**c) for c in raw]
        return []

    def _save_chains(self, chains: List[CapabilityChain]):
        data = [asdict(c) for c in chains]
        self._chains_file.write_text(json.dumps(data, indent=2))

    def _emit_capability_signal(self, cap: Capability, signal_type: str):
        """Emit discovery/promotion signal to agent bus."""
        try:
            from tools.agent_bus import AgentBus, Signal
            bus = AgentBus(self.target)
            bus.send(Signal(
                signal_type=signal_type,
                from_agent=cap.discovering_agent,
                to_agents=["*"],
                priority="high" if cap.boundary_crossing_potential >= 0.8 else "medium",
                finding_ref=cap.cap_id,
                signal_data={
                    "capability_id": cap.cap_id,
                    "capability_type": cap.cap_type.value,
                    "component": cap.component,
                    "parameter": cap.parameter,
                    "confidence": cap.confidence,
                    "is_cross_boundary": cap.is_cross_boundary,
                    "boundary_potential": cap.boundary_crossing_potential,
                }
            ))
        except ImportError:
            pass

    def _emit_chain_signal(self, chain: CapabilityChain):
        """Emit chain discovery signal to agent bus."""
        try:
            from tools.agent_bus import AgentBus, Signal
            bus = AgentBus(self.target)
            bus.send(Signal(
                signal_type="chain",
                from_agent="capability-registry",
                to_agents=["*"],
                priority="critical" if chain.severity == "critical" else "high",
                finding_ref=chain.chain_id,
                signal_data={
                    "chain_id": chain.chain_id,
                    "chain_type": chain.chain_type,
                    "severity": chain.severity,
                    "capabilities": chain.capabilities,
                    "trust_boundaries_crossed": chain.trust_boundaries_crossed,
                }
            ))
        except ImportError:
            pass

    def delete_all(self):
        for f in [self._caps_file, self._chains_file]:
            if f.exists():
                f.unlink()


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

_registry_instances: Dict[str, CapabilityRegistry] = {}

def get_registry(target: str) -> CapabilityRegistry:
    if target not in _registry_instances:
        _registry_instances[target] = CapabilityRegistry(target)
    return _registry_instances[target]


def register_capability(target: str, cap_type: CapabilityType, component: str,
                        **kwargs) -> Capability:
    """Quick registration from agent code."""
    reg = get_registry(target)
    cap = Capability(cap_id="", cap_type=cap_type, component=component,
                     category="", **kwargs)
    return reg.register(cap)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BountyForge Capability Registry")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--register", help="Register a capability (JSON)")
    parser.add_argument("--register-batch", help="Register capabilities (JSON array)")
    parser.add_argument("--query", help="Query filter expression")
    parser.add_argument("--query-type", help="Filter by capability type")
    parser.add_argument("--query-category", help="Filter by category")
    parser.add_argument("--query-component", help="Filter by component")
    parser.add_argument("--query-agent", help="Filter by discovering agent")
    parser.add_argument("--min-confidence", type=float, default=0.0)
    parser.add_argument("--find-chains", action="store_true",
                        help="Discover exploit chains")
    parser.add_argument("--coverage", action="store_true",
                        help="Show coverage analysis")
    parser.add_argument("--report", action="store_true", help="Generate full report")
    parser.add_argument("--output-format", default="text", choices=["text", "json"])
    args = parser.parse_args()

    reg = CapabilityRegistry(args.target)

    if args.register:
        data = json.loads(args.register)
        if "cap_type" in data and isinstance(data["cap_type"], str):
            data["cap_type"] = CapabilityType(data["cap_type"])
        cap = Capability(**data)
        reg.register(cap)
        print(f"[+] Capability registered: {cap.cap_id}")
        print(f"    Type: {cap.cap_type.value}")
        print(f"    Component: {cap.component}")
        print(f"    Confidence: {cap.confidence}")

    elif args.register_batch:
        caps_data = json.loads(args.register_batch)
        caps = []
        for d in caps_data:
            if "cap_type" in d and isinstance(d["cap_type"], str):
                d["cap_type"] = CapabilityType(d["cap_type"])
            caps.append(Capability(**d))
        results = reg.register_batch(caps)
        print(f"[+] Registered {len(results)} capabilities")

    elif args.query or args.query_type or args.query_category:
        results = reg.query(
            cap_type=CapabilityType(args.query_type) if args.query_type else None,
            category=args.query_category,
            component=args.query_component,
            agent=args.query_agent,
            min_confidence=args.min_confidence,
        )
        if args.output_format == "json":
            print(json.dumps([asdict(c) for c in results], indent=2, default=str))
        else:
            print(f"[*] Query results: {len(results)}")
            for c in results:
                print(f"  [{c.confidence:.1f}] {c.cap_type.value} @ {c.component} "
                      f"({c.discovering_agent})")

    elif args.find_chains:
        chains = reg.find_chains()
        if args.output_format == "json":
            print(json.dumps([asdict(c) for c in chains], indent=2))
        else:
            print(f"[*] Chains discovered: {len(chains)}")
            for c in chains:
                print(f"  [{c.severity.upper()}] {c.chain_type}")
                print(f"    {c.description}")

    elif args.coverage:
        coverage = reg.get_coverage()
        if args.output_format == "json":
            print(json.dumps(coverage, indent=2, default=str))
        else:
            print(f"[*] Coverage: {coverage['total_capabilities']} capabilities")
            print(f"    High confidence: {coverage['high_confidence']}")
            print(f"    Cross-boundary: {coverage['cross_boundary']}")
            print(f"    Gaps: {len(coverage['gaps'])}")
            for gap in coverage["gaps"]:
                print(f"    [!] {gap['message']}")

    elif args.report:
        print(reg.generate_report())

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
