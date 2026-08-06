#!/usr/bin/env python3
"""
BountyForge Trust Map Engine v3.0.0

Builds and maintains a directed graph of trust relationships across a target.
Nodes = components, services, endpoints, roles, data stores.
Edges = trust relationships (who trusts whom, for what, how strongly).

When Agent A discovers a capability on component X and Agent B discovers that
component Y trusts X unconditionally, the trust map fires a chain signal across
the agent bus — this is the multiplier that turns individual primitives into
exploit chains.

Usage:
  python3 tools/trust_map.py --target example.com --init
  python3 tools/trust_map.py --target example.com --add-node api --type service
  python3 tools/trust_map.py --target example.com --add-edge api internal-db --trust-type "no-auth"
  python3 tools/trust_map.py --target example.com --find-crossings
  python3 tools/trust_map.py --target example.com --report
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

TRUST_MAP_DIR = ROOT / "state" / "trust_maps"

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TrustNode:
    node_id: str
    name: str
    node_type: str  # service, endpoint, role, datastore, external, auth_provider, cdn, proxy, gateway
    host: str = ""
    port: int = 0
    protocol: str = ""  # http, grpc, tcp, udp
    auth_required: bool = True
    auth_method: str = ""  # cookie, bearer, oauth, mtls, none
    is_public: bool = False
    is_authenticated: bool = False  # does this node have its own auth context
    metadata: Dict = field(default_factory=dict)
    capabilities: List[str] = field(default_factory=list)  # capability_ids from registry

    def __hash__(self):
        return hash(self.node_id)


@dataclass
class TrustEdge:
    edge_id: str
    from_node: str  # trustor (who trusts)
    to_node: str    # trustee (who is trusted)
    trust_type: str  # full_trust, header_based, ip_based, token_based, no_auth, redirect_trust, cookie_trust, cors_trust, internal_skip
    trust_strength: float  # 0.0 (no trust) to 1.0 (full implicit trust)
    description: str = ""
    evidence: str = ""  # how was this trust relationship discovered?
    is_conditional: bool = False
    condition: str = ""  # e.g. "only when X-Forwarded-For matches 10.0.0.0/8"
    is_cross_boundary: bool = False  # crosses a security boundary (public→private, user→admin, etc.)
    boundary_type: str = ""  # public_to_private, user_to_admin, service_to_service, external_to_internal
    metadata: Dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.edge_id:
            raw = f"{self.from_node}->{self.to_node}:{self.trust_type}"
            self.edge_id = hashlib.sha256(raw.encode()).hexdigest()[:12]


@dataclass
class TrustBoundary:
    boundary_id: str
    name: str
    boundary_type: str  # public_private, authenticated_internal, admin_boundary, service_boundary, data_boundary
    inside_nodes: List[str] = field(default_factory=list)   # nodes in the trusted zone
    outside_nodes: List[str] = field(default_factory=list)  # nodes outside the trusted zone
    crossing_edges: List[str] = field(default_factory=list)  # edge_ids that cross this boundary

    def __post_init__(self):
        if not self.boundary_id:
            raw = f"{self.name}:{self.boundary_type}"
            self.boundary_id = hashlib.sha256(raw.encode()).hexdigest()[:12]


@dataclass
class TrustCrossing:
    """A capability chain that crosses a trust boundary."""
    crossing_id: str
    boundary: str  # boundary_id
    from_node: str  # outside node (attacker position)
    to_node: str    # inside node (target)
    edge: str       # the trust edge being exploited
    capability_from: str = ""  # capability_id on the from_node
    capability_to: str = ""    # capability_id on the to_node
    severity: str = "medium"   # escalated severity of this crossing
    chain_candidates: List[Dict] = field(default_factory=list)
    discovered_at: str = ""

    def __post_init__(self):
        if not self.discovered_at:
            self.discovered_at = datetime.now(timezone.utc).isoformat()
        if not self.crossing_id:
            raw = f"{self.from_node}>{self.to_node}:{self.boundary}"
            self.crossing_id = hashlib.sha256(raw.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Trust Map Engine
# ---------------------------------------------------------------------------

class TrustMap:
    """Directed trust graph for a target."""

    def __init__(self, target: str):
        self.target = target
        safe = target.replace("/", "_").replace(":", "_").replace("*", "WILDCARD")
        self._dir = TRUST_MAP_DIR / safe
        self._dir.mkdir(parents=True, exist_ok=True)
        self._nodes_file = self._dir / "nodes.json"
        self._edges_file = self._dir / "edges.json"
        self._boundaries_file = self._dir / "boundaries.json"
        self._crossings_file = self._dir / "crossings.json"

    # ---- Nodes ----

    def add_node(self, node: TrustNode) -> TrustNode:
        nodes = self._load_nodes()
        if node.node_id in nodes:
            existing = nodes[node.node_id]
            existing.capabilities = list(set(existing.capabilities + node.capabilities))
            existing.metadata.update(node.metadata)
            nodes[node.node_id] = existing
        else:
            nodes[node.node_id] = node
        self._save_nodes(nodes)
        return nodes[node.node_id]

    def get_node(self, node_id: str) -> Optional[TrustNode]:
        return self._load_nodes().get(node_id)

    def get_nodes_by_type(self, node_type: str) -> List[TrustNode]:
        return [n for n in self._load_nodes().values() if n.node_type == node_type]

    def get_nodes_in_boundary(self, boundary_id: str) -> List[TrustNode]:
        boundary = self.get_boundary(boundary_id)
        if not boundary:
            return []
        nodes = self._load_nodes()
        result = []
        for nid in boundary.inside_nodes:
            if nid in nodes:
                result.append(nodes[nid])
        return result

    def attach_capability(self, node_id: str, capability_id: str):
        """Attach a capability from the registry to a trust map node."""
        node = self.get_node(node_id)
        if node:
            if capability_id not in node.capabilities:
                node.capabilities.append(capability_id)
                self.add_node(node)

    # ---- Edges ----

    def add_edge(self, edge: TrustEdge) -> TrustEdge:
        edges = self._load_edges()
        edges[edge.edge_id] = edge
        self._save_edges(edges)
        # Re-evaluate boundary crossings when a new edge is added
        self._detect_crossings_for_edge(edge)
        return edge

    def get_edge(self, edge_id: str) -> Optional[TrustEdge]:
        return self._load_edges().get(edge_id)

    def get_edges_from(self, node_id: str) -> List[TrustEdge]:
        return [e for e in self._load_edges().values() if e.from_node == node_id]

    def get_edges_to(self, node_id: str) -> List[TrustEdge]:
        return [e for e in self._load_edges().values() if e.to_node == node_id]

    def find_path(self, from_node: str, to_node: str) -> List[List[TrustEdge]]:
        """Find all trust paths from one node to another (BFS)."""
        edges = self._load_edges()
        adj = defaultdict(list)
        for e in edges.values():
            adj[e.from_node].append(e)

        paths = []
        queue = [(from_node, [])]
        visited = set()

        while queue:
            current, path = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            if current == to_node:
                paths.append(path)
                continue

            for edge in adj.get(current, []):
                if edge.to_node not in visited:
                    queue.append((edge.to_node, path + [edge]))

        return paths

    # ---- Boundaries ----

    def add_boundary(self, boundary: TrustBoundary) -> TrustBoundary:
        boundaries = self._load_boundaries()
        boundaries[boundary.boundary_id] = boundary
        self._save_boundaries(boundaries)
        return boundary

    def get_boundary(self, boundary_id: str) -> Optional[TrustBoundary]:
        return self._load_boundaries().get(boundary_id)

    def get_all_boundaries(self) -> List[TrustBoundary]:
        return list(self._load_boundaries().values())

    def _detect_boundary_crossings(self, edge: TrustEdge) -> bool:
        """Check if an edge crosses a security boundary."""
        nodes = self._load_nodes()
        from_n = nodes.get(edge.from_node)
        to_n = nodes.get(edge.to_node)

        if not from_n or not to_n:
            return False

        # Public → Private
        if from_n.is_public and not to_n.is_public:
            return True
        # Unauthenticated → Authenticated
        if not from_n.is_authenticated and to_n.is_authenticated:
            return True
        # User role → Admin role
        if (from_n.node_type == "role" and to_n.node_type == "role" and
                from_n.name in ("user", "member", "viewer") and
                to_n.name in ("admin", "owner", "operator")):
            return True

        return False

    # ---- Crossings ----

    def _detect_crossings_for_edge(self, edge: TrustEdge):
        """When a new edge is added, check if it creates dangerous boundary crossings."""
        if not edge.is_cross_boundary:
            return

        boundaries = self._load_boundaries()
        nodes = self._load_nodes()
        from_node = nodes.get(edge.from_node)
        to_node = nodes.get(edge.to_node)

        if not from_node or not to_node:
            return

        for boundary in boundaries.values():
            # Does this edge cross this specific boundary?
            from_inside = edge.from_node in boundary.inside_nodes
            to_inside = edge.to_node in boundary.inside_nodes
            from_outside = edge.from_node in boundary.outside_nodes
            to_outside = edge.to_node in boundary.outside_nodes

            if (from_outside and to_inside) or (from_inside and to_outside):
                # This edge crosses the boundary
                crossing = TrustCrossing(
                    crossing_id="",
                    boundary=boundary.boundary_id,
                    from_node=edge.from_node,
                    to_node=edge.to_node,
                    edge=edge.edge_id,
                    capability_from=from_node.capabilities[-1] if from_node.capabilities else "",
                    capability_to=to_node.capabilities[-1] if to_node.capabilities else "",
                    severity=self._assess_crossing_severity(edge, boundary),
                )
                self._save_crossing(crossing)
                boundary.crossing_edges.append(edge.edge_id)
                if edge.edge_id not in boundary.crossing_edges:
                    boundaries[boundary.boundary_id] = boundary
                    self._save_boundaries(boundaries)

                # Emit agent bus signal if available
                try:
                    from tools.agent_bus import AgentBus, Signal
                    bus = AgentBus(self.target)
                    bus.send(Signal(
                        signal_type="chain",
                        from_agent="trust-map-engine",
                        to_agents=["*"],
                        priority="high",
                        finding_ref=crossing.crossing_id,
                        signal_data={
                            "crossing_id": crossing.crossing_id,
                            "boundary": boundary.name,
                            "from_node": edge.from_node,
                            "to_node": edge.to_node,
                            "severity": crossing.severity,
                            "chain_type": f"trust_crossing_{boundary.boundary_type}",
                        }
                    ))
                except ImportError:
                    pass

    def _assess_crossing_severity(self, edge: TrustEdge, boundary: TrustBoundary) -> str:
        """Assess how dangerous a boundary crossing is."""
        score = 0.0
        score += edge.trust_strength * 2  # Higher trust = more dangerous when exploited
        if boundary.boundary_type == "public_private":
            score += 1.5
        if boundary.boundary_type == "admin_boundary":
            score += 1.5
        if edge.trust_type in ("no_auth", "ip_based", "header_based"):
            score += 1.0
        if edge.trust_type == "internal_skip":
            score += 2.0

        if score >= 3.5:
            return "critical"
        elif score >= 2.5:
            return "high"
        elif score >= 1.5:
            return "medium"
        return "low"

    def find_all_crossings(self) -> List[TrustCrossing]:
        """Return all detected trust boundary crossings."""
        return self._load_crossings()

    def find_crossings_by_boundary(self, boundary_id: str) -> List[TrustCrossing]:
        return [c for c in self._load_crossings() if c.boundary == boundary_id]

    def find_chains_from_crossings(self) -> List[Dict]:
        """Analyze crossings for exploitable chains.

        A chain exists when:
        1. An outside node has a capability (attacker primitive)
        2. A trust edge crosses a boundary
        3. An inside node has a capability (what the attacker can reach)
        """
        chains = []
        crossings = self._load_crossings()
        nodes = self._load_nodes()

        for crossing in crossings:
            from_node = nodes.get(crossing.from_node)
            to_node = nodes.get(crossing.to_node)

            if not from_node or not to_node:
                continue

            # If the outside node has capabilities AND the inside node has capabilities
            if from_node.capabilities and to_node.capabilities:
                chains.append({
                    "crossing_id": crossing.crossing_id,
                    "boundary": crossing.boundary,
                    "severity": crossing.severity,
                    "attacker_primitives": from_node.capabilities,
                    "target_primitives": to_node.capabilities,
                    "attack_path": f"{crossing.from_node} → {crossing.to_node} "
                                   f"(via {crossing.edge})",
                    "description": (
                        f"Attacker on {from_node.name} ({from_node.node_type}) "
                        f"exploits trust from {to_node.name} ({to_node.node_type}) "
                        f"to cross {crossing.boundary}"
                    ),
                })

        return sorted(chains, key=lambda c: (
            {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(c["severity"], 1)
        ), reverse=True)

    def generate_report(self) -> str:
        """Generate a human-readable trust map report."""
        nodes = self._load_nodes()
        edges = self._load_edges()
        boundaries = self._load_boundaries()
        crossings = self._load_crossings()
        chains = self.find_chains_from_crossings()

        lines = [
            "=" * 72,
            f"  TRUST MAP REPORT — {self.target}",
            "=" * 72,
            f"  Generated: {datetime.now(timezone.utc).isoformat()}",
            f"  Nodes: {len(nodes)}",
            f"  Edges: {len(edges)}",
            f"  Boundaries: {len(boundaries)}",
            f"  Crossings detected: {len(crossings)}",
            f"  Exploitable chains: {len(chains)}",
            "=" * 72,
            "",
            "## Trust Boundaries",
            "",
        ]

        for b in boundaries.values():
            lines.append(f"### {b.name} ({b.boundary_type})")
            lines.append(f"    Inside: {', '.join(b.inside_nodes) or 'none'}")
            lines.append(f"    Outside: {', '.join(b.outside_nodes) or 'none'}")
            lines.append(f"    Crossings: {len(b.crossing_edges)}")
            lines.append("")

        lines.append("## Nodes")
        lines.append("")
        for n in sorted(nodes.values(), key=lambda x: x.node_type + x.name):
            caps = f" [{len(n.capabilities)} capabilities]" if n.capabilities else ""
            pub = " [PUBLIC]" if n.is_public else ""
            auth = " [AUTH]" if n.is_authenticated else ""
            lines.append(f"  [{n.node_type}] {n.name}{pub}{auth}{caps}")
        lines.append("")

        lines.append("## Trust Edges")
        lines.append("")
        for e in sorted(edges.values(), key=lambda x: x.trust_strength, reverse=True):
            cross = " ⚡CROSSES BOUNDARY" if e.is_cross_boundary else ""
            lines.append(
                f"  {e.from_node} ──[{e.trust_type}: {e.trust_strength:.1f}]──▶ "
                f"{e.to_node}{cross}")
        lines.append("")

        lines.append("## Boundary Crossings (Exploitable)")
        lines.append("")
        if crossings:
            for c in sorted(crossings, key=lambda x: (
                {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(x.severity, 1)
            ), reverse=True):
                lines.append(f"  [{c.severity.upper()}] {c.from_node} → {c.to_node}")
                lines.append(f"    Boundary: {c.boundary}")
                lines.append(f"    Edge: {c.edge}")
                if c.capability_from:
                    lines.append(f"    Attacker capability: {c.capability_from}")
                if c.capability_to:
                    lines.append(f"    Target capability: {c.capability_to}")
                lines.append("")
        else:
            lines.append("  No crossings detected yet.")
            lines.append("  Add edges with is_cross_boundary=true to detect crossings.")
            lines.append("")

        lines.append("## Chain Candidates")
        lines.append("")
        if chains:
            for i, chain in enumerate(chains):
                lines.append(f"  Chain {i+1}: [{chain['severity'].upper()}]")
                lines.append(f"    Path: {chain['attack_path']}")
                lines.append(f"    {chain['description']}")
                lines.append("")
        else:
            lines.append("  No chains detected yet.")
            lines.append("  Attach capabilities to nodes to enable chain detection.")
            lines.append("")

        lines.append("=" * 72)
        lines.append("  Generated by BountyForge Trust Map Engine v3.0.0")
        lines.append("=" * 72)

        return "\n".join(lines)

    # ---- Persistence ----

    def _load_nodes(self) -> Dict[str, TrustNode]:
        if self._nodes_file.exists():
            raw = json.loads(self._nodes_file.read_text())
            return {k: TrustNode(**v) for k, v in raw.items()}
        return {}

    def _save_nodes(self, nodes: Dict[str, TrustNode]):
        data = {k: asdict(v) for k, v in nodes.items()}
        self._nodes_file.write_text(json.dumps(data, indent=2))

    def _load_edges(self) -> Dict[str, TrustEdge]:
        if self._edges_file.exists():
            raw = json.loads(self._edges_file.read_text())
            return {k: TrustEdge(**v) for k, v in raw.items()}
        return {}

    def _save_edges(self, edges: Dict[str, TrustEdge]):
        data = {k: asdict(v) for k, v in edges.items()}
        self._edges_file.write_text(json.dumps(data, indent=2))

    def _load_boundaries(self) -> Dict[str, TrustBoundary]:
        if self._boundaries_file.exists():
            raw = json.loads(self._boundaries_file.read_text())
            return {k: TrustBoundary(**v) for k, v in raw.items()}
        return {}

    def _save_boundaries(self, boundaries: Dict[str, TrustBoundary]):
        data = {k: asdict(v) for k, v in boundaries.items()}
        self._boundaries_file.write_text(json.dumps(data, indent=2))

    def _load_crossings(self) -> List[TrustCrossing]:
        if self._crossings_file.exists():
            raw = json.loads(self._crossings_file.read_text())
            return [TrustCrossing(**c) for c in raw]
        return []

    def _save_crossing(self, crossing: TrustCrossing):
        crossings = self._load_crossings()
        # Deduplicate
        existing_ids = {c.crossing_id for c in crossings}
        if crossing.crossing_id not in existing_ids:
            crossings.append(crossing)
            data = [asdict(c) for c in crossings]
            self._crossings_file.write_text(json.dumps(data, indent=2))

    def _save_crossings(self, crossings: List[TrustCrossing]):
        data = [asdict(c) for c in crossings]
        self._crossings_file.write_text(json.dumps(data, indent=2))

    def delete_all(self):
        """Wipe trust map for this target."""
        for f in [self._nodes_file, self._edges_file, self._boundaries_file, self._crossings_file]:
            if f.exists():
                f.unlink()


# ---------------------------------------------------------------------------
# Quick bootstrap from recon output
# ---------------------------------------------------------------------------

def bootstrap_from_recon(target: str, endpoints_file: str = None, recon_dir: str = None) -> TrustMap:
    """Quickly bootstrap a trust map from recon output.

    Creates nodes for each service type discovered.
    """
    tm = TrustMap(target)

    # Default architecture assumptions (refined as more data arrives)
    tm.add_node(TrustNode(
        node_id=f"{target}-web", name="Web Server", node_type="service",
        host=target, is_public=True, is_authenticated=False, auth_required=False,
        metadata={"source": "bootstrap"},
    ))
    tm.add_node(TrustNode(
        node_id=f"{target}-api", name="API Backend", node_type="service",
        host=target, is_public=False, is_authenticated=True, auth_required=True,
        metadata={"source": "bootstrap"},
    ))
    tm.add_node(TrustNode(
        node_id=f"{target}-db", name="Database", node_type="datastore",
        is_public=False, is_authenticated=True,
        metadata={"source": "bootstrap"},
    ))
    tm.add_node(TrustNode(
        node_id=f"{target}-auth", name="Auth Service", node_type="auth_provider",
        is_public=False, is_authenticated=True,
        metadata={"source": "bootstrap"},
    ))
    tm.add_node(TrustNode(
        node_id=f"{target}-cdn", name="CDN", node_type="cdn",
        is_public=True, is_authenticated=False, auth_required=False,
        metadata={"source": "bootstrap"},
    ))

    # Default trust edges
    tm.add_edge(TrustEdge(
        edge_id="", from_node=f"{target}-web", to_node=f"{target}-api",
        trust_type="full_trust", trust_strength=0.9,
        description="Web server proxies to API backend",
        is_cross_boundary=True, boundary_type="public_to_private",
    ))
    tm.add_edge(TrustEdge(
        edge_id="", from_node=f"{target}-api", to_node=f"{target}-db",
        trust_type="token_based", trust_strength=0.7,
        description="API accesses database with service credentials",
        is_cross_boundary=False,
    ))
    tm.add_edge(TrustEdge(
        edge_id="", from_node=f"{target}-api", to_node=f"{target}-auth",
        trust_type="token_based", trust_strength=0.8,
        description="API validates sessions against auth service",
        is_cross_boundary=False,
    ))
    tm.add_edge(TrustEdge(
        edge_id="", from_node=f"{target}-web", to_node=f"{target}-cdn",
        trust_type="header_based", trust_strength=0.6,
        description="CDN caches responses based on web server headers",
        is_cross_boundary=True, boundary_type="public_to_private",
    ))

    # Add default boundaries
    tm.add_boundary(TrustBoundary(
        boundary_id="",
        name="Public → Private",
        boundary_type="public_private",
        inside_nodes=[f"{target}-api", f"{target}-db", f"{target}-auth"],
        outside_nodes=[f"{target}-web", f"{target}-cdn"],
    ))
    tm.add_boundary(TrustBoundary(
        boundary_id="",
        name="User → Admin",
        boundary_type="admin_boundary",
        inside_nodes=[],
        outside_nodes=[],
    ))

    return tm


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="BountyForge Trust Map Engine")
    parser.add_argument("--target", required=True, help="Target name/domain")
    parser.add_argument("--init", action="store_true", help="Bootstrap trust map from defaults")
    parser.add_argument("--add-node", help="Add a node (provide JSON)")
    parser.add_argument("--add-edge", help="Add an edge (provide JSON)")
    parser.add_argument("--add-boundary", help="Add a boundary (provide JSON)")
    parser.add_argument("--attach-capability", nargs=2, metavar=("NODE_ID", "CAP_ID"),
                        help="Attach a capability to a node")
    parser.add_argument("--find-crossings", action="store_true",
                        help="Find boundary crossings")
    parser.add_argument("--find-chains", action="store_true",
                        help="Find chains from boundary crossings")
    parser.add_argument("--path", nargs=2, metavar=("FROM", "TO"),
                        help="Find trust paths between two nodes")
    parser.add_argument("--report", action="store_true", help="Generate full report")
    parser.add_argument("--output-format", default="text", choices=["text", "json"])
    args = parser.parse_args()

    tm = TrustMap(args.target)

    if args.init:
        tm = bootstrap_from_recon(args.target)
        print(f"[+] Trust map bootstrapped for {args.target}")
        print(f"    Nodes: {len(tm._load_nodes())}")
        print(f"    Edges: {len(tm._load_edges())}")
        print(f"    Boundaries: {len(tm._load_boundaries())}")

    elif args.add_node:
        data = json.loads(args.add_node)
        node = TrustNode(**data)
        tm.add_node(node)
        print(f"[+] Node added: {node.node_id}")

    elif args.add_edge:
        data = json.loads(args.add_edge)
        edge = TrustEdge(**data)
        tm.add_edge(edge)
        print(f"[+] Edge added: {edge.from_node} → {edge.to_node}")
        if edge.is_cross_boundary:
            print(f"    ⚡ Boundary crossing detected!")
            crossings = tm.find_crossings_by_boundary(edge.edge_id)
            for c in tm.find_all_crossings():
                if c.edge == edge.edge_id:
                    print(f"    Crossing: {c.crossing_id} [{c.severity}]")

    elif args.add_boundary:
        data = json.loads(args.add_boundary)
        boundary = TrustBoundary(**data)
        tm.add_boundary(boundary)
        print(f"[+] Boundary added: {boundary.name}")

    elif args.attach_capability:
        node_id, cap_id = args.attach_capability
        tm.attach_capability(node_id, cap_id)
        print(f"[+] Capability {cap_id} attached to node {node_id}")

    elif args.find_crossings:
        crossings = tm.find_all_crossings()
        if args.output_format == "json":
            print(json.dumps([asdict(c) for c in crossings], indent=2))
        else:
            print(f"[*] Boundary crossings: {len(crossings)}")
            for c in sorted(crossings, key=lambda x: (
                {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(x.severity, 1)
            ), reverse=True):
                print(f"    [{c.severity.upper()}] {c.from_node} → {c.to_node} "
                      f"(boundary: {c.boundary})")

    elif args.find_chains:
        chains = tm.find_chains_from_crossings()
        if args.output_format == "json":
            print(json.dumps(chains, indent=2))
        else:
            print(f"[*] Chain candidates: {len(chains)}")
            for chain in chains:
                print(f"    [{chain['severity'].upper()}] {chain['attack_path']}")
                print(f"    {chain['description']}")
                print()

    elif args.path:
        paths = tm.find_path(args.path[0], args.path[1])
        print(f"[*] Trust paths from {args.path[0]} to {args.path[1]}: {len(paths)}")
        for i, path in enumerate(paths):
            nodes = [args.path[0]]
            for e in path:
                nodes.append(e.to_node)
            print(f"    Path {i+1}: {' → '.join(nodes)}")

    elif args.report:
        print(tm.generate_report())

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
