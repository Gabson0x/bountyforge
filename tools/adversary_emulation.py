#!/usr/bin/env python3
"""
BountyForge Adversary Emulation Framework v2.1.0

Maps every agent action and finding to:
  - MITRE ATT&CK Enterprise (T-codes)
  - MITRE ATT&CK Mobile (for mobile testing)
  - OWASP Top 10 2021 (A-codes)
  - OWASP API Security Top 10 2023
  - OWASP LLM Top 10 (for AI/LLM testing)
  - CAPEC (Common Attack Pattern Enumeration)

Tracks coverage per target, per agent, and identifies gaps:
  - Which techniques haven't been tested?
  - Which agents haven't been deployed?
  - Which severity levels have no findings?

Usage:
  python3 tools/adversary_emulation.py --target example.com --report
  python3 tools/adversary_emulation.py --target example.com --coverage-gaps
  python3 tools/adversary_emulation.py --agent web-api-agent --map-findings
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Set
from dataclasses import dataclass, field, asdict
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

EMULATION_DIR = ROOT / "state" / "emulation"


# ---------------------------------------------------------------------------
# MITRE ATT&CK Enterprise — web/bug bounty relevant techniques
# ---------------------------------------------------------------------------

MITRE_ENTERPRISE = {
    # Reconnaissance
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance",
              "sub": {".001": "Scanning IP Blocks", ".002": "Vulnerability Scanning",
                      ".003": "Wordlist Scanning", ".004": "DNS Scanning"}},
    "T1592": {"name": "Gather Victim Host Information",
              "tactic": "Reconnaissance",
              "sub": {".001": "Hardware", ".002": "Software/Version",
                      ".003": "Firmware"}},
    "T1590": {"name": "Gather Victim Network Information",
              "tactic": "Reconnaissance",
              "sub": {".001": "Domain Properties", ".002": "DNS",
                      ".003": "Network Trust Dependencies",
                      ".005": "IP Addresses"}},
    "T1589": {"name": "Gather Victim Identity Information",
              "tactic": "Reconnaissance",
              "sub": {".001": "Credentials", ".002": "Email Addresses"}},

    # Resource Development
    "T1583": {"name": "Acquire Infrastructure", "tactic": "Resource Development",
              "sub": {".001": "Domains", ".003": "Virtual Private Server",
                      ".006": "DNS Server"}},
    "T1587": {"name": "Develop Capabilities", "tactic": "Resource Development",
              "sub": {".001": "Malware", ".002": "Code Signing Certs",
                      ".004": "Exploits"}},

    # Initial Access
    "T1190": {"name": "Exploit Public-Facing Application",
              "tactic": "Initial Access"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1199": {"name": "Trusted Relationship", "tactic": "Initial Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access",
              "sub": {".001": "Default Accounts", ".002": "Domain Accounts",
                      ".004": "Cloud Accounts"}},
    "T1566": {"name": "Phishing", "tactic": "Initial Access",
              "sub": {".001": "Spearphishing Attachment",
                      ".002": "Spearphishing Link"}},

    # Execution
    "T1059": {"name": "Command and Scripting Interpreter",
              "tactic": "Execution",
              "sub": {".001": "PowerShell", ".003": "Unix Shell",
                      ".004": "Python", ".005": "JavaScript"}},
    "T1203": {"name": "Exploitation for Client Execution",
              "tactic": "Execution"},

    # Persistence
    "T1505": {"name": "Server Software Component", "tactic": "Persistence",
              "sub": {".003": "Web Shell"}},
    "T1078": {"name": "Valid Accounts", "tactic": "Persistence",
              "note": "Same ID appears in multiple tactics"},

    # Privilege Escalation
    "T1068": {"name": "Exploitation for Privilege Escalation",
              "tactic": "Privilege Escalation"},
    "T1078": {"name": "Valid Accounts", "tactic": "Privilege Escalation",
              "note": "Reused across tactics — privilege context matters"},

    # Defense Evasion
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion",
              "sub": {".001": "Clear Windows Event Logs",
                      ".004": "File Deletion"}},
    "T1564": {"name": "Hide Artifacts", "tactic": "Defense Evasion"},
    "T1027": {"name": "Obfuscated Files or Information",
              "tactic": "Defense Evasion"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},

    # Credential Access
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access",
              "sub": {".001": "Credentials In Files",
                      ".002": "Credentials in Registry",
                      ".004": "Private Keys"}},
    "T1555": {"name": "Credentials from Password Stores",
              "tactic": "Credential Access",
              "sub": {".003": "Secrets Dump"}},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access",
              "sub": {".001": "Password Guessing",
                      ".003": "Password Spraying"}},
    "T1606": {"name": "Forge Web Credentials", "tactic": "Credential Access",
              "sub": {".001": "Web Cookies", ".002": "SAML Tokens"}},

    # Discovery
    "T1083": {"name": "File and Directory Discovery",
              "tactic": "Discovery"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery",
              "sub": {".001": "Local Account", ".002": "Domain Account",
                      ".003": "Email Account", ".004": "Cloud Account"}},
    "T1526": {"name": "Cloud Service Discovery", "tactic": "Discovery"},

    # Collection
    "T1119": {"name": "Automated Collection", "tactic": "Collection"},
    "T1213": {"name": "Data from Information Repositories",
              "tactic": "Collection",
              "sub": {".001": "Confluence", ".002": "Sharepoint",
                      ".003": "Code Repositories"}},
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},

    # Exfiltration
    "T1048": {"name": "Exfiltration Over Alternative Protocol",
              "tactic": "Exfiltration",
              "sub": {".002": "Exfiltration Over HTTP"}},
    "T1567": {"name": "Exfiltration Over Web Service",
              "tactic": "Exfiltration"},

    # Impact
    "T1485": {"name": "Data Destruction", "tactic": "Impact"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},

    # Resource Development (bounty-relevant)
    "T1584": {"name": "Compromise Infrastructure", "tactic": "Resource Development",
              "sub": {".004": "Server", ".006": "DNS Server"}},
    "T1608": {"name": "Stage Capabilities", "tactic": "Resource Development",
              "sub": {".001": "Upload Malware", ".002": "Upload Tool"}},
}

# Bounty-specific techniques not in MITRE but relevant
BOUNTY_EXTENSIONS = {
    "BX001": {"name": "OAuth Authorization Code Theft",
              "tactic": "Credential Access",
              "mitre_map": "T1606.002"},
    "BX002": {"name": "API Mass Assignment",
              "tactic": "Privilege Escalation",
              "mitre_map": "T1068"},
    "BX003": {"name": "JWT Algorithm Confusion",
              "tactic": "Credential Access",
              "mitre_map": "T1606.001"},
    "BX004": {"name": "GraphQL Introspection Abuse",
              "tactic": "Discovery",
              "mitre_map": "T1083"},
    "BX005": {"name": "HTTP Request Smuggling",
              "tactic": "Initial Access",
              "mitre_map": "T1190"},
    "BX006": {"name": "Web Cache Poisoning",
              "tactic": "Collection",
              "mitre_map": "T1189"},
    "BX007": {"name": "Race Condition Exploitation",
              "tactic": "Execution",
              "mitre_map": "T1203"},
    "BX008": {"name": "Subdomain Takeover",
              "tactic": "Initial Access",
              "mitre_map": "T1584.006"},
    "BX009": {"name": "Email Confirmation Bypass",
              "tactic": "Privilege Escalation",
              "mitre_map": "T1078"},
    "BX010": {"name": "Cryptographic Weakness Exploitation",
              "tactic": "Credential Access",
              "mitre_map": "T1552.004"},
}


# ---------------------------------------------------------------------------
# OWASP Top 10 2021
# ---------------------------------------------------------------------------

OWASP_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

OWASP_API_2023 = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server-Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}

OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model Denial of Service",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "Insecure Plugin Design",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
    "LLM10": "Model Theft",
}


# ---------------------------------------------------------------------------
# Agent → Technique mapping
# ---------------------------------------------------------------------------

AGENT_TECHNIQUE_MAP = {
    "recon-agent": {
        "mitre": ["T1595", "T1590", "T1592", "T1083", "T1046", "T1087",
                   "T1526", "T1589"],
        "owasp_2021": ["A05", "A06"],
        "owasp_api": ["API8", "API9"],
        "owasp_llm": [],
        "capec": ["CAPEC-169", "CAPEC-224"],
    },
    "web-api-agent": {
        "mitre": ["T1190", "T1059", "T1203", "T1552", "T1027"],
        "owasp_2021": ["A01", "A03", "A04", "A05", "A07", "A10"],
        "owasp_api": ["API1", "API2", "API3", "API4", "API5", "API7", "API8"],
        "owasp_llm": [],
        "capec": ["CAPEC-66", "CAPEC-272", "CAPEC-664"],
    },
    "access-control-agent": {
        "mitre": ["T1068", "T1078", "T1606"],
        "owasp_2021": ["A01", "A04", "A07"],
        "owasp_api": ["API1", "API2", "API3", "API5"],
        "owasp_llm": [],
        "capec": ["CAPEC-233", "CAPEC-58"],
    },
    "business-logic-agent": {
        "mitre": ["T1490"],
        "owasp_2021": ["A04"],
        "owasp_api": ["API6"],
        "owasp_llm": [],
        "capec": ["CAPEC-128", "CAPEC-210"],
    },
    "race-condition-agent": {
        "mitre": ["T1203"],
        "owasp_2021": ["A04"],
        "owasp_api": ["API4"],
        "owasp_llm": [],
        "capec": ["CAPEC-26"],
    },
    "smart-contract-agent": {
        "mitre": [],  # Not in enterprise MITRE
        "owasp_2021": ["A02", "A04", "A08"],
        "owasp_api": [],
        "owasp_llm": [],
        "capec": ["CAPEC-130", "CAPEC-459"],
        "custom": ["SC-REENTRANCY", "SC-ACCESS-CTRL", "SC-ORACLE",
                    "SC-FLASH-LOAN", "SC-INTEGER", "SC-UPGRADE"],
    },
    "economic-security-agent": {
        "mitre": [],
        "owasp_2021": [],
        "owasp_api": [],
        "owasp_llm": [],
        "custom": ["ECON-ORACLE-MANIP", "ECON-FLASH-LOAN",
                    "ECON-TOKEN-DILUTION", "ECON-INCENTIVE"],
    },
    "supply-chain-agent": {
        "mitre": ["T1195", "T1583"],
        "owasp_2021": ["A06", "A08"],
        "owasp_api": [],
        "owasp_llm": ["LLM05"],
        "capec": ["CAPEC-438", "CAPEC-439"],
    },
    "browser-automation-agent": {
        "mitre": ["T1566"],
        "owasp_2021": [],
        "owasp_api": [],
        "owasp_llm": [],
        "capec": ["CAPEC-103"],
    },
    "graphql-agent": {
        "mitre": ["T1083"],
        "owasp_2021": ["A01", "A03", "A05"],
        "owasp_api": ["API1", "API8"],
        "owasp_llm": [],
        "capec": [],
    },
    "http-smuggling-agent": {
        "mitre": ["T1190"],
        "owasp_2021": ["A04"],
        "owasp_api": ["API8"],
        "owasp_llm": [],
        "capec": ["CAPEC-33"],
    },
    "cache-poisoning-agent": {
        "mitre": ["T1189"],
        "owasp_2021": ["A04"],
        "owasp_api": [],
        "owasp_llm": [],
        "capec": ["CAPEC-141"],
    },
    "counter-intelligence-agent": {
        "mitre": ["T1070", "T1564", "T1036"],
        "owasp_2021": [],
        "owasp_api": [],
        "owasp_llm": [],
        "capec": [],
        "custom": ["CI-WAF-DETECT", "CI-HONEYPOT-DETECT", "CI-CANARY-DETECT"],
    },
    "regression-agent": {
        "mitre": [],  # Post-exploitation
        "owasp_2021": [],
        "owasp_api": [],
        "owasp_llm": [],
        "custom": ["REG-FIX-VERIFY", "REG-BYPASS", "REG-SIBLING"],
    },
}


# ---------------------------------------------------------------------------
# Finding → Technique classifier
# ---------------------------------------------------------------------------

BUG_CLASS_TECHNIQUE_MAP = {
    # Web/API bug classes → MITRE + OWASP
    "idor": {"mitre": "T1068", "owasp_2021": "A01", "owasp_api": "API1"},
    "broken-auth": {"mitre": "T1078", "owasp_2021": "A07", "owasp_api": "API2"},
    "jwt-bypass": {"mitre": "T1606", "owasp_2021": "A02", "owasp_api": "API2"},
    "ssrf": {"mitre": "T1190", "owasp_2021": "A10", "owasp_api": "API7"},
    "sqli": {"mitre": "T1190", "owasp_2021": "A03", "owasp_api": "API8"},
    "xss-stored": {"mitre": "T1189", "owasp_2021": "A03", "owasp_api": "API8"},
    "xss-reflected": {"mitre": "T1189", "owasp_2021": "A03", "owasp_api": "API8"},
    "xss-dom": {"mitre": "T1189", "owasp_2021": "A03", "owasp_api": "API8"},
    "xxe": {"mitre": "T1190", "owasp_2021": "A03", "owasp_api": "API8"},
    "rce": {"mitre": "T1059", "owasp_2021": "A03", "owasp_api": "API8"},
    "path-traversal": {"mitre": "T1083", "owasp_2021": "A01", "owasp_api": "API1"},
    "open-redirect": {"mitre": "T1189", "owasp_2021": "A04", "owasp_api": "API8"},
    "csrf": {"mitre": "T1189", "owasp_2021": "A01", "owasp_api": "API8"},
    "graphql-introspection": {"mitre": "T1083", "owasp_2021": "A05", "owasp_api": "API8"},
    "business-logic": {"mitre": "T1490", "owasp_2021": "A04", "owasp_api": "API6"},
    "race-condition-web": {"mitre": "T1203", "owasp_2021": "A04", "owasp_api": "API4"},
    "mass-assignment": {"mitre": "T1068", "owasp_2021": "A01", "owasp_api": "API3"},
    "insecure-deserialization": {"mitre": "T1059", "owasp_2021": "A08", "owasp_api": "API8"},
    "info-disclosure": {"mitre": "T1083", "owasp_2021": "A04", "owasp_api": "API8"},
    "cors-misconfiguration": {"mitre": "T1189", "owasp_2021": "A01", "owasp_api": "API8"},
    "account-takeover": {"mitre": "T1078", "owasp_2021": "A07", "owasp_api": "API2"},
    "privilege-escalation-web": {"mitre": "T1068", "owasp_2021": "A01", "owasp_api": "API5"},
    "api-key-exposure": {"mitre": "T1552", "owasp_2021": "A02", "owasp_api": "API8"},
    "oauth-bypass": {"mitre": "T1606", "owasp_2021": "A07", "owasp_api": "API2"},
    "subdomain-takeover": {"mitre": "T1584", "owasp_2021": "A06", "owasp_api": "API9"},
    "cache-poisoning": {"mitre": "T1189", "owasp_2021": "A04", "owasp_api": "API8"},
    "request-smuggling": {"mitre": "T1190", "owasp_2021": "A04", "owasp_api": "API8"},
    "parameter-pollution": {"mitre": "T1190", "owasp_2021": "A04", "owasp_api": "API8"},
    "host-header-injection": {"mitre": "T1189", "owasp_2021": "A04", "owasp_api": "API8"},
    "csv-injection": {"mitre": "T1203", "owasp_2021": "A03", "owasp_api": "API8"},

    # Smart contract bug classes
    "reentrancy": {"custom": "SC-REENTRANCY", "owasp_2021": "A04"},
    "integer-overflow": {"custom": "SC-INTEGER", "owasp_2021": "A08"},
    "integer-underflow": {"custom": "SC-INTEGER", "owasp_2021": "A08"},
    "precision-loss": {"custom": "SC-INTEGER", "owasp_2021": "A08"},
    "access-control-bypass": {"custom": "SC-ACCESS-CTRL", "owasp_2021": "A01"},
    "unprotected-initializer": {"custom": "SC-ACCESS-CTRL", "owasp_2021": "A01"},
    "storage-collision": {"custom": "SC-UPGRADE", "owasp_2021": "A04"},
    "front-running": {"custom": "SC-ORACLE", "owasp_2021": "A04"},
    "oracle-manipulation": {"custom": "SC-ORACLE", "owasp_2021": "A04"},
    "flash-loan-attack": {"custom": "SC-FLASH-LOAN", "owasp_2021": "A04"},
    "signature-replay": {"custom": "SC-ACCESS-CTRL", "owasp_2021": "A02"},
    "upgrade-bypass": {"custom": "SC-UPGRADE", "owasp_2021": "A01"},
    "delegatecall-injection": {"custom": "SC-ACCESS-CTRL", "owasp_2021": "A03"},
    "price-manipulation": {"custom": "ECON-ORACLE-MANIP", "owasp_2021": "A04"},
    "invariant-violation": {"custom": "SC-INTEGER", "owasp_2021": "A04"},
    "denial-of-service": {"custom": "SC-ACCESS-CTRL", "owasp_2021": "A04"},
    "griefing": {"custom": "ECON-INCENTIVE", "owasp_2021": "A04"},
}


# ---------------------------------------------------------------------------
# Coverage tracker
# ---------------------------------------------------------------------------

@dataclass
class CoverageReport:
    target: str
    generated_at: str
    agents_deployed: List[str]
    agents_missing: List[str]
    mitre_coverage: Dict[str, float]  # tactic → coverage %
    owasp_2021_coverage: Dict[str, bool]
    owasp_api_coverage: Dict[str, bool]
    owasp_llm_coverage: Dict[str, bool]
    gaps: List[Dict]
    recommendations: List[str]
    findings_mapped: int = 0
    total_techniques_mitre: int = 224  # Total enterprise techniques
    techniques_covered: int = 0


class AdversaryEmulation:
    """Maps findings to adversary frameworks and tracks coverage."""

    def __init__(self, target: str):
        self.target = target
        EMULATION_DIR.mkdir(parents=True, exist_ok=True)
        (EMULATION_DIR / target).mkdir(exist_ok=True)

    def classify_finding(self, finding: Dict) -> Dict:
        """Map a finding to MITRE ATT&CK + OWASP categories."""
        bug_class = finding.get("bug_class", "").lower()
        mapping = BUG_CLASS_TECHNIQUE_MAP.get(bug_class, {})

        result = {
            "finding_id": finding.get("finding_id", ""),
            "title": finding.get("title", ""),
            "bug_class": bug_class,
            "severity": finding.get("severity", "info"),
            "mitre_technique": mapping.get("mitre", "N/A"),
            "owasp_2021": mapping.get("owasp_2021", "N/A"),
            "owasp_api": mapping.get("owasp_api", "N/A"),
            "custom": mapping.get("custom", "N/A"),
        }

        # Enrich with MITRE details
        mitre_id = result["mitre_technique"]
        if mitre_id in MITRE_ENTERPRISE:
            t = MITRE_ENTERPRISE[mitre_id]
            result["mitre_name"] = t["name"]
            result["mitre_tactic"] = t["tactic"]

        return result

    def map_findings(self, findings: List[Dict]) -> List[Dict]:
        """Map all findings and persist the mapping."""
        mapped = [self.classify_finding(f) for f in findings]

        out = EMULATION_DIR / self.target / "finding-mapping.json"
        out.write_text(json.dumps(mapped, indent=2))

        return mapped

    def compute_coverage(self, agents_deployed: List[str] = None,
                         findings: List[Dict] = None) -> CoverageReport:
        """Compute coverage across all frameworks.

        Compares what agents COULD cover vs what they DID cover (via findings).
        """

        # What techniques SHOULD be covered based on deployed agents?
        expected_mitre: Set[str] = set()
        expected_owasp: Set[str] = set()
        expected_api: Set[str] = set()
        expected_llm: Set[str] = set()

        for agent in (agents_deployed or []):
            atm = AGENT_TECHNIQUE_MAP.get(agent, {})
            expected_mitre.update(atm.get("mitre", []))
            expected_owasp.update(atm.get("owasp_2021", []))
            expected_api.update(atm.get("owasp_api", []))
            expected_llm.update(atm.get("owasp_llm", []))

        # What techniques were ACTUALLY hit by findings?
        actual_mitre: Set[str] = set()
        actual_owasp: Set[str] = set()
        actual_api: Set[str] = set()
        actual_llm: Set[str] = set()

        for f in (findings or []):
            bc = f.get("bug_class", "").lower()
            mapping = BUG_CLASS_TECHNIQUE_MAP.get(bc, {})
            if mapping.get("mitre"):
                actual_mitre.add(mapping["mitre"])
            if mapping.get("owasp_2021"):
                actual_owasp.add(mapping["owasp_2021"])
            if mapping.get("owasp_api"):
                actual_api.add(mapping["owasp_api"])

        # Compute gaps
        mitre_gaps = expected_mitre - actual_mitre
        owasp_gaps = expected_owasp - actual_owasp
        api_gaps = expected_api - actual_api
        llm_gaps = expected_llm - actual_llm

        # Build per-tactic coverage for MITRE
        tactic_coverage: Dict[str, float] = {}
        for tid in expected_mitre:
            if tid in MITRE_ENTERPRISE:
                tactic = MITRE_ENTERPRISE[tid]["tactic"]
                if tactic not in tactic_coverage:
                    tactic_coverage[tactic] = {"total": 0, "covered": 0}
                tactic_coverage[tactic]["total"] += 1
                if tid in actual_mitre:
                    tactic_coverage[tactic]["covered"] += 1

        mitre_pct = {}
        for tactic, counts in tactic_coverage.items():
            mitre_pct[tactic] = (counts["covered"] / max(counts["total"], 1)) * 100

        # Generate recommendations
        recommendations = []
        for gap in sorted(mitre_gaps):
            if gap in MITRE_ENTERPRISE:
                recommendations.append(
                    f"[MITRE {gap}] {MITRE_ENTERPRISE[gap]['name']} "
                    f"({MITRE_ENTERPRISE[gap]['tactic']}) — not yet tested")

        for gap in sorted(owasp_gaps):
            recommendations.append(
                f"[OWASP {gap}] {OWASP_2021.get(gap, gap)} — no findings")

        for gap in sorted(api_gaps):
            recommendations.append(
                f"[API {gap}] {OWASP_API_2023.get(gap, gap)} — no findings")

        # Agent gaps
        all_agents = set(AGENT_TECHNIQUE_MAP.keys())
        deployed_set = set(agents_deployed or [])
        agent_gaps = []
        for agent in sorted(all_agents - deployed_set):
            if agent not in ("smart-contract-agent", "economic-security-agent",
                             "browser-automation-agent", "mobile-client-agent",
                             "supply-chain-agent", "graphql-agent",
                             "http-smuggling-agent", "cache-poisoning-agent"):
                continue  # Only flag web-relevant agents
            agent_gaps.append(agent)

        if agent_gaps:
            recommendations.append(
                f"[AGENTS] Deploy additional agents: {', '.join(agent_gaps)}")

        return CoverageReport(
            target=self.target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            agents_deployed=agents_deployed or [],
            agents_missing=agent_gaps,
            mitre_coverage=mitre_pct,
            owasp_2021_coverage={k: k in actual_owasp for k in OWASP_2021},
            owasp_api_coverage={k: k in actual_api for k in OWASP_API_2023},
            owasp_llm_coverage={k: k in actual_llm for k in OWASP_LLM},
            gaps=[{"framework": "MITRE", "id": g} for g in sorted(mitre_gaps)] +
                 [{"framework": "OWASP 2021", "id": g} for g in sorted(owasp_gaps)] +
                 [{"framework": "OWASP API", "id": g} for g in sorted(api_gaps)] +
                 [{"framework": "OWASP LLM", "id": g} for g in sorted(llm_gaps)],
            recommendations=recommendations,
            findings_mapped=len(findings or []),
            techniques_covered=len(actual_mitre),
        )

    def generate_heatmap(self, report: CoverageReport) -> str:
        """Generate an ASCII heatmap of coverage."""
        lines = [
            f"ATT&CK Coverage Heatmap — {report.target}",
            "=" * 60,
        ]

        all_tactics = sorted(set(
            MITRE_ENTERPRISE[t]["tactic"]
            for t in MITRE_ENTERPRISE
        ))

        for tactic in all_tactics:
            pct = report.mitre_coverage.get(tactic, 0)
            bar_len = int(pct / 10)
            bar = "█" * bar_len + "░" * (10 - bar_len)
            lines.append(f"  {tactic:<30} [{bar}] {pct:.0f}%")

        lines.append("")
        lines.append("OWASP 2021 Coverage:")
        for code, name in OWASP_2021.items():
            covered = report.owasp_2021_coverage.get(code, False)
            status = "✓" if covered else "✗"
            lines.append(f"  [{status}] {code}: {name}")

        lines.append("")
        lines.append("OWASP API 2023 Coverage:")
        for code, name in OWASP_API_2023.items():
            covered = report.owasp_api_coverage.get(code, False)
            status = "✓" if covered else "✗"
            lines.append(f"  [{status}] {code}: {name}")

        return "\n".join(lines)

    def save_report(self, report: CoverageReport):
        """Persist the coverage report."""
        out = EMULATION_DIR / self.target / "coverage-report.json"
        out.write_text(json.dumps(asdict(report), indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BountyForge Adversary Emulation Framework")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--report", action="store_true", help="Generate coverage report")
    parser.add_argument("--coverage-gaps", action="store_true",
                        help="Show coverage gaps only")
    parser.add_argument("--agents", nargs="+", help="Agents deployed")
    parser.add_argument("--findings-file", help="JSONL findings file to map")
    parser.add_argument("--format", default="text",
                        choices=["text", "json", "heatmap"],
                        help="Output format")
    parser.add_argument("--dump-matrix", action="store_true",
                        help="Dump full ATT&CK matrix for reference")
    args = parser.parse_args()

    emulation = AdversaryEmulation(args.target)

    if args.dump_matrix:
        print(json.dumps({
            "mitre_enterprise": MITRE_ENTERPRISE,
            "bounty_extensions": BOUNTY_EXTENSIONS,
            "owasp_2021": OWASP_2021,
            "owasp_api": OWASP_API_2023,
            "owasp_llm": OWASP_LLM,
            "agent_technique_map": AGENT_TECHNIQUE_MAP,
            "bug_class_map": BUG_CLASS_TECHNIQUE_MAP,
        }, indent=2))
        return

    # Load findings
    findings = []
    if args.findings_file:
        raw = Path(args.findings_file).read_text()
        findings = [json.loads(l) for l in raw.splitlines() if l.strip()]
    else:
        try:
            from tools.state import get_findings
            findings = get_findings(args.target)
        except ImportError:
            pass

    agents = args.agents or [a for a in AGENT_TECHNIQUE_MAP
                              if a not in ("smart-contract-agent",
                                           "economic-security-agent")]

    if args.report or args.coverage_gaps:
        mapped = emulation.map_findings(findings)
        report = emulation.compute_coverage(agents, findings)
        emulation.save_report(report)

        if args.format == "heatmap":
            print(emulation.generate_heatmap(report))
        elif args.format == "json":
            print(json.dumps(asdict(report), indent=2))
        else:
            print(f"[*] Coverage Report: {args.target}")
            print(f"    Findings mapped: {report.findings_mapped}")
            print(f"    Agents deployed: {len(report.agents_deployed)}")
            print(f"    MITRE techniques covered: {report.techniques_covered}")
            print(f"    Gaps identified: {len(report.gaps)}")
            print()
            if report.recommendations:
                print("Recommendations:")
                for r in report.recommendations[:20]:
                    print(f"  {r}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
