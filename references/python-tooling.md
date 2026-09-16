# Python Tooling — Command Reference

> Split from SKILL.md v4.1.0. Load when orchestrating `tools/` scripts. Tool inventory: `tools/` + `references/setup.md`.

---

## PYTHON TOOLING

All tools are in `tools/` relative to this SKILL.md. Use them directly — do not reimplement their logic.

### Core Hunting Tools

| Tool | Purpose | Usage |
|------|---------|-------|
| `tools/hunt.py` | Session management, curl builder, auth-aware requests, active injection (SQLi/XSS/SSTI/RCE/path-traversal) | `python3 tools/hunt.py --target T --active --json` |
| `tools/state.py` | Session state persistence (endpoints, findings) | Import and use `SessionState` class |
| `tools/leads.py` | Lead Ledger — persistent OPEN LEAD state-transition objects (preconditions, one-variable mutation loop, chain pool, kill guard) | `--add/--set-half/--next-mutation/--mutate/--park/--kill/--chain-partners` |
| `tools/agent_bus.py` | Inter-agent signal passing | Import and use `AgentBus` class |

### Exploit Generation

| Tool | Purpose | Usage |
|------|---------|-------|
| `tools/exploit_gen.py` | Generate PoC code (curl, Python, Burp, Metasploit) | `from exploit_gen import gen_curl, gen_python_poc` |
| `tools/kill_chain.py` | A→B bug chain builder (23 H100-proven chains), auto-escalation | Import `KillChainBuilder` class |
| `tools/adversary_emulation.py` | MITRE ATT&CK + OWASP coverage mapping, heatmap, gap analysis | Import `AdversaryEmulation` class |
| `tools/formal_verify.py` | Certora specs, fuzz harnesses, API invariant tests | Import and use functions |

### Recon & Intel

| Tool | Purpose | Usage |
|------|---------|-------|
| `tools/threat_intel.py` | HackerOne Hacktivity intelligence | `from threat_intel import fetch_hacktivity` |
| `tools/patch_gap.py` | CVE/patch gap analysis, ExploitDB search | `from patch_gap import fetch_cves_by_tech` |
| `tools/opsec.py` | UA rotation, Tor support, request obfuscation | Import `OpsecRotator` class |

### Trust & Verification (v3.0.0)

| Tool | Purpose | Usage |
|------|---------|-------|
| `tools/trust_map.py` | Target trust relationship graph, boundary crossing detection, chain signaling | Import `TrustMap` class |
| `tools/refutation.py` | Adversarial finding refutation — spawns a different model to kill findings through 4-gate evaluation | Import `RefutationEngine` class |
| `tools/observation.py` | Observation/Oracle Validation layer — a raw HTTP response can never silently refute an experiment; candidate vs control/baseline comparison (status, body, headers, timing, redirects, size) with deterministic UNKNOWN classification + follow-up generation, provenance-preserving | Import `OracleValidator` class |
| `tools/capability_registry.py` | Structured catalog of every discovered primitive, chain compatibility matching, coverage analysis | Import `CapabilityRegistry` class |
| `tools/program_fit.py` | Program scope/suitability gate — filters noise before report generation | Import `ProgramFitGate` class |
| `tools/ledger.py` | Evidence consistency verifier — cross-references findings against journal, endpoints, custody | Import `LedgerVerifier` class |
| `tools/agent_isolation.py` | Agent isolation checker — verifies each agent operates within defined boundaries, prevents cross-contamination | Import `AgentIsolationChecker` class |

### Infrastructure & OPSEC

| Tool | Purpose | Usage |
|------|---------|-------|
| `tools/infra_deploy.py` | Callback server for OOB testing | `from infra_deploy import CallbackHandler` |
| `tools/crypto_vault.py` | AES encryption for sensitive findings | `from crypto_vault import aes_encrypt, aes_decrypt` |
| `tools/chain_of_custody.py` | Evidence chain of custody, BLAKE3 hashing, Merkle chain linking | Import `CustodyChain` class |

### Fleet & Scheduling

| Tool | Purpose | Usage |
|------|---------|-------|
| `tools/fleet.py` | Multi-target fleet management | Import `FleetTarget`, `FleetSession` |
| `tools/retest_scheduler.py` | Scope monitoring, retest scheduling | Import `RetestJob`, `WatchConfig` |

### How to Use Tools

**Full pipeline (single target):**
```bash
# Phase 1: Recon → seed live-hosts.txt and urls.txt
# (run recon tools first: subfaster + httpx + katana)

# Phase 2: Hunt with active injection + JSON output
python3 tools/hunt.py --target TARGET --active --json 2>/dev/null | tee findings.json

# Phase 3: Build kill chains from findings
python3 -c "
import json, sys
from tools.kill_chain import KillChainBuilder
findings = json.load(open('findings.json'))['findings']
builder = KillChainBuilder('TARGET')
chains = builder.build_all_chains(findings)
for c in chains:
    print(f'{c.pattern.chain_id}: {c.pattern.name} (score={c.match_score:.2f}, {c.combined_severity})')
    for s in c.trigger_sequence: print(f'  {s}')
"

# Phase 4: Generate PoC for confirmed findings
python3 -c "from tools.exploit_gen import gen_curl, gen_python_poc; print(gen_curl({'method':'POST','url':'https://target.com/api','headers':{},'body':'test'}))"

# Phase 5: MITRE/OWASP coverage analysis
python3 -c "
import json
from tools.adversary_emulation import AdversaryEmulation
findings = json.load(open('findings.json'))['findings']
emu = AdversaryEmulation('TARGET')
for f in findings:
    emu.classify_finding(f)  # Maps to MITRE ATT&CK + OWASP automatically
cov = emu.compute_coverage(agents_deployed=['web-api-agent'], findings=findings)
mitre_avg = sum(cov.mitre_coverage.values()) / max(len(cov.mitre_coverage), 1)
print(f'MITRE avg: {mitre_avg:.0%}, OWASP gaps: {len(cov.gaps)}')
"
```

**Individual tool usage:**
```bash
# Hunt with auth
python3 tools/hunt.py --target TARGET --cookie 'session=abc123' --active --json

# Hunt with two sessions for IDOR diffing
python3 tools/hunt.py --target TARGET --auth-file-a .private/user-a.json --auth-file-b .private/user-b.json --json

# Generate PoC
python3 -c "from tools.exploit_gen import gen_curl; print(gen_curl({'method':'POST','url':'https://target.com/api','headers':{},'body':'test'}))"

# Fetch Hacktivity intel
python3 -c "from tools.threat_intel import fetch_hacktivity; print(fetch_hacktivity('target-program', limit=10))"

# Check CVEs
python3 -c "from tools.patch_gap import fetch_cves_by_tech; print(fetch_cves_by_tech(['nginx','apache'], days_back=30))"

# Deploy OOB callback infrastructure
python3 tools/infra_deploy.py --type http-callback --port 8080 --dns-port 5353
```

**Rule:** If a tool exists for a task, USE THE TOOL. Do not rewrite its logic. Agents should call `hunt.py --active --json` as their first action after recon — the structured JSON output feeds directly into kill_chain, exploit_gen, and adversary_emulation.
