"""
Glider On-Chain Vulnerability Scanner — BountyForge v2.0
Usage: glider run scan.py --network ethereum --limit 10000

Queries deployed contracts for common vuln patterns:
  - Uninitialized proxies (UUPS/Transparent)
  - Storage collisions between proxy & implementation
  - Missing access control on sensitive functions
  - Unchecked low-level calls (reentrancy surface)
  - Arbitrary delegatecall / call injection
  - Selfdestruct / selfdestruct
  - Unlimited token approvals
  - Ownership renounce without recovery
  - Timestamp/oracle manipulation surface
  - Flash loan borrowable tokens
"""

from glider import *

# ── Configuration ──────────────────────────────────────────────
CONFIG = {
    "proxy_patterns": True,      # Uninitialized proxies
    "storage_collisions": True,  # Proxy/impl storage overlap
    "access_control": True,      # Missing onlyOwner / access checks
    "unchecked_calls": True,     # Low-level call without return check
    "delegatecall_injection": True,  # User-controlled delegatecall target
    "selfdestruct": True,        # Selfdestruct reachable by non-owner
    "unlimited_approvals": True, # Infinite token approvals
    "ownership_renounce": True,  # Renounce ownership without transfer
    "oracle_manipulation": True, # Spot price / single-source oracle
    "flash_loan_surface": True,  # Functions callable in a single tx
}

# ── Helpers ────────────────────────────────────────────────────

def is_unchecked(insn):
    """Call result not checked — reentrancy/delegatecall surface."""
    if insn.opcode in ["CALL", "DELEGATECALL", "CALLCODE", "STATICCALL"]:
        # Check if next instruction pops and checks the return value
        next_insns = insn.next_instructions(3)
        for n in next_insns:
            if n.opcode in ["ISZERO", "JUMPI"]:
                return False  # Return value IS checked
        return True
    return False

def has_modifier(fn, modifier_name):
    """Check if function has a specific modifier (onlyOwner, etc.)."""
    for mod in fn.modifiers:
        if modifier_name.lower() in mod.modifier_name.lower():
            return True
    return False

def is_public_or_external(fn):
    return fn.visibility in ["public", "external"]

def writes_storage(fn):
    for insn in fn.instructions():
        if insn.opcode == "SSTORE":
            return True
    return False

# ── 1. Uninitialized Proxies ───────────────────────────────────
def find_uninitialized_proxies():
    """
    UUPS/Transparent proxies where implementation slot is empty
    or _imp() returns address(0).
    """
    print("\n═══ UNINITIALIZED PROXIES ═══")
    results = []

    contracts = Contracts() \
        .with_function_name("upgradeTo|upgrade|upgradeToAndCall") \
        .exec()

    for c in contracts:
        # Check if implementation slot (EIP-1967: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
        impl_slot = c.slots().get("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
        if impl_slot and impl_slot.value == 0:
            results.append({
                "contract": c.address,
                "name": c.name,
                "issue": "Proxy implementation slot is zero — uninitialized",
                "severity": "Critical",
            })

    for r in results:
        print(f"  [!] {r['contract']} — {r['issue']}")
    return results


# ── 2. Missing Access Control on Writable Functions ─────────────
def find_missing_access_control():
    """
    Public/external functions that write to storage but have
    no onlyOwner, onlyRole, or auth modifier.
    """
    print("\n═══ MISSING ACCESS CONTROL ═══")
    results = []

    auth_keywords = ["only", "owner", "role", "auth", "admin", "governance", "guard", "operator"]

    contracts = Contracts() \
        .with_function_visibility("public|external") \
        .exec()

    for c in contracts:
        for fn in c.functions:
            if not writes_storage(fn):
                continue
            if fn.name in ["initialize", "init", "__init__"]:
                continue  # Skip initializers

            mod_names = [m.modifier_name.lower() for m in fn.modifiers]
            is_guarded = any(any(kw in m for kw in auth_keywords) for m in mod_names)

            if not is_guarded:
                results.append({
                    "contract": c.address,
                    "function": fn.name,
                    "modifiers": mod_names,
                    "issue": f"Public/external function '{fn.name}' writes to storage without auth",
                    "severity": "High",
                })

    for r in results[:20]:
        print(f"  [!] {r['contract']}::{r['function']} — no auth guard")
    return results


# ── 3. Unchecked Low-Level Calls ────────────────────────────────
def find_unchecked_calls():
    """
    .call() / .delegatecall() / .staticcall() without checking
    the return boolean — classic reentrancy surface.
    """
    print("\n═══ UNCHECKED LOW-LEVEL CALLS ═══")
    results = []

    contracts = Contracts() \
        .with_opcode("CALL|DELEGATECALL|CALLCODE") \
        .exec()

    for c in contracts:
        for fn in c.functions:
            for insn in fn.instructions():
                if is_unchecked(insn):
                    results.append({
                        "contract": c.address,
                        "function": fn.name,
                        "opcode": insn.opcode,
                        "offset": insn.offset,
                        "issue": f"Unchecked {insn.opcode} at offset {insn.offset} — reentrancy surface",
                        "severity": "High",
                    })

    for r in results[:20]:
        print(f"  [!] {r['contract']}::{r['function']} — unchecked {r['opcode']} at {r['offset']}")
    return results


# ── 4. Arbitrary Delegatecall ──────────────────────────────────
def find_arbitrary_delegatecall():
    """
    DELEGATECALL where the target address comes from calldata,
    storage, or an external call — attacker can execute arbitrary code.
    """
    print("\n═══ ARBITRARY DELEGATECALL ═══")
    results = []

    contracts = Contracts() \
        .with_opcode("DELEGATECALL") \
        .exec()

    for c in contracts:
        for fn in c.functions:
            insns = list(fn.instructions())
            for i, insn in enumerate(insns):
                if insn.opcode != "DELEGATECALL":
                    continue
                # Trace backward — does target come from CALLDATALOAD?
                back_insns = insns[max(0, i - 8):i]
                for bi in back_insns:
                    if bi.opcode in ["CALLDATALOAD", "CALLDATACOPY", "MLOAD"]:
                        results.append({
                            "contract": c.address,
                            "function": fn.name,
                            "source": bi.opcode,
                            "issue": "DELEGATECALL target from user-controlled source",
                            "severity": "Critical",
                        })
                        break

    for r in results:
        print(f"  [!!] {r['contract']}::{r['function']} — delegatecall target from {r['source']}")
    return results


# ── 5. Selfdestruct Reachable by Non-Owner ─────────────────────
def find_accessible_selfdestruct():
    """
    Functions containing SELFDESTRUCT that are callable without
    owner-only restrictions.
    """
    print("\n═══ ACCESSIBLE SELFDESTRUCT ═══")
    results = []

    contracts = Contracts() \
        .with_opcode("SELFDESTRUCT") \
        .exec()

    for c in contracts:
        for fn in c.functions:
            has_selfdestruct = any(
                insn.opcode == "SELFDESTRUCT" for insn in fn.instructions()
            )
            if not has_selfdestruct:
                continue
            if is_public_or_external(fn) and not has_modifier(fn, "only"):
                results.append({
                    "contract": c.address,
                    "function": fn.name,
                    "visibility": fn.visibility,
                    "issue": "SELFDESTRUCT reachable without owner guard",
                    "severity": "Critical",
                })

    for r in results:
        print(f"  [!!] {r['contract']}::{r['function']} ({r['visibility']}) — unprotected selfdestruct")
    return results


# ── 6. Unlimited Token Approvals ────────────────────────────────
def find_unlimited_approvals():
    """
    ERC20 approve() called with type(uint256).max — infinite allowance.
    """
    print("\n═══ UNLIMITED APPROVALS ═══")
    results = []

    contracts = Contracts() \
        .with_function_name("approve") \
        .exec()

    for c in contracts:
        for fn in c.functions:
            if fn.name != "approve":
                continue
            for insn in fn.instructions():
                # Look for PUSH32 of max uint256
                if insn.opcode == "PUSH32" and insn.operand == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff":
                    results.append({
                        "contract": c.address,
                        "issue": "Unlimited approval via type(uint256).max in approve()",
                        "severity": "Medium",
                    })
                    break

    for r in results:
        print(f"  [!] {r['contract']} — unlimited approval pattern")
    return results


# ── 7. Ownership Renounce Without Recovery ─────────────────────
def find_ownership_renounce():
    """
    renounceOwnership() or transferOwnership(address(0)) without
    a two-step transfer or recovery mechanism.
    """
    print("\n═══ OWNERSHIP RENOUNCE RISK ═══")
    results = []

    contracts = Contracts() \
        .with_function_name("renounceOwnership|transferOwnership") \
        .exec()

    for c in contracts:
        for fn in c.functions:
            if "renounce" in fn.name.lower():
                # Check if there's a two-step pattern or timelock
                has_twostep = any("accept" in m.modifier_name.lower() for m in fn.modifiers)
                has_timelock = any("timelock" in m.modifier_name.lower() for m in fn.modifiers)
                if not has_twostep and not has_timelock:
                    results.append({
                        "contract": c.address,
                        "function": fn.name,
                        "issue": "renounceOwnership without two-step transfer or timelock",
                        "severity": "Medium",
                    })

    for r in results:
        print(f"  [!] {r['contract']}::{r['function']} — single-step renounce")
    return results


# ── 8. Oracle / Price Manipulation Surface ─────────────────────
def find_oracle_manipulation_surface():
    """
    Functions reading from a single DEX pair reserve without TWAP.
    Spot-price oracles are flash-loan manipulable.
    """
    print("\n═══ ORACLE MANIPULATION SURFACE ═══")
    results = []

    # Find contracts that call getReserves() on UniswapV2-style pairs
    contracts = Contracts() \
        .with_function_name("getReserves|consult|getAmountsOut|getAmountsIn") \
        .exec()

    for c in contracts:
        for fn in c.functions:
            if is_public_or_external(fn) and writes_storage(fn):
                # Check if there's a TWAP or multi-oracle guard
                fn_str = str(fn).lower()
                has_twap = any(kw in fn_str for kw in ["twap", "cumulative", "timeweighted", "median", "chainlink", "oracle"])
                if not has_twap:
                    results.append({
                        "contract": c.address,
                        "function": fn.name,
                        "issue": "Uses DEX spot price — flash loan manipulable",
                        "severity": "High",
                    })

    for r in results:
        print(f"  [!] {r['contract']}::{r['function']} — spot price oracle")
    return results


# ── 9. Flash Loan Borrow Surface ────────────────────────────────
def find_flash_loan_targets():
    """
    Functions that borrow + repay in one tx — flash loan compatible.
    Look for borrow().*repay() pattern within same function.
    """
    print("\n═══ FLASH LOAN SURFACE ═══")
    results = []

    contracts = Contracts() \
        .with_function_name("borrow|flashLoan|flash|leveraged") \
        .exec()

    for c in contracts:
        for fn in c.functions:
            fn_str = str(fn).lower()
            has_borrow = any(kw in fn_str for kw in ["borrow", "flashloan", "flash"])
            has_repay = any(kw in fn_str for kw in ["repay", "payback", "settle"])
            is_single_tx = not has_modifier(fn, "lock")  # No reentrancy guard

            if has_borrow and has_repay and is_public_or_external(fn):
                results.append({
                    "contract": c.address,
                    "function": fn.name,
                    "issue": "Flash-loanable function without reentrancy guard",
                    "severity": "High",
                })

    for r in results:
        print(f"  [!] {r['contract']}::{r['function']} — flash loan target")
    return results


# ── 10. Storage Collision Between Proxy & Implementation ────────
def find_storage_collisions():
    """
    Proxy and implementation contracts that both define storage
    variables without gap slots — upgrade will corrupt state.
    """
    print("\n═══ STORAGE COLLISION RISK ═══")
    results = []

    # Find upgradeable proxies
    proxies = Contracts() \
        .with_function_name("upgradeTo|upgrade|_authorizeUpgrade") \
        .exec()

    for proxy in proxies:
        # Find the implementation address from EIP-1967 slot
        impl_addr = proxy.slots().get("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
        if not impl_addr or impl_addr.value == 0:
            continue

        impl = Contract(impl_addr.value)
        if not impl.exists():
            continue

        # Compare storage layouts
        proxy_vars = [v.name for v in proxy.state_variables()]
        impl_vars = [v.name for v in impl.state_variables()]

        overlap = set(proxy_vars) & set(impl_vars)
        if overlap and "__gap" not in str(impl_vars) and "reserved" not in str(impl_vars).lower():
            results.append({
                "proxy": proxy.address,
                "implementation": impl_addr.value,
                "overlapping_vars": list(overlap)[:5],
                "issue": "Storage slot overlap between proxy and implementation",
                "severity": "Critical",
            })

    for r in results:
        print(f"  [!!] Proxy {r['proxy']} + Impl {r['implementation']} — overlap: {r['overlapping_vars']}")
    return results


# ── Main ────────────────────────────────────────────────────────
def main():
    print("=" * 65)
    print("  BountyForge · Glider On-Chain Scanner")
    print("=" * 65)

    all_findings = []
    scan_map = {
        "uninitialized_proxies": (CONFIG["proxy_patterns"], find_uninitialized_proxies),
        "storage_collisions": (CONFIG["storage_collisions"], find_storage_collisions),
        "access_control": (CONFIG["access_control"], find_missing_access_control),
        "unchecked_calls": (CONFIG["unchecked_calls"], find_unchecked_calls),
        "delegatecall_injection": (CONFIG["delegatecall_injection"], find_arbitrary_delegatecall),
        "selfdestruct": (CONFIG["selfdestruct"], find_accessible_selfdestruct),
        "unlimited_approvals": (CONFIG["unlimited_approvals"], find_unlimited_approvals),
        "ownership_renounce": (CONFIG["ownership_renounce"], find_ownership_renounce),
        "oracle_manipulation": (CONFIG["oracle_manipulation"], find_oracle_manipulation_surface),
        "flash_loan_surface": (CONFIG["flash_loan_surface"], find_flash_loan_targets),
    }

    for name, (enabled, scanner) in scan_map.items():
        if enabled:
            try:
                findings = scanner()
                all_findings.extend(findings)
            except Exception as e:
                print(f"  [ERR] {name}: {e}")

    # ── Summary ─────────────────────────────────────────────────
    print(f"\n{'=' * 65}")
    print(f"  SCAN COMPLETE — {len(all_findings)} total findings")
    print(f"{'=' * 65}")

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in all_findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    for sev, count in sev_counts.items():
        if count > 0:
            print(f"  {sev}: {count}")

    # Export to JSON for BountyForge report pipeline
    import json
    with open("glider_findings.json", "w") as f:
        json.dump(all_findings, f, indent=2)
    print(f"\n  Findings exported → glider_findings.json")
    print(f"  Feed into BountyForge: /report --source glider_findings.json")


if __name__ == "__main__":
    main()
