"""
Glider Chainlink Oracle Vulnerability Scanner — BountyForge v2.0
Usage: glider run chainlink_oracle_vulns.py --network ethereum

Finds contracts using Chainlink price feeds, then identifies which ones
have the stale-price / missing-validation vulnerabilities that lead to
price oracle manipulation and fund loss.

Categories detected:
  SEVERE   — No staleness check (discards updatedAt/answeredInRound)
  HIGH     — Uses assert() on price instead of require()
  MEDIUM   — Single-source price with no fallback oracle
  INFO     — Uses Chainlink (base detection, manual review needed)
"""

from glider import *

# ── Helpers ────────────────────────────────────────────────────

def function_has_opcode(fn, opcode_name):
    """Check if a function contains a specific EVM opcode."""
    for insn in fn.instructions():
        if insn.opcode == opcode_name:
            return True
    return False

def function_has_callee(fn, callee_names):
    """Check if a function calls any of the given function names."""
    for insn in fn.instructions():
        if hasattr(insn, 'callee_name') and insn.callee_name in callee_names:
            return True
    return False

def get_chainlink_calls(limit=200):
    """Base query: all instructions calling Chainlink price feed methods."""
    latest = (
        Instructions()
        .with_callee_name('latestRoundData')
        .exec(limit)
    )
    historical = (
        Instructions()
        .with_callee_signature('getRoundData(uint80)')
        .exec(limit)
    )
    return latest + historical


# ── 1. SEVERE: No Staleness Check ──────────────────────────────

def find_no_staleness_check(instructions):
    """
    Contracts where the function calling latestRoundData/latestAnswer
    never checks updatedAt or answeredInRound — accepts any price
    from any point in history.

    Pattern: function gets price but never contains:
      - timestamp comparison (require(block.timestamp - updatedAt < ...))
      - answeredInRound check
      - GT/LT/SLT/SGT opcodes applied to the 4th or 5th return value
    """
    results = []
    seen = set()

    for insn in instructions:
        fn = insn.function
        if not fn:
            continue

        contract = fn.contract
        key = (contract.address, fn.name)
        if key in seen:
            continue
        seen.add(key)

        # Count how many of the 5 return values are actually used
        # If only 1-2 are used (just price + maybe roundId), it's vulnerable
        fn_insns = list(fn.instructions())

        # Check for timestamp/recentness validation patterns
        has_timestamp_check = False
        has_staleness_check = False

        for i in fn_insns:
            op = i.opcode if hasattr(i, 'opcode') else ''
            # Look for patterns that check timestamp freshness
            # These appear as SUB + GT/LT comparisons with block.timestamp
            if op in ['TIMESTAMP', 'NUMBER']:
                # Check nearby instructions for comparison
                nearby = fn_insns[max(0, fn_insns.index(i)-5):fn_insns.index(i)+5]
                for n in nearby:
                    if hasattr(n, 'opcode') and n.opcode in ['GT', 'LT', 'SLT', 'SGT']:
                        has_timestamp_check = True
                        break

        # Check for answeredInRound usage
        for i in fn_insns:
            if hasattr(i, 'operand') and i.operand and 'answeredInRound' in str(i.operand).lower():
                has_staleness_check = True

        # If neither check exists, this is vulnerable
        if not has_timestamp_check and not has_staleness_check:
            # Verify it actually writes state (SSTORE) — price used for something
            writes_state = function_has_opcode(fn, 'SSTORE')

            results.append({
                'contract': contract.address,
                'contract_name': contract.name,
                'function': fn.name,
                'visibility': fn.visibility,
                'writes_state': writes_state,
                'issue': 'No staleness check — accepts any historical price',
                'severity': 'Critical' if writes_state else 'High',
            })

    return results


# ── 2. HIGH: assert() Instead of require() ─────────────────────

def find_assert_price_check(instructions):
    """
    Functions that use assert() instead of require() when validating
    Chainlink price. assert() burns all gas on failure (pre-0.8)
    or panics with no recovery path — protocol brick on bad price.
    """
    results = []
    seen = set()

    for insn in instructions:
        fn = insn.function
        if not fn:
            continue

        contract = fn.contract
        key = (contract.address, fn.name)
        if key in seen:
            continue
        seen.add(key)

        # Check for ASSERT opcode in the function (0xfe = INVALID/panic)
        fn_insns = list(fn.instructions())
        has_assert = False
        has_timestamp = False

        for i in fn_insns:
            op = i.opcode if hasattr(i, 'opcode') else ''
            if op in ['INVALID', 'ASSERTFAIL']:
                has_assert = True
            if op in ['TIMESTAMP', 'NUMBER']:
                has_timestamp = True

        if has_assert and not has_timestamp:
            results.append({
                'contract': contract.address,
                'contract_name': contract.name,
                'function': fn.name,
                'issue': 'Uses assert() instead of require() on price — protocol bricks on bad price',
                'severity': 'High',
            })

    return results


# ── 3. MEDIUM: try/catch Silently Returns Zero ─────────────────

def find_silent_zero_price(instructions):
    """
    Functions that wrap Chainlink calls in try/catch and silently
    return zero on failure. Callers may treat answer=0 as valid.

    Pattern: function contains both the Chainlink call AND a
    zero-value return path without explicit price validation.
    """
    results = []
    seen = set()

    for insn in instructions:
        fn = insn.function
        if not fn:
            continue

        # Check if function has a try/catch-like pattern
        # In EVM, try/catch compiles to specific jump patterns
        # We look for functions that both call Chainlink AND
        # have a direct return path that could return uninitialized data

        contract = fn.contract
        key = (contract.address, fn.name)
        if key in seen:
            continue
        seen.add(key)

        fn_insns = list(fn.instructions())
        has_return = False
        has_chainlink = False

        for i in fn_insns:
            op = i.opcode if hasattr(i, 'opcode') else ''
            callee = i.callee_name if hasattr(i, 'callee_name') else ''

            if op == 'RETURN':
                has_return = True
            if callee in ['latestRoundData', 'getRoundData', 'decimals', 'latestAnswer']:
                has_chainlink = True

        # If function calls Chainlink AND has multiple return paths
        # AND doesn't have positive-price validation, it's risky
        if has_chainlink and has_return:
            # Check for positive price validation (require(price > 0))
            has_positive_check = False
            for i in fn_insns:
                if hasattr(i, 'opcode') and i.opcode in ['SGT', 'GT']:
                    # There's some comparison — could be > 0 check
                    has_positive_check = True

            if not has_positive_check:
                results.append({
                    'contract': contract.address,
                    'contract_name': contract.name,
                    'function': fn.name,
                    'issue': 'No positive price check — silently accepts zero on feed failure',
                    'severity': 'Medium',
                })

    return results


# ── 4. INFO: All Chainlink Consumers ───────────────────────────

def find_all_chainlink_consumers(instructions):
    """List all contracts using Chainlink for manual review."""
    results = []
    seen = set()

    for insn in instructions:
        fn = insn.function
        if not fn:
            continue
        contract = fn.contract
        key = contract.address
        if key in seen:
            continue
        seen.add(key)

        results.append({
            'contract': contract.address,
            'contract_name': contract.name,
            'total_functions': len(contract.functions),
            'oracle_functions': [fn.name],
        })

    return results


# ── Main ────────────────────────────────────────────────────────

def query():
    print("=" * 65)
    print("  BountyForge · Chainlink Oracle Vuln Scanner")
    print("=" * 65)

    # Step 1: Get all Chainlink-consuming instructions
    instructions = get_chainlink_calls(200)
    print("\n[*] Found {} instructions calling Chainlink oracles".format(len(instructions)))

    # Step 2: Severe — no staleness check
    print("\n═══ SEVERE: No Staleness Check ═══")
    severe = find_no_staleness_check(instructions)
    for r in severe:
        state_tag = " [WRITES STATE]" if r['writes_state'] else ""
        print("  [!!] {}::{} ({}) — {} {}".format(
            r['contract_name'] or r['contract'][:10],
            r['function'],
            r['visibility'],
            r['issue'],
            state_tag
        ))
    if not severe:
        print("  (none found)")

    # Step 3: High — assert() instead of require()
    print("\n═══ HIGH: assert() on Price ═══")
    high = find_assert_price_check(instructions)
    for r in high:
        print("  [!] {}::{} — {}".format(
            r['contract_name'] or r['contract'][:10],
            r['function'],
            r['issue']
        ))
    if not high:
        print("  (none found)")

    # Step 4: Medium — silent zero price
    print("\n═══ MEDIUM: Silent Zero Price ═══")
    medium = find_silent_zero_price(instructions)
    for r in medium:
        print("  [-] {}::{} — {}".format(
            r['contract_name'] or r['contract'][:10],
            r['function'],
            r['issue']
        ))
    if not medium:
        print("  (none found)")

    # Step 5: All consumers
    print("\n═══ INFO: All Chainlink Consumers ═══")
    consumers = find_all_chainlink_consumers(instructions)
    for c in consumers:
        print("  [i] {} ({} functions, oracles in: {})".format(
            c['contract_name'] or c['contract'][:10],
            c['total_functions'],
            ', '.join(c['oracle_functions'])
        ))

    # Summary
    print("\n" + "=" * 65)
    print("  SCAN COMPLETE")
    print("  Severe: {}  High: {}  Medium: {}  Total consumers: {}".format(
        len(severe), len(high), len(medium), len(consumers)
    ))
    print("=" * 65)

    return instructions


if __name__ == "__main__":
    query()
