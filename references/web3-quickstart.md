# Web3 Quickstart — Multi-Chain + Grep Arsenal

> Split from SKILL.md v4.1.0. Load for `--multi-chain`, `--solidity`, `--move`, `--solana`, `--web3` at hunt start.

---

## MULTI-CHAIN SUPPORT (7 Blockchain Platforms)

When `--multi-chain` or platform-specific triggers detected, apply the three-layer reading order for each chain:

| Platform | Language | Toolchain | Key Attack Surface |
|----------|----------|-----------|-------------------|
| **Ethereum/EVM** | Solidity, Vyper | Foundry, Hardhat, Slither | Storage, reentrancy, flash loans, proxy upgrades |
| **Solana/SVM** | Rust (Anchor) | Anchor CLI, cargo-test-sbf | Program owner, PDA seeds, account privilege escalation |
| **TON** | FunC, Tact | blueprint, toncli | Fundament, context, message routing |
| **Sui/Move** | Move | sui-cli, move-prover | Object ownership, hot potato, transfer rules |
| **Cosmos** | CosmWasm | cargo-test, wasmd | Message ordering, IBC relayer, staking |
| **Near** | Rust | near-sdk, cargo near | Function call access keys, storage staking |
| **Cardano** | Plutus, Aiken | cabal, aiken | Datum, redeem, collateral |

**Protocol-type-specific audit tricks:**
- **Oracle consumers:** Check price feed freshness, TWAP manipulation, single-block manipulation
- **Lending:** Verify interest rate model bounds, utilization cap, bad debt handling
- **Staking/Delegation:** Check validator set changes, slashing conditions, reward distribution
- **AMM/DEX:** Verify fee-on-transfer handling, K invariant, price impact bounds
- **Governance:** Check timelock bypass, proposal threshold, vote manipulation

---

## WEB3 GREP ARSENAL — First 30 Minutes

Run these grep blocks immediately on any new Solidity target. Copy-paste ready.

### Tier 1 — Always Run First

```bash
# Access Control (19% of all Criticals)
rg -n "onlyOwner|onlyRole|require\(.*msg\.sender" --include="*.sol" | grep -v "test\|mock\|lib/"

# Reentrancy
rg -n "external.*\{|\.call\{value|\.transfer\(|\.send\(" --include="*.sol" | grep -v "test\|mock"

# Price/Oracle Manipulation
rg -n "getRate\|getPrice\|latestAnswer\|spotPrice\|twap" --include="*.sol" | grep -v "test\|mock"

# Flash Loan Entry Points
rg -n "flashLoan\|flash loan\|onFlashLoan\|IPool" --include="*.sol" | grep -v "test\|mock"

# Proxy/Upgrade Patterns
rg -n "upgradeTo\|upgradeToAndCall\|delegatecall\|implementation" --include="*.sol" | grep -v "test\|mock"
```

### Tier 2 — Run If Tier 1 Hits

```bash
# Accounting Desync (28% of all Criticals)
rg -n "totalSupply\|totalAssets\|balanceOf\|sharesOf\|convertToShares" --include="*.sol" | grep -v "test\|mock"

# Signature Replay
rg -n "ecrecover\|ECDSA\|signature\|nonce\|DOMAIN_SEPARATOR" --include="*.sol" | grep -v "test\|mock"

# ERC4626 Vault
rg -n "deposit\|withdraw\|mint\|redeem\|totalAssets\|convertToShares\|convertToAssets" --include="*.sol" | grep -v "test\|mock"

# Access Control State
rg -n "grantRole\|revokeRole\|_grantRole\|DEFAULT_ADMIN_ROLE" --include="*.sol" | grep -v "test\|mock"

# Unsafe Math
rg -n "unchecked\{|\.add\(|\.sub\(|\.mul\(|SafeMath" --include="*.sol" | grep -v "test\|mock\|lib/"
```

### Tier 3 — Protocol-Specific

```bash
# Oracle Staleness
rg -n "block\.timestamp.*stale\|heartbeat\|roundId\|updatedAt" --include="*.sol"

# LP/Share Price
rg -n "getReserves\|token0\|token1\|totalSupply.*pool\|MINIMUM_LIQUIDITY" --include="*.sol"

# Admin/Privileged Roles
rg -n "OWNER_ROLE\|MANAGER_ROLE\|PAUSER_ROLE\|MINTER_ROLE\|STRATEGIST" --include="*.sol"
```

---

