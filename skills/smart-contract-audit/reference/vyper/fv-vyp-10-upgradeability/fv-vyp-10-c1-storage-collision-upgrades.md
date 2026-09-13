# FV-VYP-10-C1 Storage Collision in Upgrades

## TLDR

Vyper assigns storage slots sequentially in declaration order, without the EIP-1967 slot reservation pattern used by many Solidity proxy frameworks. When an upgradeable proxy delegates to a new implementation that reorders or inserts storage variables, previously stored values are reinterpreted under the wrong variable names, corrupting contract state.

## Detection Heuristics

**New storage variables inserted between existing declarations**
- Implementation V2 declares a new state variable between two variables that existed in V1, shifting all subsequent slots by one
- Comparison of V1 and V2 source shows differing declaration order for any subset of variables that were live in V1

**Variable renamed or retyped at the same declaration position**
- A slot previously holding an `address` is now declared as `uint256` or vice versa without a corresponding data migration
- A `HashMap[address, uint256]` replaced by `HashMap[address, bool]` at the same position, silently truncating stored values

**No reserved gap slots in V1**
- V1 implementation contains no `_reserved0`, `_reserved1`, ... placeholder variables to absorb future additions
- All storage declarations in V1 are immediately followed by logic without any gap or explicit storage layout comment

**Proxy pattern using `delegatecall` without layout enforcement**
- Contract uses `raw_call` with `is_delegate_call=True` or an external proxy routes through `delegatecall` to a Vyper implementation
- No off-chain storage layout snapshot (e.g., Ape, Brownie, or `vyper -f layout` output) checked against the previous version

**`__init__` re-executed on upgrade writing over live storage**
- Upgrade flow calls `__init__` on the new implementation through the proxy, overwriting `owner` or other critical variables stored at slot 0

## False Positives

- Contracts that only append new variables at the end of the storage declaration list without inserting between or reordering existing ones
- Non-upgradeable contracts deployed fresh with each version where no prior state persists across deployments
- Proxy implementations where storage is intentionally segregated using a fixed high-entropy slot via inline assembly, verified against the deployed bytecode layout