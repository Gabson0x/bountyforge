# FV-SOL-7-C7 Diamond Proxy Pitfalls

## TLDR

EIP-2535 Diamond proxies introduce unique storage and selector collision risks beyond standard proxy patterns. Facets that declare top-level state variables all start at slot 0, overwriting each other's data. Adding a facet with a selector that already exists in another facet hijacks all calls to that function. Shared `DiamondStorage` structs accessed at non-namespaced slots collide with facet storage.

## Detection Heuristics

**Cross-Facet Storage Collision**
- Facet contracts declare top-level `uint256`, `address`, or other state variables (not inside a struct)
- `assembly { ds.slot := 0 }` or low-numbered slot for `DiamondStorage` struct
- No EIP-7201 `@custom:storage-location` annotation on storage structs

**Selector Collision on diamondCut**
- `diamondCut` implementation doesn't check for existing selectors before registering
- `DiamondLoupeFacet.facetFunctionSelectors()` not called to verify post-cut state
- No governance review of selector collision before upgrade

**Shared DiamondStorage Not Namespaced**
- Multiple facets import and mutate the same `DiamondStorage` struct
- Storage position derived from sequential slot or small constant
- Storage position not verified against EIP-7201 formula

## False Positives

- All facets use EIP-7201 namespaced storage: `keccak256(abi.encode(uint256(keccak256("namespace")) - 1)) & ~bytes32(uint256(0xff))`
- No top-level state variables in any facet - only function definitions and struct definitions
- `diamondCut` validates no selector collisions before registering
- `DiamondLoupeFacet` enumerates all selectors post-cut for off-chain verification
- Multisig + timelock on `diamondCut` with mandatory selector review step
