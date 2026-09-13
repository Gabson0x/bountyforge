# FV-SOL-4-C7 ERC-1271 Signature Validation Delegation

## TLDR

ERC-1271 allows smart contract accounts to validate signatures by implementing `isValidSignature(bytes32 hash, bytes calldata signature) returns (bytes4)`. When a protocol relies on this for authorization and the implementation delegates to an externally-supplied or insufficiently-guarded module, a malicious module can always return the magic value `0x1626ba7e`, bypassing all signature checks unconditionally.

## Detection Heuristics

**Unguarded Module Delegation**
- `isValidSignature` delegates to an address stored in state that is settable by any caller without access control
- `setSignatureModule(address)` or equivalent has no `onlyOwner` or guardian check
- Any address can deploy a contract returning `0x1626ba7e` unconditionally and register it as the active module

**Module Registry Without Approval Gate**
- Module address stored in a mutable state variable with no timelock or multisig approval requirement before activation
- No whitelist of audited modules - arbitrary user-deployed contracts accepted

**Return Value Not Validated**
- Caller of `isValidSignature` treats any non-reverting response as valid without checking the exact `bytes4` return value equals `0x1626ba7e`
- Protocol accepts `true` or non-zero return instead of the exact magic bytes

## False Positives

- Module delegation restricted to an owner-controlled whitelist of audited contracts
- Module registry requires timelock or multisig guardian approval before a new module becomes active
- `isValidSignature` implementation is self-contained with no external delegation
- Module address is immutable or set only once in the constructor
