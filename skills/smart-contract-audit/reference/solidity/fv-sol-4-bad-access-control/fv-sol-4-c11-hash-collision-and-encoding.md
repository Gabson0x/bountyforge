# FV-SOL-4-C11 Hash Collision via Encoding and Calldata Malleability

## TLDR

Two encoding bugs allow attackers to produce colliding hashes or bypass deduplication. When `abi.encodePacked` is used with two or more dynamic-type arguments, inputs with different field boundaries but identical concatenated bytes produce the same hash. When protocols deduplicate by hashing raw `msg.data`, attackers can produce semantically identical but bytewise-different calldata by manipulating ABI offset pointers, bypassing replay protection.

## Detection Heuristics

**abi.encodePacked Collision**
- `keccak256(abi.encodePacked(a, b, ...))` where two or more arguments are `string`, `bytes`, or dynamic arrays
- Result used as access control key, nullifier, permit hash, or uniqueness check
- Solidity compiler warning about tight packing with dynamic types present and unresolved
- Two distinct input combinations produce the same packed bytes (e.g., `("a","bc")` and `("ab","c")`)

**Calldata Malleability**
- `keccak256(msg.data)` used for replay protection or deduplication of relayed transactions
- Function accepts dynamic types in calldata (strings, bytes, or arrays) with ABI offset pointers
- Non-canonical ABI encoding: malformed offset pointers decode to the same Solidity values but differ in raw bytes
- `calldataload(offset)` at hardcoded positions assuming standard canonical ABI layout

## False Positives

- `abi.encode()` used instead of `abi.encodePacked` - includes length prefixes, no boundary collision possible
- Only one dynamic type argument present (no collision possible with a single dynamic argument)
- All arguments are fixed-size types (`address`, `uint256`, `bytes32`) - calldata is non-malleable
- Deduplication hashes decoded parameters rather than raw calldata: `keccak256(abi.encode(decodedA, decodedB))`
- Nonce-based replay protection makes calldata-level uniqueness irrelevant
