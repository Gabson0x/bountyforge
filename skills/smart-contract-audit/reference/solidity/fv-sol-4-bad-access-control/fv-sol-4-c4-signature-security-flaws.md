# FV-SOL-4-C4 Signature Security Flaws

## TLDR

Signature-based authentication is vulnerable to three related issues: malleability (the same signing key produces two valid signatures for the same message), zero-address recovery (`ecrecover` returns `address(0)` for malformed signatures), and replay attacks (a valid signature used once can be reused). Raw use of `ecrecover` without input validation exposes all three.

## Detection Heuristics

**Signature Malleability**
- Raw `ecrecover` without `require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)`
- Both `(v, r, s)` and `(v', r, s')` recover the same address - bypasses signature-based deduplication
- Deduplication based on `(r, s)` bytes rather than a message hash nullifier

**ecrecover Returns address(0)**
- Raw `ecrecover` without `require(recovered != address(0))`
- If `authorizedSigner` is uninitialized or `permissions[address(0)]` is non-zero, any garbage signature gains privileges

**Signature Replay / Missing Nonce**
- Signed message has no per-user nonce, or nonce is present but not stored or incremented after use
- Same signature resubmittable indefinitely across transactions or chains
- No `chainId` or contract address bound into the signed digest

## False Positives

- OZ `ECDSA.recover()` used (validates `s` range and reverts on `address(0)`)
- Message hash used as deduplication key (not raw signature bytes) preventing malleability bypass
- Monotonic per-signer nonce included in signed payload, checked and incremented atomically
- `usedSignatures[hash]` mapping marks signatures as consumed after first use
