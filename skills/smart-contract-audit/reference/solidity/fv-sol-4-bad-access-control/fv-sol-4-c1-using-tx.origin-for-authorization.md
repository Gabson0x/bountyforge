# FV-SOL-4-C1 Using tx.origin for Authorization

## TLDR

`tx.origin` always resolves to the original EOA that initiated the transaction, regardless of how many contracts the call passed through. A malicious contract invoked by a privileged user can exploit this to impersonate that user in any contract that relies on `tx.origin` for access control.

## Detection Heuristics

**tx.origin Used as Access Guard**
- `require(tx.origin == admin)` or `require(tx.origin == owner)` as the sole authorization check
- `if (tx.origin != trustedAddress) revert` pattern in state-changing functions
- `tx.origin` compared against any stored address to gate privileged operations

**Combination Patterns That Still Fail**
- `tx.origin` used as a fallback when `msg.sender` check fails - still exploitable via phishing
- `tx.origin` used to set an owner or beneficiary address during initialization, then later compared for authorization

## False Positives

- `msg.sender` is used instead of `tx.origin` for the authorization check
- `tx.origin` appears only in event emissions or logging, not in require/revert guards
- `tx.origin == msg.sender` used to assert caller is an EOA with no downstream privileged action gated solely on that check
