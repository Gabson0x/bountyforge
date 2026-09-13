# FV-MOV-2: Access Control and Capabilities

Sui Move uses the capability object pattern as its primary access control mechanism. This category covers missing capability checks, incorrect visibility modifiers, phantom type bypass, and sender address spoofing.

## Cases

- [fv-mov-2-cl1-missing-capability-check.md](fv-mov-2-cl1-missing-capability-check.md) - Privileged function callable without a capability object
- [fv-mov-2-cl2-capability-lifecycle.md](fv-mov-2-cl2-capability-lifecycle.md) - Capability created outside `init` or OTW pattern missing
- [fv-mov-2-cl3-entry-visibility-bypass.md](fv-mov-2-cl3-entry-visibility-bypass.md) - `public(package) entry` overrides package-only restriction
- [fv-mov-2-cl4-sender-spoofing.md](fv-mov-2-cl4-sender-spoofing.md) - Caller address accepted as parameter instead of from TxContext

## Key Vectors

V1, V2, V6, V7, V8, V9, V10, V12, V13, V16, V21, V122, V123, V124
