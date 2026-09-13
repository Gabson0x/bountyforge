# FV-ANC-7-CL7 Unconstrained Freeze Authority

## TLDR

A token account can be frozen by the mint's freeze authority at any time, permanently preventing deposits, withdrawals, and transfers. Protocols that accept tokens from mints where freeze authority has not been revoked expose themselves to an attack or admin error where a malicious or compromised freeze authority bricks all protocol operations involving that token.

## Detection Heuristics

**Freeze Authority Not Verified at Initialization**
- Vault, pool, or market initialization does not check that `mint.freeze_authority == COption::None`
- Mint account loaded as a typed `Mint` struct but `freeze_authority` field not inspected before accepting the mint into the protocol
- Token initialization accepts user-supplied mints without validating freeze authority revocation status

**Arbitrary Mint Acceptance**
- Protocol accepts any SPL Token or Token-2022 mint without a whitelist or freeze authority check
- Deposit or swap paths register new tokens on-the-fly without verifying freeze authority at registration time
- Integration with a permissioned stablecoin or centralized token where freeze authority exists by design but no operational controls are documented

**No Monitoring or Circuit Breaker**
- Protocol has no off-chain monitoring for freeze authority transactions; a freeze could go undetected until users report fund inaccessibility
- No emergency withdraw path that bypasses normal token transfer logic in the event of a frozen account

## False Positives

- Protocol operates exclusively with a hardcoded set of known mints where freeze authority has been verifiably set to `None` on-chain
- Freeze authority is a well-documented protocol DAO with a documented governance process, and protocol documentation acknowledges and accepts this counterparty risk
