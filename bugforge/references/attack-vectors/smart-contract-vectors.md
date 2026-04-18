# Smart Contract Attack Vectors

## EVM / Solidity
- Reentrancy: single, cross-function, cross-contract, read-only
- Integer overflow/underflow (pre-0.8, unchecked blocks)
- Signature replay: missing chainId, nonce, deadline
- ecrecover zero address return
- Oracle manipulation: spot price, short TWAP, stale Chainlink
- Flash loan: single-tx price manipulation, governance vote
- First depositor inflation attack
- Front-running: DEX swap, liquidation, NFT mint
- Proxy storage collision, uninitialized implementation, UUPS guard bypass
- Access control: unprotected initializer, inconsistent modifier, tx.origin auth
- Unchecked return values from low-level calls
- Block timestamp dependence
- Denial of service: unbounded loop, forced revert, block gas limit

## Move / Aptos
- Capability copied or dropped unexpectedly
- borrow_global_mut without ownership check
- Object type confusion (attacker passes wrong object type)
- upgrade_policy too permissive
- Upgrade capability publicly accessible
- CCTP: single-attester threshold, attester rotation race
- Missing zero-address guard on role functions
- Orphaned minter allowance after removal
- Generic type T not constrained to expected coin type

## Solana / Anchor
- Missing account owner check
- Missing signer check
- Missing has_one or constraint
- PDA seed collision
- Unchecked CPI target
- Token account owner not validated
- Non-canonical bump seed

## TRON
- TRC20 transferFrom without allowance check
- int overflow in mulDiv (pre-0.8 patterns)
- block.number used as timestamp
- Stake 2.0 resource ceiling silent failure
- eth_call pending block tag fallthrough

## Cross-Chain / Bridges
- Message replay across domains
- Missing destination domain validation
- Attester/relayer single point of failure
- Replace-before-revoke gap window
- Bridge message race condition
