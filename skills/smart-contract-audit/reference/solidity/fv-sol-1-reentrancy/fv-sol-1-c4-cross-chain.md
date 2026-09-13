# FV-SOL-1-C4 Cross Chain

## TLDR

Cross-chain reentrancy exploits the absence of replay protection and access control on bridge completion functions. An attacker triggers `completeTransfer` (or equivalent) from a manipulated or replayed cross-chain message, crediting balances that were never actually locked on the source chain. The asynchronous nature of cross-chain messaging makes state inconsistencies harder to detect and replay attacks easier to execute.

## Detection Heuristics

**Unguarded Bridge Completion Functions**
- `completeTransfer`, `finalizeDeposit`, `mintWrapped`, or equivalent functions callable by any address without `onlyTrustedRelayer` or equivalent access control
- No check that `msg.sender` is an authorized bridge relayer, oracle, or trusted remote contract
- No verification of a cryptographic proof, Merkle root, or signed attestation from the source chain

**Missing Replay Protection**
- No nonce, `messageId`, or transaction hash tracked in a `processedMessages` mapping
- `completeTransfer` can be called multiple times with the same parameters

**State Increment Without Source-Chain Proof**
- Direct `balances[user] += amount` or `token.mint(user, amount)` triggered solely by calldata values with no on-chain evidence of the source-chain lock
- Emitting `TransferCompleted` before or without atomically marking the message as processed

## False Positives

- Completion function restricted to a trusted relayer or verified bridge contract via `onlyOwner`, role-based access control, or signature verification
- Each bridge message identified by a unique ID and tracked in a `processedMessages` or equivalent mapping that prevents replay
- Amount credited is verified against a Merkle proof or signed attestation anchored to a finalized source-chain block
- Source-chain lock is atomically verified and consumed in the same transaction as the destination-chain credit
