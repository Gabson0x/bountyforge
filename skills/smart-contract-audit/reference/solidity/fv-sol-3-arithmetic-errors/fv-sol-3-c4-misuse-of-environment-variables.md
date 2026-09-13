# FV-SOL-3-C4 Misuse of Environment Variables

## TLDR

Environment variables such as `block.timestamp`, `block.number`, and `block.basefee` carry miner- or validator-influenced values that should not be used as precise inputs to arithmetic or access control. Small manipulations of `block.timestamp` (up to ~15 seconds on Ethereum mainnet) are within validator discretion, and `block.number` advances at variable real-world time between networks. Arithmetic that assumes exact or predictable values from these variables is exploitable or unreliable.

## Detection Heuristics

**Timestamp Arithmetic for Time-Sensitive Logic**
- `block.timestamp +/- N` used to set deadlines, unlock times, or cooldown windows shorter than ~15 minutes
- `require(block.timestamp >= start + duration)` where `duration` is seconds-to-minutes scale
- `block.timestamp % period` used for slot selection, randomness, or round scheduling

**Timestamp as Randomness Source**
- `block.timestamp` hashed alone or combined only with on-chain predictable values to seed randomness
- `uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)))` used as a random number
- Lottery, NFT reveal, or game outcome determined solely from block-level variables

**Block Number as Wall-Clock Proxy**
- `block.number * SECONDS_PER_BLOCK` used for time calculations where `SECONDS_PER_BLOCK` is hardcoded
- Hardcoded assumption (e.g., 6500 blocks per day) applied across multiple chain deployments without network-specific override
- Vesting or interest calculation based on block number difference using a fixed rate not validated per network

**Arithmetic Overflow With Environment Variables**
- `block.timestamp + userSuppliedOffset` where offset is unbounded (can overflow `uint256`)
- `block.basefee * gasEstimate` without overflow guard in fee accounting
- `block.number - deployBlock` underflow if deployment block stored incorrectly

## False Positives

- Time windows measured in hours or days where sub-minute manipulation is economically irrelevant to the outcome
- `block.timestamp` used only for logging in events, not for access control or arithmetic
- `block.number` used with a network-specific, governance-updatable rate parameter rather than a hardcode
- Chainlink VRF or equivalent verifiable randomness used alongside block variables without relying on them for entropy
- Timestamp comparison with wide tolerance band: `require(block.timestamp >= deadline - TOLERANCE)` where `TOLERANCE` absorbs manipulation
