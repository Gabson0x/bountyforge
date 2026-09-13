# FV-SOL-5-C9 Deployment and Configuration Pitfalls

## TLDR

Errors in deployment scripts and contract configuration cause permanent misconfiguration or front-runnable initialization windows. These are not runtime logic bugs but deployment-time failures that are often irrecoverable.

Key patterns:
- **Cross-chain replay**: deployment tx replayed on other chains (same nonce → same CREATE address, different owner/state)
- **Nonce gap from reverted txs**: pre-computed CREATE addresses wrong if intermediate tx reverts
- **Missing chain ID validation**: scripts that broadcast without asserting `block.chainid`
- **Non-atomic deployment**: separate deploy + initialize transactions leave a front-runnable window
- **Immutable misconfiguration**: constructor args silently swapped (multiple same-type addresses)
- **Hardcoded addresses**: literal `address(0x...)` for external dependencies, wrong on other chains
- **Block number as timestamp**: `block.number * 13` assumes fixed block times across chains

## Detection Heuristics

**Cross-Chain Replay / Wrong Network**
- `block.chainid` not asserted at start of deployment script or in constructor
- No `--chain-id` flag in Foundry script; no EIP-155 enforcement
- Same deployer EOA used across chains without nonce tracking

**Nonce Gap / CREATE Address Mismatch**
- Deployment script uses `CREATE` with pre-computed addresses from deployer nonce
- Multiple `vm.broadcast()` blocks with intermediate revertable calls
- Addresses stored in config before deployment receipt confirmed

**Non-Atomic Deploy + Init**
- `new Proxy(impl, admin, "")` with empty data, `initialize()` called in separate tx
- Uninitialized proxy in public mempool between two transactions

**Immutable Misconfiguration**
- Multiple `address` parameters in constructor without named deployment config
- Post-deploy assertions absent from deployment script

**Block Number as Timestamp**
- `(block.number - startBlock) * 13` for vesting/interest/reward calculation
- Hardcoded block time constant used on multi-chain deployment

**Hardcoded Addresses**
- Literal `address(0x...)` for routers, oracles, tokens in production code
- No per-chain config file keyed by `block.chainid`

## False Positives

- `require(block.chainid == expectedChainId)` at script start
- `block.timestamp` used for all time calculations
- Atomic deploy: init calldata passed in proxy constructor `new Proxy(impl, admin, initData)`
- `_disableInitializers()` in implementation constructor
- Per-chain config file with addresses looked up by `block.chainid`
- Deployment script reads back and asserts every configured immutable value
- `CREATE2` used - nonce-independent, pre-computed addresses correct regardless of intermediate reverts
