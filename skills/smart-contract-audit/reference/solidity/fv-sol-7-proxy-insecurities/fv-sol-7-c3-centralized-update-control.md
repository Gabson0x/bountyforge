# FV-SOL-7-C3 Centralized Update Control

## TLDR

When upgrade authority is held by a single EOA or unconstrained admin address, a compromised or malicious key holder can replace the implementation with arbitrary code, draining funds or bricking the contract. This represents a critical trust assumption that undermines the security guarantees of the protocol for all users.

## Detection Heuristics

**Single EOA Holds Upgrade Authority**
- `require(msg.sender == admin, ...)` in upgrade function where `admin` is set to `msg.sender` in the constructor
- No multisig, timelock, or governance contract in the upgrade call chain
- Admin address is a regular EOA rather than a contract address

**No Timelock on Upgrades**
- `updateImplementation` or `upgradeTo` takes effect immediately without a queuing delay
- No `TimelockController` or equivalent in the upgrade path
- Users have no window to exit before a new implementation is active

**Admin Role Non-Transferable or Irrevocable**
- No mechanism to transfer admin to a more secure address after deployment
- No two-step admin transfer (propose + accept) to prevent accidental lockout

**Lack of Upgrade Event or Transparency**
- Implementation change emits no event or logs no verifiable on-chain record
- No mechanism for users or watchers to detect that an upgrade has occurred

## False Positives

- Admin is a multisig wallet (e.g., Gnosis Safe) with a threshold requiring multiple independent signers
- Upgrade function is gated behind a governance contract with on-chain voting and a timelock
- Upgrades require a two-step process: proposal followed by a time-delayed execution
- Protocol is in a guarded launch phase with planned migration to decentralized governance, documented and time-bounded
