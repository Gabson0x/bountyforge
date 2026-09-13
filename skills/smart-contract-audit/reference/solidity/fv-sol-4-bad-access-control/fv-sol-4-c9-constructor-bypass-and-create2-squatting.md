# FV-SOL-4-C9 Constructor and Counterfactual Address Bypass

## TLDR

Two related patterns allow attackers to bypass access controls that assume `msg.sender` is an EOA or a not-yet-deployed address. During construction, `extcodesize` is zero even though the caller is a contract, allowing constructor-context calls to pass EOA-only guards. With CREATE2, if the salt is not bound to `msg.sender`, an attacker can precompute the deterministic address and deploy first, squatting the victim's expected counterfactual address and taking ownership.

## Detection Heuristics

**extcodesize Bypass**
- `require(msg.sender.code.length == 0)` or `require(extcodesize(caller()) == 0)` used as the primary security guard
- Pattern used in NFT minting limits, whitelist claims, or anti-bot checks where economic value is gated
- No secondary check preventing calls from constructor context (e.g., prior-block deposit requirement, signed permit, or merkle proof)

**CREATE2 Address Squatting**
- `salt` is user-supplied without incorporating `msg.sender` into the salt derivation
- Factory function calls `Create2.deploy(0, salt, bytecode)` where salt is a raw user-provided `bytes32`
- Account abstraction wallets where the counterfactual address is used for fund custody before deployment
- `initialize(owner)` called as a separate transaction after `Create2.deploy` - owner address squattable by a front-runner who deploys first

## False Positives

- `require(msg.sender.code.length == 0)` is non-security-critical (informational soft anti-bot only, no economic gating)
- Access protected by alternative mechanism: signed permit, merkle proof, or prior-block deposit that a constructor-context call cannot satisfy
- Salt binds to deployer: `keccak256(abi.encodePacked(msg.sender, userSalt))`
- Factory restricts deployment to whitelisted callers only
- Owner set via constructor argument embedded in `creationCode` - different owner produces a different deterministic address
