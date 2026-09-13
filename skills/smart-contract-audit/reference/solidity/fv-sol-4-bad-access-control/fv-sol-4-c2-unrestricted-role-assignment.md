# FV-SOL-4-C2 Unrestricted Role Assignment

## TLDR

When a function that assigns ownership, admin rights, or privileged roles is public and lacks any access control guard, any caller can elevate their own privileges or assign them to an attacker-controlled address, taking full control of the contract.

## Detection Heuristics

**Unguarded Role-Assignment Function**
- `public` or `external` function that writes to `owner`, `admin`, or a role-tracking mapping without a `require(msg.sender == admin)` or role-based modifier
- Missing `onlyOwner`, `onlyRole`, or equivalent guard on any function that grants or revokes roles
- `setOwner(address)`, `grantRole(bytes32, address)`, `addAdmin(address)` callable by any address

**Initialization-Time Exposure**
- `initialize()` function with no access control that sets owner - callable by anyone after deployment if not called atomically
- Proxy pattern where `initialize` is not gated by `initializer` modifier, allowing re-initialization

**Indirect Privilege Escalation**
- A public function that writes to a mapping used later as an authorization check without validating who the caller is
- `privilegedUsers[user] = true` reachable without a caller identity check

## False Positives

- Role-assignment function is `internal` or `private`
- `onlyOwner` or `onlyRole` modifier present and correctly enforced
- Assignment occurs exclusively in the `constructor` where `msg.sender` is implicitly trusted
- OpenZeppelin `AccessControl` or `Ownable` used without overrides that bypass guards
