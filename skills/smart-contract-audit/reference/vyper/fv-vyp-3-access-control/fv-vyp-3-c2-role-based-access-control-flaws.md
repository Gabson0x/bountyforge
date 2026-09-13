# FV-VYP-3-C2 Role-Based Access Control Flaws

## TLDR

Vyper has no native role system. Contracts that implement role hierarchies using `HashMap[address, bool]` are prone to privilege escalation when lower-privileged roles can grant themselves or others higher privileges, or when role checks are applied to the wrong operations.

## Detection Heuristics

**Horizontal privilege escalation: role members can add peers**
- A function gated by `assert self.moderators[msg.sender]` also writes `self.moderators[new_address] = True`, allowing any moderator to create additional moderators without admin approval
- `assert self.operators[msg.sender]` used to guard `self.operators[target] = True`, creating an unbounded role-grant loop

**Role assigned to funds or critical operations that should require admin**
- `assert self.moderators[msg.sender]` gates `raw_call(msg.sender, b"", value=amount)` or other fund-moving operations that should require a higher-privilege role
- A role check that is appropriate for read operations is reused verbatim on write or withdrawal operations

**Role revocation not implemented or callable by the role member themselves**
- No function exists to revoke a role, making compromised role holders permanent
- `self.moderators[msg.sender] = False` callable by the role member, allowing self-revocation to evade detection after an exploit

**Default HashMap value exploited as implicit role**
- `HashMap[address, bool]` defaults to `False` for unset keys; a bug in initialization logic that sets a default-valued entry to `True` could grant unexpected access
- Zero address (`empty(address)`) implicitly holds a role because no explicit exclusion is checked

**No separation between role administration and role usage**
- The same check (`assert self.admins[msg.sender]`) guards both the ability to grant roles and the ability to use those roles in sensitive operations, conflating administration and execution

## False Positives

- Role-gated functions where the role exclusively controls non-fund, non-state-critical operations such as metadata updates or display parameters
- Multi-sig or DAO-controlled admin addresses where the role-grant function is protected by an off-chain governance process even if the on-chain check appears weak in isolation
- Explicit role hierarchies where the admin role is separated from the operator role and the grant function verifies `msg.sender == self.admin` rather than any role mapping