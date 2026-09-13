# FV-TON-2-CL3 Admin Authorization

## TLDR

Administrative operations (parameter updates, fund withdrawals, pausing, upgrading) that lack a sender address check against the stored admin/owner address allow any contract or wallet to invoke privileged functions.

## Detection Heuristics

**Missing sender validation on privileged opcodes**
- Handler for ops like `op::change_admin`, `op::withdraw`, `op::upgrade`, `op::set_params` has no `throw_unless(error::not_owner, equal_slices(sender_address, admin_address))`
- `admin_address` loaded from storage but the comparison is skipped or commented out
- Authorization check present only on some admin ops but not all - inconsistent coverage

**No admin transfer mechanism or insecure one**
- No `op::change_admin` or `op::transfer_ownership` handler - admin key loss permanently locks privileged functions
- Admin address change in a single step with no pending/confirm pattern - sending to a wrong address is irreversible
- Admin address stored in code cell (c3) instead of data cell (c4), requiring a full code upgrade to change it

**Tact contracts**
- Tact contract uses `Ownable` trait but one or more `receive()` handlers for administrative messages do not call `self.requireOwner()` before executing

## False Positives

- Contract is intentionally permissionless for the audited operation; confirm this is by design and there is no way to escalate to fund extraction
- Admin check implemented via a helper function - verify the helper performs `equal_slices(sender_address, admin_address)` and throws on mismatch
