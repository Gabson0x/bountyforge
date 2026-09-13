# FV-ANC-4-CL4 PDA Purpose Isolation Failure

## TLDR

When different instruction handlers derive PDAs using identical or overlapping seed sets, an attacker can substitute one PDA in place of another. Instructions that accept a PDA account by key alone without validating its discriminator or type-specific field allow cross-context injection, enabling an attacker to satisfy an account constraint with a PDA intended for a different purpose.

## Detection Heuristics

**Identical Seeds Across Multiple Account Types**
- Multiple instruction handlers accept PDAs derived from the same seed set (e.g., `[b"config", user.key()]`) but interpret the resulting account data as different struct types
- Seed construction does not include a type discriminator prefix or namespace byte to distinguish purposes
- Two different Anchor account types share the same seeds constraint, meaning a valid account of one type passes the seeds check for the other

**Missing Discriminator or Type Validation**
- Account passed as `UncheckedAccount` or raw `AccountInfo` without a discriminator check in the instruction logic
- Anchor `Account<'_, T>` constraint omitted, allowing any account at that address to satisfy the constraint
- Program manually checks only the account key and skips checking that the data matches the expected struct layout

**Accepted PDA Not Namespaced**
- PDA seeds lack a static namespace prefix (e.g., `b"user_config"` vs `b"user_stake"`) that would make the same user key produce distinct addresses for distinct purposes
- Seed byte arrays reused across programs or program versions without a version discriminator

## False Positives

- PDAs include a type-specific constant seed prefix that makes seed collision between different account types impossible
- Anchor's automatic 8-byte discriminator check on `Account<'_, T>` prevents accepting an account of the wrong type even if keys match
