# FV-ANC-3-CL14 realloc Without zero_init

## TLDR

Anchor's `realloc` constraint expands an account's data allocation. When `realloc::zero_init = false`, newly exposed bytes from the previous allocation are not zeroed and may contain stale data from prior account usage. Reading those bytes as structured fields yields unpredictable values.

## Detection Heuristics

**realloc::zero_init = false on Expanding Reallocations**
- `#[account(mut, realloc = new_size, realloc::payer = payer, realloc::zero_init = false)]` where `new_size` is larger than the account's current size
- Instruction body reads fields in the newly allocated region without manually zeroing them first

**Stale Byte Exposure After Size Increase**
- Account previously used for a different data structure, closed, and then reallocated to a new type without zeroing; residual bytes from the old structure appear in new fields
- Reallocation performed in a loop where each iteration may expose previously used memory from a prior account lifecycle

**Missing Manual Zero in Instruction Body**
- `realloc::zero_init = false` used and no `data[old_size..new_size].fill(0)` or equivalent in the instruction body before reading new fields

## False Positives

- `realloc::zero_init = false` used only for shrinking allocations, where no new bytes are exposed
- Instruction immediately overwrites all newly allocated bytes with explicit values before any read, making the initial content irrelevant
