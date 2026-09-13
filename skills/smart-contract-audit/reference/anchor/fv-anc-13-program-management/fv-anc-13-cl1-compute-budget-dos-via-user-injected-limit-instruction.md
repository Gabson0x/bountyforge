# FV-ANC-13-CL1 Compute Budget DoS via User-Injected Limit Instruction

## TLDR

Solana transactions can include a `SetComputeUnitLimit` instruction that caps the compute units available for the entire transaction. A malicious user can prepend a `SetComputeUnitLimit` with a very low value before calling a protocol instruction, causing the instruction to exhaust compute units and fail. If a critical operation (liquidation, settlement, position close) can be DoS'd this way, it creates a window for economic exploitation.

## Detection Heuristics

**Protocol Does Not Read or Validate Compute Budget**
- Protocol has no mechanism to detect or reject transactions where a `SetComputeUnitLimit` instruction has set the limit below the instruction's required compute units
- Instruction whose compute cost varies with input size (e.g., iterating over positions) does not enforce a minimum compute budget at entry
- Critical operations (liquidation, forced settlement) executable by anyone have predictable compute costs that can be targeted with a precise low compute limit

**No Protection on Critical Paths**
- Liquidation, position close, or settlement instruction does not set its own compute request via a CPI to the Compute Budget program to ensure sufficient units are reserved
- Protocol documentation does not mention compute budget injection as a known DoS vector despite having instructions with variable compute cost
- No transaction simulation or compute budget check in off-chain keeper infrastructure that submits critical transactions

**Keeper Infrastructure Gap**
- Keeper that triggers liquidations uses a fixed compute budget that can be undercut by a user who adds a lower `SetComputeUnitLimit` before the keeper's instruction in the same bundle

## False Positives

- All critical instructions are only callable by a trusted keeper or admin that submits transactions via a private relay; no public user can prepend instructions
- Protocol's critical instructions have bounded, low, fixed compute costs that cannot be targeted effectively with a compute limit attack
