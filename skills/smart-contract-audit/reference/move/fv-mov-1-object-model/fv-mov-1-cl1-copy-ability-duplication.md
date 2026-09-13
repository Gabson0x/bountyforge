# FV-MOV-1-CL1: Copy Ability Enables Token Duplication

## TLDR

A value-bearing object (coin, NFT, badge, receipt, staking position) granted the `copy` ability can be duplicated by any holder. The attacker duplicates a token to drain pools, inflate supply, or repeatedly spend the same credential.

## Detection Heuristics

- Read every struct definition in the codebase; for any struct with `copy` in its ability list, assess whether it holds financial value, represents ownership, or grants authority
- Search: `struct .* has .*copy` in all `.move` files
- For coin-like types or share types, `copy` is always incorrect - they must be consumed on use
- Pay special attention to receipt structs, LP position structs, and badge structs that flow through `deposit`, `withdraw`, or `claim` functions
- If the struct is used as a function argument and the function does not consume it (no `let _ =`), check whether the caller can reuse the same value

## False Positives

- Struct explicitly designed to be copyable: configuration data, read-only references, display metadata with no authority semantics
- Struct is used only via immutable reference (`&T`) in all callsites and copying is harmless
- Protocol documentation explicitly states `copy` is intentional with rationale
