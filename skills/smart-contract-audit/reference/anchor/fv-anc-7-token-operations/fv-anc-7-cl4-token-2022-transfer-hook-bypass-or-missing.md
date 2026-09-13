# FV-ANC-7-CL4 Token-2022 Transfer Hook Bypass or Missing

## TLDR

Token-2022 mints can register a transfer hook program that must be invoked on every token transfer. Programs that use the legacy `spl_token::transfer` instruction or call the SPL Token program ID directly (`TokenkegQfe...`) bypass the hook entirely, violating the mint's invariants and potentially enabling unauthorized transfers, compliance bypasses, or protocol accounting errors.

## Detection Heuristics

**Legacy spl_token Used for Token-2022 Mints**
- Token transfer uses `spl_token::instruction::transfer` or passes the SPL Token program ID (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`) for a mint that is actually a Token-2022 mint (program ID: `TokenzQdBNbEqunMB4obVY4sQnrvdGUFkRGXWdTZ...`)
- Program does not check the mint's token program ID before constructing the transfer instruction
- CPI to transfer tokens does not include the hook program account when the mint extension `TransferHook` is present and has a non-None program address

**Hook Account Missing from CPI**
- `token_2022::transfer_checked` call does not include the hook program account in the remaining_accounts list
- Transfer amount not checked against any hook program return value or hook-imposed constraint
- Hook program account not loaded or its address not validated before the transfer CPI

**Transfer Hook Not Invoked at All**
- Program constructs raw instruction data for an SPL transfer without going through `spl_token_2022` crate helpers that automatically include hook invocation
- Token account close or burn operations that interact with a token-2022 mint also skip hook invocation

## False Positives

- Mint is a legacy SPL Token mint (program ID `TokenkegQfe...`); Token-2022 extensions do not apply
- Token-2022 mint with a `TransferHook` extension where the hook program address is explicitly `None`; no hook invocation required
