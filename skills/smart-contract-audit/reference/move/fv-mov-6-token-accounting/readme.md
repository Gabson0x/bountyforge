# FV-MOV-6: Token and Coin Accounting

Sui separates `Coin<T>` (object with ID) from `Balance<T>` (internal value without ID). Confusing the two, violating supply invariants, or mishandling fees creates silent accounting errors and permanent fund loss.

## Cases

- [fv-mov-6-cl1-coin-balance-confusion.md](fv-mov-6-cl1-coin-balance-confusion.md) - `Coin<T>` and `Balance<T>` mixed without consistent accounting
- [fv-mov-6-cl2-supply-invariant-violations.md](fv-mov-6-cl2-supply-invariant-violations.md) - Mint without deposit, burn without release, or self-transfer side effects
- [fv-mov-6-cl3-fee-accounting.md](fv-mov-6-cl3-fee-accounting.md) - Fee bypass via alternate paths, non-atomic deduction, or no withdrawal function
- [fv-mov-6-cl4-dust-and-cleanup.md](fv-mov-6-cl4-dust-and-cleanup.md) - Dust locks objects, orphaned dynamic fields, `destroy_zero` on non-zero balance

## Key Vectors

V70, V71, V74, V75, V76, V77, V79, V81, V82, V83, V84, V85, V86, V87, V131, V140
