# FV-MOV-8: Advanced Patterns and Real-World Exploits

This category captures patterns that emerged from 1141 real findings across 200+ Move audits, including named exploits (Cetus, Baptswap, Bluefin, KriyaDEX, Thala Labs). These are high-signal, high-severity patterns confirmed in production codebases.

## Cases

- [fv-mov-8-cl1-generic-type-confusion.md](fv-mov-8-cl1-generic-type-confusion.md) - Unvalidated generic `T` allows fake token injection (Navi, Econia pattern)
- [fv-mov-8-cl2-table-collection-bugs.md](fv-mov-8-cl2-table-collection-bugs.md) - Table duplicate key DoS, vector size limits, orphaned collections
- [fv-mov-8-cl3-flash-loan-receipt-binding.md](fv-mov-8-cl3-flash-loan-receipt-binding.md) - Receipt without pool_id binding; nested start resets snapshot (Cetus, Dexlyn)
- [fv-mov-8-cl4-real-world-exploits.md](fv-mov-8-cl4-real-world-exploits.md) - Transposed return values, self-referential assertions, accumulator ordering (KriyaDEX, Hop, Thala)

## Key Vectors

V72, V73, V121, V124, V125, V126, V127, V129, V130, V131, V132, V135, V136, V141, V142, V143
