# FV-MOV-4: Shared Objects and PTBs

Sui's shared object model and programmable transaction blocks (PTBs) introduce concurrency, composability, and flash-loan attack surfaces not present in owned-object designs. Hot potato pattern enforcement and clock usage are the primary correctness mechanisms.

## Cases

- [fv-mov-4-cl1-shared-object-races.md](fv-mov-4-cl1-shared-object-races.md) - Concurrent mutations without version/sequence check cause lost updates
- [fv-mov-4-cl2-hot-potato-flash-loan.md](fv-mov-4-cl2-hot-potato-flash-loan.md) - Flash loan receipt has incorrect abilities or missing pool binding
- [fv-mov-4-cl3-ptb-price-manipulation.md](fv-mov-4-cl3-ptb-price-manipulation.md) - PTB atomicity enables borrow-manipulate-exploit-repay in one transaction
- [fv-mov-4-cl4-clock-and-time.md](fv-mov-4-cl4-clock-and-time.md) - Clock not used, wrong time unit, or missing deadline parameter

## Key Vectors

V31, V32, V34, V35, V36, V40, V41, V42, V50, V51, V52, V53, V58, V127, V128, V129
