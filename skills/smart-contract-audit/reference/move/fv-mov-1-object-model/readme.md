# FV-MOV-1: Object Model and Abilities

Sui Move's type system grants objects abilities: `copy`, `drop`, `store`, and `key`. Incorrect ability assignment is a primary source of critical vulnerabilities. This category also covers object wrapping, dynamic fields, and unauthorized sharing or freezing.

## Cases

- [fv-mov-1-cl1-copy-ability-duplication.md](fv-mov-1-cl1-copy-ability-duplication.md) - Value-bearing object has `copy`, enabling token duplication
- [fv-mov-1-cl2-drop-ability-debt-destruction.md](fv-mov-1-cl2-drop-ability-debt-destruction.md) - Obligation object has `drop`, enabling silent debt erasure
- [fv-mov-1-cl3-store-ability-wrapping.md](fv-mov-1-cl3-store-ability-wrapping.md) - Capability object has `store`, enabling unauthorized wrapping or transfer
- [fv-mov-1-cl4-object-wrapping-lock.md](fv-mov-1-cl4-object-wrapping-lock.md) - Object wrapped by third-party contract with no unwrap path

## Key Vectors

V3, V4, V5, V6, V24, V25, V28, V29, V30, V126
