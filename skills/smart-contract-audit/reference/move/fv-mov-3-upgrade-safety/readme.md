# FV-MOV-3: Package Upgrades and Lifecycle

Sui Move has unique upgrade semantics: `init` does not run on upgrade, struct fields are forward-compatible only, and `UpgradeCap` is the single point of control over future code. Errors here are typically critical or high severity.

## Cases

- [fv-mov-3-cl1-init-upgrade-assumptions.md](fv-mov-3-cl1-init-upgrade-assumptions.md) - Logic assumes `init` re-runs on upgrade; post-upgrade state left uninitialized
- [fv-mov-3-cl2-version-check-missing.md](fv-mov-3-cl2-version-check-missing.md) - Shared objects have no `version` field or public functions do not check it
- [fv-mov-3-cl3-struct-field-evolution.md](fv-mov-3-cl3-struct-field-evolution.md) - Fields reordered or removed in upgrade, breaking existing object deserialization
- [fv-mov-3-cl4-upgrade-cap-security.md](fv-mov-3-cl4-upgrade-cap-security.md) - `UpgradeCap` held by single EOA or destroyed prematurely

## Key Vectors

V17, V18, V19, V20, V43, V44, V45, V46, V47, V107, V108, V120, V134
