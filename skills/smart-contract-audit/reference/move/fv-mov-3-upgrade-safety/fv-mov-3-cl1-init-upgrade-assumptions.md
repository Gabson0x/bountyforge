# FV-MOV-3-CL1: init Assumptions After Upgrade

## TLDR

In Sui Move, the `init` function runs only once at first deployment. Package upgrades do NOT re-execute `init`. Code that relies on `init` running again to reset state, create new capabilities, or initialize new fields will leave post-upgrade state uninitialized.

## Detection Heuristics

- Look for `init` functions that create capabilities or configure shared objects, then check whether any upgrade scenario requires those to be re-run
- Search for new struct fields added in an upgrade that are initialized to zero/default but require a non-zero starting value
- Check whether a `migrate()` or `upgrade_v2()` function exists and is called as part of the upgrade plan
- Verify that any code path depending on a freshly-initialized state variable accounts for the case where `init` has already run and the variable holds the old value

## False Positives

- Migration function explicitly handles all post-upgrade initialization
- New fields are safely defaulted to zero/false and require no special initialization
- No new state introduced in the upgrade that depends on `init` semantics
