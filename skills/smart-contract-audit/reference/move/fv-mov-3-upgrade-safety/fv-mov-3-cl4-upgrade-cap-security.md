# FV-MOV-3-CL4: UpgradeCap Security

## TLDR

The `UpgradeCap` for a Sui package is the single object controlling all future code upgrades. A compromised or malicious holder can deploy arbitrary new code, immediately draining all protocol funds. This is the highest-impact single point of failure in any upgradeable Sui protocol.

## Detection Heuristics

- Find the `UpgradeCap` object ID in the deployment manifest or `init` function and trace its destination
- If `UpgradeCap` is transferred to a single EOA address, it is a critical finding
- Verify whether a timelock wrapper is applied: `UpgradeCap` should only be exercisable after a minimum delay (24-48 hours minimum)
- Check if `UpgradeCap` has been destroyed (`package::make_immutable`) - if so, verify this was intentional and no critical bugs remain unfixed
- Overly permissive upgrade policy (`compatible` instead of `dep_only`) is a medium finding - unnecessary attack surface

## False Positives

- `UpgradeCap` held by a multi-sig contract with documented signers
- Timelock module wraps `UpgradeCap` with enforced delay
- Governance vote required before upgrade execution
- `UpgradeCap` destroyed after protocol matured and all bugs resolved - immutability intentional and documented
