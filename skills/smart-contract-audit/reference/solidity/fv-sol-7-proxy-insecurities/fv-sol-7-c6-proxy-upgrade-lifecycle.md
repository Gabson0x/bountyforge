# FV-SOL-7-C6 Proxy Upgrade Lifecycle Security

## TLDR

The upgrade lifecycle - initialization, authorization, and execution ordering - has several critical failure modes including re-initialization via wrong modifier, permanent loss of upgrade capability when UUPS logic is dropped, race conditions between upgrade and configuration, missing access control on `_authorizeUpgrade`, front-runnable non-atomic initialization, and admin routing confusion in transparent proxies.

## Detection Heuristics

**Re-initialization**
- V2+ contract uses `initializer` modifier instead of `reinitializer(N)`
- Upgrade resets initialized counter or storage-collides the `_initialized` flag
- No version bump in OZ `Initializable` usage

**UUPS Upgrade Logic Removed**
- New implementation doesn't inherit `UUPSUpgradeable`
- `upgradeTo`/`upgradeToAndCall` not present in V2 ABI
- `_authorizeUpgrade` not overridden in new implementation

**Upgrade Race Condition**
- `upgradeTo(V2)` and `V2.initialize()` or config calls in separate transactions
- No `upgradeToAndCall()` usage

**Missing Upgrade Authorization**
- `_authorizeUpgrade(address) internal override {}` with empty body
- No `onlyOwner`, role check, or governance gate

**Non-Atomic Initialization**
- `new TransparentUpgradeableProxy(impl, admin, "")` with empty `data` param
- `initialize()` broadcasted in separate transaction after proxy deployment

**Admin Routing Confusion**
- `ProxyAdmin` not a dedicated contract - admin is same EOA used for protocol operations
- Admin calls protocol functions directly instead of through `ProxyAdmin`

## False Positives

- `reinitializer(version)` with correctly incrementing versions for V2+
- `_authorizeUpgrade` has `onlyOwner` or equivalent governance gate
- `upgradeToAndCall()` bundles upgrade + init atomically
- Init calldata passed in proxy constructor - atomic initialization
- Dedicated `ProxyAdmin` contract used exclusively for admin operations
- OZ upgrades plugin validates storage layout and upgrade compatibility in CI
