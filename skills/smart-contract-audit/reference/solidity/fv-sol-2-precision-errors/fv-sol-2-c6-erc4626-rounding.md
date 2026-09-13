# FV-SOL-2-C6 ERC4626 Rounding Direction Violations

## TLDR

EIP-4626 mandates specific rounding directions on every conversion function to prevent share-price manipulation and round-trip profit extraction. The invariant is: the vault must favor itself over the user at every step.

- `previewDeposit` / `convertToShares` (deposit path): round down - issue fewer shares
- `previewMint` (mint path): round up - charge more assets
- `previewWithdraw` (withdraw path): round up - burn more shares
- `previewRedeem` / `convertToAssets` (redeem path): round down - return fewer assets

Violations allow attackers to cycle deposit→redeem repeatedly for net profit, or to extract more assets than deposited.

## Detection Heuristics

**Preview/Mint Asymmetry**
- `previewDeposit` returns more shares than `deposit` actually mints
- `previewMint` charges fewer assets than `mint` actually takes
- Single `_convertToShares` helper with same `Rounding` arg on both paths

**Deposit/Withdraw Share Asymmetry**
- `_convertToShares` uses `Rounding.Floor` for withdraw path
- `withdraw(a)` burns fewer shares than `deposit(a)` minted - cycling manufactures free shares
- `convertToShares` and `previewWithdraw` return identical values without rounding distinction

**Mint/Redeem Asset Asymmetry**
- `_convertToAssets` uses `Rounding.Ceil` in `redeem` and `Rounding.Floor` in `mint`
- `redeem(s)` returns more assets than `mint(s)` costs - cycling yields net profit
- `previewRedeem` and `previewMint` both round in the user's favor

**Share Inflation via Rounding**
- `shares = assets / pricePerShare` rounds down for deposit, up for redeem
- First-depositor donation attack amplifies rounding error
- No `_decimalsOffset()` or dead-share initialization pattern

## False Positives

- OpenZeppelin ERC4626 base used without overriding `_convertToShares`/`_convertToAssets`
- Custom implementation explicitly uses: deposit with `Rounding.Floor`, withdraw with `Rounding.Ceil`, mint with `Rounding.Ceil`, redeem with `Rounding.Floor`
- `_decimalsOffset()` returns non-zero virtual shares offsetting first-depositor attack
- Protocol documentation explicitly accepts bounded dust loss by design with verified bounds
