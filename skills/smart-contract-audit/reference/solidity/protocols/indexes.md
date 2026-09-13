# Index Protocol Security Patterns

> Applies to: on-chain index protocols, basket tokens, index rebalancing, Set Protocol-style, Index Coop-style, tokenized portfolios

## Protocol Context

Index protocols hold a basket of ERC-20 components and issue a single token representing proportional ownership. Every operation-mint, redeem, rebalance-must iterate over all components and price each independently, compounding per-token rounding error and gas exposure. The attack surface is unusually broad: each component carries its own decimal precision, fee-on-transfer behavior, callback potential, and oracle dependency, and any single component anomaly can cascade to corrupt the entire basket's invariants.

---

### Arithmetic Overflow and Underflow (ref: fv-sol-3)

**Protocol-Specific Preconditions**
- Reserves or supply accumulators are stored in `uint128` or `uint64` while intermediate math uses `uint256`, producing silent truncation on downcast
- Exponential decay reward functions receive inputs outside their safe numerical range
- Weighted basket math multiplies component quantities by prices before summing, with intermediate products exceeding `type(uint256).max` for high-value components

**Detection Heuristics**
- Search for explicit downcasts: `uint128(x)`, `uint64(x)`, `int256(x)` from `uint256` without prior bounds check or `SafeCast`
- Find subtraction on unsigned types where the second operand may exceed the first (e.g., sold exceeds total supply in order books)
- Audit `unchecked` blocks for arithmetic in accounting-critical paths
- Check loop counter types against the realistic upper bound of the collection being iterated
- For Solidity < 0.8.0, confirm SafeMath is used on all arithmetic in index math

**False Positives**
- Solidity >= 0.8.0 without `unchecked` blocks provides automatic overflow protection
- Downcast preceded by a validated upper bound check is safe
- Hash computations that intentionally wrap around

**Notable Historical Findings**
Caviar's reserve update silently overflowed when `netInputAmount` exceeded `type(uint128).max`, corrupting the virtual reserve tracking used for NFT index pricing. Knox Finance's withdrawal preview function underflowed when `totalContractsSold` exceeded `totalContracts` due to an order processing bug, permanently bricking withdrawals. Bancor's compounding rewards used an exponential function that overflowed when the time-to-half-life ratio exceeded the safe input range for `exp2`.

**Remediation Notes**
- Use `SafeCast.toUint128(x)` instead of bare `uint128(x)` for all reserve and supply downcasts
- Validate inputs to fixed-point exponential functions against a protocol-defined `MAX_SAFE_EXP_INPUT` before calling
- For index rebalance math, keep all intermediate values at full `uint256` precision and downcast only at the final storage write

---

### Decimal and Precision Mismatch (ref: fv-sol-2)

**Protocol-Specific Preconditions**
- Index basket contains components with heterogeneous decimals (WBTC at 8, USDC at 6, WETH at 18)
- Price adapters assume WAD (1e18) precision for all component prices but receive values in the component's native decimal scale
- Fixed-point library functions (`expWad`, `lnWad`, `powWad`) receive inputs that are not normalized to 1e18, returning near-linear instead of exponential curves

**Detection Heuristics**
- Identify all hardcoded `1e18` divisors in index math and verify the operand token actually has 18 decimals
- Audit `preciseMul` / `preciseDiv` call sites for inputs not in WAD precision
- Check exponential price adapter arguments for scale; a `timeCoefficient` expressed in 1e6 rather than 1e18 produces silent linearization
- Find `buyQuote` or similar pricing functions where a small numerator divided by a large denominator can round to zero, enabling zero-cost token acquisition

**False Positives**
- Protocol normalizes all amounts to a common precision at ingress before any math
- Only 18-decimal tokens are supported and a whitelist enforces this
- Rounding loss is bounded to sub-cent dust values with no amplification vector

**Notable Historical Findings**
Index Coop's BoundedStepwiseExponentialPriceAdapter received `timeCoefficient` in the wrong scale, causing the auction price curve to degrade to a nearly flat line and mispricing rebalance trades significantly. Caviar's `buyQuote` rounded down to zero for certain reserve ratios, allowing buyers to acquire fractional NFT tokens for free. ParaSpace's Uniswap V3 position valuation applied 18-decimal math to token pairs containing WBTC, producing collateral values off by up to 10 orders of magnitude.

**Remediation Notes**
- Normalize price inputs: `priceWad = componentPrice * 10**(18 - quoteDecimals + componentDecimals)` before passing to WAD math
- Add a `require(inputAmount > 0, "rounds to zero")` guard after any division that feeds into a swap output
- Document the expected precision for each oracle price feed in the NatSpec of every price adapter

---

### Fee-on-Transfer Token Accounting (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Index composition includes deflationary or tax tokens
- Basket minting credits the nominal transfer amount rather than the actual post-fee amount received
- Swap functions inside the index router compute output from the declared `amountIn` rather than measuring the real received balance

**Detection Heuristics**
- Trace every `transferFrom` into the contract: if the subsequent balance credit uses the `amount` parameter rather than `balanceOf(after) - balanceOf(before)`, the pattern is present
- Check minimum output guards for off-by-fee errors: a `require(amountOut >= minAmountOut)` that uses the pre-fee input will pass even when the user receives fewer tokens than expected
- Verify that token whitelists explicitly exclude deflationary tokens if the balance-difference pattern is not implemented

**False Positives**
- Protocol enforces a whitelist of known non-fee tokens (WETH, USDC, DAI) and reverts on unsupported tokens
- Balance-before/after snapshot pattern is already implemented
- Internal function is only reachable with pre-validated tokens from a restricted caller

**Notable Historical Findings**
OpenLeverage's `uniClassSell` passed the nominal `amountIn` to the AMM's output calculation even when fee-on-transfer tokens reduced the actual transferred amount, causing trades to execute against incorrect input amounts and leaving systematic shortfalls. InsureDAO's Vault credited depositors for the full nominal amount on fee-on-transfer deposits, meaning the contract's actual token balance was always less than the sum of recorded balances, making later withdrawals underfunded.

**Remediation Notes**
- Measure received amount with `uint256 received = token.balanceOf(address(this)) - balanceBefore` and use `received` for all subsequent accounting
- For index minting, perform this snapshot for every component transfer in the basket loop

---

### Flash Loan Exploitation in Rebalance Operations (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Flash loan functions accept a user-supplied `token` address rather than using the contract's known NFT/ERC-20 address
- Health factor or auction validity checks can be satisfied temporarily within a single transaction by borrowing collateral
- Asset transfers in batch buy functions occur before payment collection, creating an implicit free flash-swap

**Detection Heuristics**
- Check if flash loan callbacks validate the return value equals `keccak256("ERC3156FlashBorrower.onFlashLoan")` per ERC-3156
- Identify functions that transfer assets before verifying payment (implicit flash-swap vulnerability)
- Verify health/solvency checks require the condition to persist across multiple blocks, not just within the transaction
- Look for fee collection that targets the wrong address (e.g., collects fee from caller rather than receiver)
- Confirm flash loan fee is distributed to protocol treasury and not silently discarded

**False Positives**
- Flash loan function accepts only the contract's own whitelisted token address, not user-supplied
- Health checks use time-weighted or multi-block measurements
- CEI pattern is followed: payment is verified before asset transfer

**Notable Historical Findings**
Caviar's `PrivatePool.flashLoan` accepted a user-supplied token address, allowing an attacker to pass a malicious ERC-721 address that did nothing on transfer, effectively borrowing the real pool NFT for free while paying a fee denominated in the worthless fake token. ParaSpace users exploited flash loans to temporarily inflate their health factor above the recovery threshold, invalidating in-progress auctions on their own positions. Multiple Caviar fee-accounting bugs meant flash loan fees were either collected from the wrong address or never forwarded to the factory's protocol fee pool.

**Remediation Notes**
- Hardcode the NFT/token address within the flash loan function rather than accepting it as a parameter
- Require health factors to persist across a configurable number of blocks before allowing auction cancellation
- Collect payment before transferring any assets in buy functions

---

### Front-Running and MEV in Rebalance (ref: fv-sol-8)

**Protocol-Specific Preconditions**
- Rebalance auctions operate via Dutch auction or open-bid mechanisms where pending price updates are visible in the mempool
- Authorization delegation functions allow the authorized party to counter-front-run by granting new delegates before revocation lands
- Oracle price setter transactions expose the next price to searchers, who buy or sell before the price update applies

**Detection Heuristics**
- Identify authorization revocation functions and check whether the target can front-run by adding a new delegate from their still-valid authorization
- Confirm that swap and auction functions include both a `minAmountOut` (slippage) and a `deadline` parameter
- Look for oracle price-setter functions lacking commit-reveal protection
- Check Dutch auction bid functions for missing increment protection that would allow sniping with a minimal bid

**False Positives**
- Transactions are routed through private mempools (Flashbots Protect, MEV Blocker)
- Commit-reveal schemes prevent information extraction from pending transactions
- Time-locks or batched execution prevent atomic front-running
- Slippage tolerance adequately limits extractable value

**Notable Historical Findings**
Drips Protocol's `unauthorize` could be front-run by the about-to-be-revoked user who called `authorize` on an accomplice address before the revocation transaction landed, preserving effective access. Index Coop's auction mechanism allowed front-runners to observe favorable Dutch auction prices and purchase before other bidders, and separately allowed full-inventory purchases to be DoS'd by front-running with a minimal competing bid. ParaSpace's admin `setPrice` was observable in the mempool, giving searchers a window to borrow or trade against the old oracle value before the update confirmed.

**Remediation Notes**
- Restrict `authorize` to the owner directly, not to delegated callers, to prevent self-re-authorization front-running
- Enforce `deadline` and `minAmountOut` parameters on all auction and swap entry points
- Use commit-reveal for oracle price updates in protocols where the price update itself carries exploitable information

---

### Missing Access Controls (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- Index component management functions (add/remove components, set oracle addresses) are externally callable without role checks
- Keeper or feeder addresses default to `address(0)` and are never validated, allowing zero-address to satisfy `require(msg.sender == keeper)`
- Oracle feeder removal has no minimum-feeder guard, allowing complete oracle DoS
- `renounceOwnership` is accessible on a contract where admin functions must remain callable post-deployment

**Detection Heuristics**
- Enumerate all external/public functions that modify component lists, oracle addresses, fee rates, or controller addresses and confirm access modifiers
- Check `address(0)` reachability: if a privileged address is never set, does the zero-address pass a `require(msg.sender == role)` check?
- Search for OpenZeppelin `Ownable` with `renounceOwnership` not overridden to revert
- Verify proxy initialization functions are callable only once and only by the deployer or factory

**False Positives**
- Function is intentionally permissionless by design (e.g., public liquidation)
- Access control is enforced at a higher contract layer that restricts callers
- `renounceOwnership` is explicitly overridden to `revert`

**Notable Historical Findings**
InsureDAO's `setController` lacked an access control modifier, allowing any caller to redirect vault withdrawals to an arbitrary address and drain all deposited funds. ParaSpace's oracle feeder removal function had no ownership check, enabling any user to remove all feeders and cause every price query to revert, permanently blocking liquidations. 1inch's governance contract allowed unauthorized stake creation on behalf of arbitrary users due to a missing access check on `notifyFor`.

**Remediation Notes**
- Add zero-address validation alongside every role-based `require`
- Override `renounceOwnership` to revert on all index contracts where admin functions must remain available
- Require at least two active feeders before permitting feeder removal

---

### Oracle Price Manipulation (ref: fv-sol-10)

**Protocol-Specific Preconditions**
- Component pricing uses AMM spot prices from low-TVL Uniswap V3 pools, which can be seeded with minimal liquidity by an attacker
- Chainlink `latestRoundData` is called without validating `updatedAt`, `answeredInRound >= roundId`, or `price > 0`
- Fallback oracle is unreachable because primary oracle reverts are not caught with try/catch
- Floor oracle for NFT index components uses an append-only data structure that can be corrupted by feeder data

**Detection Heuristics**
- Confirm no AMM `getReserves()` or `getAmountsOut()` call is used for valuation; require TWAP or Chainlink
- For every `latestRoundData()` call, verify: `price > 0`, `updatedAt > 0`, `answeredInRound >= roundId`, `block.timestamp - updatedAt < STALENESS_THRESHOLD`
- Trace the fallback oracle call path with a primary oracle that reverts; confirm try/catch is present
- Review feeder-based floor oracles for data structure integrity (sorted insertion, removal safety, feeder count guardrails)

**False Positives**
- TWAP oracles with windows of 30+ minutes are used and documented
- Protocol operates on high-liquidity Chainlink-covered pairs only
- Multiple independent oracle sources are aggregated with median selection

**Notable Historical Findings**
ParaSpace's collateral pricing for Uniswap V3 LP positions used pools where an attacker could create their own low-liquidity pair and manipulate the reported price by orders of magnitude, enabling under-collateralized borrowing. The NFT floor oracle used an array-based structure that became corrupted when feeders were removed mid-round, causing out-of-bounds reads and a DoS on all price queries. Marginswap used `getAmountsOut` (a spot-price function) as its sole price source, making every collateral decision vulnerable to flash-loan manipulation.

**Remediation Notes**
- Reject any price source that can be influenced within a single transaction; require Chainlink or a Uniswap V3 TWAP with a minimum observation period
- Add try/catch around all external oracle calls and route failures to a validated fallback
- Store feeder indices in a mapping rather than a packed array to allow O(1) removal without structural corruption

---

### Privileged Function Abuse (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- Controller address can be changed to a malicious contract that then calls vault withdrawal functions
- "Rescue" or "redundant withdrawal" functions can withdraw any token including user-deposited components
- Cover or compensation functions have no idempotency guard, allowing repeated application to drain index reserves
- Admin can bypass timelocks by resetting `lastUpdated` fields or calling override functions directly

**Detection Heuristics**
- Enumerate all `onlyOwner`/`onlyAdmin` functions and model whether each can redirect user funds to an arbitrary address
- Check "rescue" functions for missing exclusion logic on protocol-managed tokens
- Confirm one-shot operations (cover application, settlement) use a `mapping(id => applied)` idempotency guard
- Verify critical parameter changes (oracle address, fee rate, collateral factor) are behind a timelock of at least 24–48 hours

**False Positives**
- Protocol is explicitly custodial and users accept admin trust in documented terms
- Admin functions sit behind a timelock + multisig that gives users time to exit
- "Rescue" functions correctly exclude all protocol-managed tokens via a whitelist check

**Notable Historical Findings**
InsureDAO's `Vault.setController` allowed the owner to atomically redirect all vault withdrawals to an attacker-controlled address, draining all deposited funds in a single transaction. The same protocol's `withdrawRedundant` function accepted any token address, making it a direct backdoor to withdraw user deposits rather than only accidentally sent tokens. Holdefi's owner could reset per-asset price data and bypass the time-checks on market and collateral assets, overriding the timelock guarantees users relied on.

**Remediation Notes**
- Require `isProtocolToken[_token] == false` in any token rescue function
- Wrap all controller and oracle address changes in a two-step propose/execute pattern with a minimum delay
- Mark one-shot operations with a storage flag keyed to the specific incident ID, not a global counter

---

### Reentrancy via Token Callbacks (ref: fv-sol-1)

**Protocol-Specific Preconditions**
- Index basket contains ERC-777 components whose `tokensReceived` hooks trigger re-entry before reserve state is updated
- NFT-backed index protocols transfer ERC-721 tokens before collecting payment, exposing `onERC721Received` re-entry
- Grant or distribution functions update a `complete` flag after the external transfer rather than before

**Detection Heuristics**
- Identify all external calls in basket operation functions; flag any state variable written after those calls
- Check for missing `nonReentrant` on `buy`, `sell`, `swap`, and grant finalization functions
- Verify that reserve/balance state is updated before any token transfer, not after
- For multi-step operations (quote → transfer → update), confirm quoted values cannot become stale by re-entering between steps

**False Positives**
- `nonReentrant` is applied and covers all relevant entry points for the shared state
- Only WETH/USDC/DAI (no callback tokens) are supported and enforced via whitelist
- All state changes precede external calls throughout the function (strict CEI)

**Notable Historical Findings**
Caviar's `buy` function transferred ERC-777 fractional tokens to the buyer before updating the virtual reserves used to calculate prices, allowing a re-entrant callback to execute another buy against stale (lower) prices and acquire tokens at a substantial discount. Marginswap's balance accounting could be inflated by re-entering during an ETH transfer, as the balance write happened after the `call{value}`. Endaoment violated CEI in a grant finalization flow, setting `grant.complete = true` after the token transfer rather than before.

**Remediation Notes**
- Apply `nonReentrant` to all buy/sell/swap functions in the index contract
- Follow strict CEI: update all reserve/balance state before any token transfer or external call
- If ERC-777 tokens must be supported, add explicit `tokensReceived` guard logic that reverts re-entrant execution

---

### Royalty and Fee Distribution Errors (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Batch NFT purchases divide total price equally across items regardless of individual item weights, producing incorrect royalty bases
- Royalty recipient addresses are not validated for zero-address or ETH-receivability
- Royalty payment callbacks within batch loops allow malicious recipients to re-enter or steal excess ETH held during the loop

**Detection Heuristics**
- Check every batch buy function for `salePrice = totalPrice / tokenIds.length`; this is wrong when NFTs have heterogeneous weights
- Verify `royaltyInfo()` is called with the per-item price, not an averaged price
- Confirm royalty payment failures are handled via a pull-payment escrow rather than a bare `.call{value}` that reverts the entire batch
- Check split royalty implementations for correct pro-rata logic across multiple creator recipients

**False Positives**
- All NFTs in the collection are fungible ERC-1155 items with equal value
- Protocol only supports single-item transactions
- Royalty recipients are validated and whitelisted at collection registration time

**Notable Historical Findings**
Caviar's batch buy computed royalties on `totalPrice / count` for each item, systematically underpaying royalties on high-value NFTs and overpaying on low-value ones, and separately allowed a malicious royalty recipient to drain the pool's excess ETH by re-entering during the royalty payment call. Foundation's multi-recipient royalty split used incorrect proportionality math, causing some creators to receive less than their entitled share while others received more. Foundation also failed to validate that `creatorRecipients` addresses were non-zero, burning fees when a zero-address was present in the recipients array.

**Remediation Notes**
- Calculate per-item sale price as `totalPrice * weights[i] / totalWeight` when items have heterogeneous values
- Use a gas-limited `.call{gas: 10000}` for royalty payments and escrow failures rather than reverting the entire batch transaction
- Validate all royalty recipients are non-zero and capable of receiving the payment token before executing the batch

---

### Signature Replay Attacks (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
- Off-chain private-sale signatures lack a nonce, meaning if the seller re-acquires the NFT the old buyer signature becomes replayable
- Nonce is bound to the transaction relayer rather than the identity or signer, allowing the same signed payload to be submitted for different target identities
- EIP-712 domain separator does not include the contract address or chain ID, enabling cross-contract and cross-chain replay

**Detection Heuristics**
- Trace all `ecrecover` / `ECDSA.recover` call sites; verify the signed hash includes: nonce, contract address, chain ID, and a unique-per-use identifier
- Confirm the nonce is incremented on the identity or signer (not the caller/relayer) after each use
- Check whether the signed action can recur (e.g., seller re-acquires asset); if so, a nonce alone is insufficient without also tracking used digests
- Verify domain separator is not an immutable constructor value that becomes stale after a hard fork

**False Positives**
- Signature includes a monotonically increasing nonce on the correct entity, preventing reuse
- Signed message includes a unique order hash tracked in a mapping
- Action is idempotent and replay produces no additional state change

**Notable Historical Findings**
Foundation's private-sale signatures for NFTs contained no nonce; if the seller re-acquired the NFT after a sale, the original buyer's signature remained valid and could be replayed to forcibly purchase the asset again below market price. Ambire's recovery system allowed `SigMode.OnlySecond` recoveries to be submitted repeatedly because no used-signature tracking existed, enabling an attacker to replay a cancelled recovery indefinitely. A separate Ambire finding showed that nonces were tracked on the calling relayer rather than the target identity, allowing the same signed operation to be replayed across different wallets that shared a common authorized signer.

**Remediation Notes**
- Track used signature digests in `mapping(bytes32 => bool) public usedSignatures` regardless of nonce freshness
- Bind nonces to the identity being acted upon, not the caller address
- Compute domain separator dynamically using `block.chainid` to remain correct after forks

---

### Unbounded Loops and Denial of Service (ref: fv-sol-9)

**Protocol-Specific Preconditions**
- Index basket component arrays or order books grow without a hard cap, and critical functions iterate the full array
- NFT-backed index pools iterate over all tokenId holders for EOS (end-of-sale) distributions without pagination
- Reward distribution loops contain external calls that can each individually revert, blocking the entire batch for all recipients

**Detection Heuristics**
- Find all `for` loops whose upper bound is a storage variable or unbounded dynamic array length
- Check whether the loop contains external calls, storage reads, or oracle queries that compound per-iteration cost
- Verify that at least one paginated alternative path exists for any unbounded loop in a critical redemption or withdrawal function
- Confirm that a single reverting recipient in a distribution loop cannot block all other recipients' payments

**False Positives**
- Loop has a hard cap enforced at insertion time (e.g., maximum 25 components per basket)
- Data structure is writable only by a trusted admin with manual size management
- Pagination is available as an equivalent alternative execution path

**Notable Historical Findings**
Foundation's `_getCreatorPaymentInfo` iterated an unbounded creator-recipients array; sufficiently large arrays caused the function to exceed the block gas limit, permanently preventing any marketplace sale from completing. Knox Finance's `_previewWithdraw` and `_redeemMax` functions looped over the entire order book, allowing the accumulation of many small orders to brick all withdrawal functionality. Marginswap's reward withdrawal function iterated a data structure that grew to a size exceeding the block gas limit, making reward claims permanently inaccessible.

**Remediation Notes**
- Enforce a maximum component/recipient count at insertion time, documented as a protocol invariant
- Implement pagination parameters (`offset`, `limit`) on any view or state function that iterates a dynamic collection
- Use the pull-payment pattern for distributions so a single failed recipient does not block others

---

### Unsafe External Calls and Token Transfers (ref: fv-sol-6)

**Protocol-Specific Preconditions**
- Component withdrawals use `address.transfer()` with the 2300-gas limit, which fails for multisig or proxy wallets holding index tokens
- Raw `IERC20.transfer()` / `transferFrom()` calls do not check return values on non-reverting tokens (USDT, BNB)
- `send()` return value is ignored, silently losing ETH when the recipient rejects it

**Detection Heuristics**
- Search for `.transfer(` on `address payable`; these always fail for contract recipients requiring more than 2300 gas
- Search for `IERC20(...).transfer()` and `IERC20(...).transferFrom()` calls not using `SafeERC20`
- Verify that failed transfers leave the contract in a consistent state and do not decrement balances before confirming success
- Check whether withdrawal loops use push or pull pattern; push loops with rigid failure semantics can permanently block all recipients

**False Positives**
- `SafeERC20.safeTransfer` is used exclusively for all token operations
- `.call{value: amount}("")` is used with proper return-value check
- Recipients are guaranteed to be EOAs and the token list is fully audited for standard revert behavior

**Notable Historical Findings**
OpenLeverage's `doTransferOut` used `payable.transfer()`, making the entire withdrawal path unusable for smart contract wallets and multisigs-a critical gap in a protocol where DAO treasuries are common users. Endaoment's token transfer functions silently returned `false` on failure rather than reverting, causing the protocol to update internal accounting as if the transfer succeeded while the tokens never moved. Aave's push-payment pattern for ETH deposits meant that a single non-payable contract address in the recipient set could permanently prevent all ETH deposits from being redeemed.

**Remediation Notes**
- Replace `payable.transfer()` and `send()` with `(bool success, ) = recipient.call{value: amount}("")` and require success
- Wrap all ERC-20 interactions with `SafeERC20` from OpenZeppelin to handle non-standard return values
- Adopt the pull-payment pattern for any multi-recipient distribution to isolate individual failures
