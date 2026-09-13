# HackenProof Global Vulnerability Policy

Use this as baseline triage guidance before applying program-specific scope/rules.

Source docs:

- Web & Mobile classification: https://docs.hackenproof.com/bug-bounty/vulnerability-classification/web-and-mobile
- Web & Mobile out-of-scope: https://docs.hackenproof.com/bug-bounty/vulnerability-classification/web-and-mobile/out-of-scope-bugs
- Smart contract classification: https://docs.hackenproof.com/bug-bounty/vulnerability-classification/smart-contracts
- Blockchain protocol classification: https://docs.hackenproof.com/bug-bounty/vulnerability-classification/blockchain-protocols

## Rule Priority

1. Program-specific scope and rules (`get_program_info`) always override global baseline.
2. If no program-specific override exists, use this global policy.
3. If classification is still ambiguous, use CVSS-based reasoning and request more evidence.

## Program Type to Classification Mapping

Derive the program type from `get_program_info` labels/scope metadata, then use:

- `web` or `mobile` -> Web & Mobile classification + Web & Mobile out-of-scope list
- `smart-contract`, `sc`, `solidity`, `evm`, `move` -> Smart Contract classification
- `blockchain`, `protocol`, `node`, `consensus`, `l1`, `l2` -> Blockchain Protocol classification

If labels indicate mixed scope, classify by impacted component first (application, contract, or protocol layer), then use the matching track.

## Web & Mobile Severity Baseline

- `Critical`: payments manipulation, SQLi, RCE, command injection, business logic causing user fund/asset loss.
- `High`: stored XSS, SSRF, wallet-linked subdomain takeover, major sensitive data leakage, auth bypass, impactful IDOR/privilege escalation.
- `Medium`: reflected XSS, non-wallet subdomain takeover, 2FA bypass, moderate sensitive data leakage, CSRF with meaningful impact.
- `Low`: HTML injection, low-impact subdomain takeover, no-rate-limit issues on low-sensitivity endpoints, content spoofing, broken link hijacking.

## Web & Mobile Out-of-Scope Baseline

General out-of-scope conditions:

- no meaningful security impact
- no practical exploitability
- non-production or third-party systems

Common web out-of-scope examples:

- best-practice/informational only findings without exploit impact
- clickjacking/tapjacking on non-sensitive pages
- open redirects without demonstrated abuse impact
- version disclosure, verbose errors, harmless mixed content
- scanner-only or theoretical reports
- DoS/resource abuse without security impact
- outdated software claims without working exploit
- CORS/session-fixation findings without demonstrable impact
- recently disclosed 0day/1day (policy indicates short cooling-off windows)

Common mobile out-of-scope examples:

- root/jailbreak-only attack paths without business impact
- obfuscation/repackaging/decompilation-only findings
- low-risk insecure storage without sensitive data exposure
- debug logs without secrets/tokens
- local/MitM assumptions without proof of exploit impact

## Smart Contract Severity Baseline

- `Critical`: direct theft, permanent freezing of funds/NFTs, governance manipulation, protocol insolvency, unauthorized mint/burn.
- `High`: temporary freezing of funds/NFTs, theft/permanent freeze of unclaimed funds, high-impact oracle manipulation.
- `Medium`: gas-theft patterns, out-of-gas flaws causing disruption/loss, DoS via state or gas abuse, griefing/no-profit attacks with protocol harm.
- `Low`: under-delivery of promised returns due to logic flaws, low-risk uninitialized storage.

Notes:

- privileged/admin-only attack paths may justify severity downgrade or disqualification

## Blockchain Protocol Severity Baseline

- `Critical`: protocol-level theft, permanent fund freeze, total network shutdown, consensus manipulation/chain split risk, hard-fork-required resolution.
- `High`: node-crash DoS, temporary network transaction freeze, temporary fund freeze.
- `Medium`: subset-node DoS, protocol edge-case behavior affecting dApps, timestamp/time manipulation, minor reorg abuse.
- `Low`: non-critical shutdown of minority node set, low-impact fee miscalculation, low-impact gossip-layer issues.

## Triage Application

Before deep validation:

1. map report domain to one baseline (`web-mobile`, `smart-contract`, `blockchain-protocol`)
2. compare claimed impact against baseline severity bucket
3. check out-of-scope indicators early; if matched, mark `Out of scope` with explicit reason
4. if in scope, continue with duplicate checks and technical validation
