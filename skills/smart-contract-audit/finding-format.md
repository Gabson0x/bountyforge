### 5.2 Finding Format

**FINDING FORMAT:**
Ensure findings created follow this format very strictly:

````markdown
## [C/H/M/L]-[Number] [Impact] via [Weakness] in [Feature]

### Core Information [display with newlines]
**Severity:** [Critical/High/Medium/Low - conservative assessment]


**Probability:** [High/Medium/Low - conservative assessment]


**Confidence:** [High/Medium/Low - based on verification depth]



### User Impact Analysis
**Innocent User Story:**
```mermaid
graph LR
    A[User] --> B[Normal Action: [User performs intended protocol interaction]]
    B --> C[Expected Outcome: [User receives expected result]]
```
*Note: Use proper mermaid syntax with valid node IDs (A, B, C, etc.) and avoid special characters in labels. Ensure all arrows use correct syntax (-->) and labels are enclosed in square brackets.*

**Attack Flow:**
```mermaid
graph LR
    A[Attacker] --> B[Attack Step 1: [Attacker performs initial action]]
    B --> C[Attack Step 2: [Attacker exploits vulnerability]]
    C --> D[Attack Step 3: [Attacker achieves malicious outcome]]
    D --> E[Final Outcome: [Attacker profits from exploitation]]
```
*Note: Create clear, linear attack flows with descriptive but concise labels. Each step should logically follow the previous one. Avoid complex branching unless necessary for clarity.*

### Technical Details
**Locations:** 
- [../../../path/to/contract.sol:XX-YY](../../../path/to/contract.sol#LXX-LYY)
- [../../../path/to/another-file.sol:LXX-LYY](../../../path/to/another-file.sol#LXX-LYY)

**Description:** 
[Technical explanation of the smart contract vulnerability. Include:
- TL;DR summary of what was located during assessment
- How an attacker might abuse this vulnerability
- What is the impact on protocol funds and user assets
- Approximately half a page of detailed technical context]

### Business Impact
**Exploitation:** 
[Real-world exploitation scenario with business context and protocol-specific impact.
Include:
- Realistic attack timeline and prerequisites (flash loans, governance votes, etc.)
- Protocol operations affected (trading, lending, staking, etc.)
- User/TVL impact and fund loss potential
- Market confidence and protocol reputation consequences
- Regulatory/compliance implications for DeFi protocols]

### Verification & Testing
**Verify Options:** 
[Manual checks needed to confirm this finding:
- Specific function calls to test
- Contract interaction patterns to verify
- Economic conditions to simulate]

**PoC Verification Prompt:** 
[LLM prompt that you would write to real-life test this vulnerability to 100% prove it's not a false positive:
- Exact steps to reproduce in testing environment
- Expected vs actual results
- Success criteria for exploitation]

### Remediation
**Recommendations:** 
[Actionable practical recommendations for remediation:
- Primary fix with exact code changes
- Alternative solutions if applicable
- Best practice implementation guidance
- Verification steps to confirm fix]

**References:**
**KB/Reference:** 
- [Relevant security standards, frameworks, or documentation]
- [Knowledge base references if applicable: `reference/[language]/...`]

### Expert Attribution

**Discovery Status:** [Found by Expert 1 only / Found by Expert 2 only / Found by both experts]

**Expert Oversight Analysis:** [If only found by one expert, the other expert should analyze why they missed it - e.g., "Expert 2 acknowledges missing this due to focusing on different attack vectors", "Expert 1 doesn't consider this a valid vulnerability because...", "Expert 2 overlooked this pattern during systematic review"]

### Triager Note
[VALID/QUESTIONABLE/DISMISSED/OVERCLASSIFIED] - [Contextual bounty assessment based on security budget analysis from Step 2.

**Bounty Assessment:** 
- VALID findings: Provide specific bounty amount ($X,XXX) based on exploitability evidence, PoC quality, and realistic attack scenarios in current wild conditions
- QUESTIONABLE findings: Explain additional proof needed - no bounty recommended until validation
- DISMISSED findings: Technical reasons why not exploitable in practice
- OVERCLASSIFIED findings: Valid vulnerability but severity was exaggerated - suggest correct severity level and adjusted bounty

**Reality Check Factors:** Consider admin-only functions, existing access controls, economic attack incentives, TVL impact scale, and practical vs theoretical exploitability. Low severity findings merit small bounties ($50-$200) for best practice improvements even if somewhat theoretical, as they fit the severity level appropriately.]
````

**SEVERITY CLASSIFICATION RULES:**

**Critical (Immediate fund loss possible):**
- Direct token drainage exploitable by any user
- Complete admin takeover without prerequisites  
- Permanent fund lockup affecting >10% of protocol TVL

**High (Conditional fund loss likely):**
- Fund loss requiring specific but common conditions (flash loans, governance)
- Privilege escalation with moderate barriers
- Oracle manipulation with realistic profit margins

**Medium (Functional impact or limited loss):**
- Temporary DOS attacks affecting protocol functionality
- Fund loss requiring unlikely conditions or extensive setup
- Non-critical function manipulation with minimal user impact

**Low (Minimal practical impact):**
- Gas optimization issues affecting UX
- Theoretical vulnerabilities with no clear exploit path
- Minor protocol functionality degradation

