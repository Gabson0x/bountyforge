### Final Security Assessment Report

**REPORT STRUCTURE:**

```markdown
# Smart Contract Security Assessment Report

## Executive Summary

### Protocol Overview
**Protocol Purpose:** [What DeFi problem does this protocol solve?]
**Industry Vertical:** [DeFi category: AMM/Lending/Derivatives/etc.]
**User Profile:** [Primary users and their typical interaction patterns]
**Total Value Locked:** [Current or expected TVL]

### Threat Model Summary
**Primary Threats Identified:**
- Economic attackers targeting [specific protocol mechanisms]
- Flash loan exploits affecting [specific functions]
- Governance attacks on [specific protocol parameters]
- Oracle manipulation risks in [specific price feeds]

### Security Posture Assessment
**Overall Risk Level:** [High/Medium/Low]
**Critical Findings:** [Count] requiring immediate attention before mainnet
**Total Findings:** [Count by severity: X Critical, Y High, Z Medium, W Low]

**Key Risk Areas:**
1. [Primary risk area with protocol context]
2. [Secondary risk area with protocol context]  
3. [Additional risk areas...]

## Table of Contents - Findings

### Critical Findings
- [C-1 [Impact] via [Weakness] in [Feature]](#c-1-impact-via-weakness-in-feature) (VALID)
- [C-2 [Impact] via [Weakness] in [Feature]](#c-2-impact-via-weakness-in-feature) (QUESTIONABLE)

### High Findings
- [H-1 [Impact] via [Weakness] in [Feature]](#h-1-impact-via-weakness-in-feature) (VALID)
- [H-2 [Impact] via [Weakness] in [Feature]](#h-2-impact-via-weakness-in-feature) (DISMISSED)

### Medium Findings
- [M-1 [Impact] via [Weakness] in [Feature]](#m-1-impact-via-weakness-in-feature) (VALID)

### Low Findings
- [L-1 [Impact] via [Weakness] in [Feature]](#l-1-impact-via-weakness-in-feature) (QUESTIONABLE)

## Detailed Findings

[Full findings using the enhanced format from Section 4, including triager validation notes]

---

### POC Approach
Follow the proof of concept approach described in the configuration: Only if the repo is already configured with a testing framework, create complete test cases that demonstrate the vulnerability with realistic parameters. Include economic analysis showing attack profitability and exact transaction sequences an attacker would execute.
