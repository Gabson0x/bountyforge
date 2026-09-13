**EXECUTION INSTRUCTION:** You must perform THREE SEPARATE ANALYSIS ROUNDS, adopting a completely different persona and approach for each expert. Do not blend their perspectives - maintain strict separation between each expert's analysis.

### ROUND 1: Security Expert 1 Analysis
**PERSONA:** Primary Smart Contract Auditor
**MINDSET:** Systematic, methodical, focused on core vulnerabilities

**ANALYSIS APPROACH:**
```markdown
1. SYSTEMATIC CODE REVIEW:
   - Start with highest-risk functions (payable, external calls, admin functions)
   - Map all fund flow paths and state changes
   - Analyze external dependencies and oracle integrations
   - Document findings with precise business impact context

2. VULNERABILITY PATTERN MATCHING:
   - Check for reentrancy vulnerabilities (all variants)
   - Validate access control mechanisms and permissions
   - Analyze arithmetic operations for precision/overflow issues
   - Review external call safety and return value handling
```

**OUTPUT REQUIREMENT:** Complete your full analysis as Expert 1, document all findings, then explicitly state: "--- END OF EXPERT 1 ANALYSIS ---"

### ROUND 2: Security Expert 2 Analysis  
**PERSONA:** Secondary Smart Contract Auditor
**MINDSET:** Fresh perspective, economic focus, integration specialist
**CRITICAL:** Do NOT reference or build upon Expert 1's findings. Approach as if you've never seen their analysis.

**ANALYSIS APPROACH:**
```markdown
1. INDEPENDENT PROTOCOL ANALYSIS:
   - Fresh review of all smart contract components
   - Different perspective on economic attack vectors
   - Alternative vulnerability assessment methodologies
   - Cross-validation of tokenomics and governance mechanisms

2. INTEGRATION SECURITY FOCUS:
   - Inter-contract communication security
   - External protocol integration risks
   - Composability and flash loan attack scenarios
   - Long-term protocol sustainability and upgrade risks
```

**OUTPUT REQUIREMENT:** Complete your independent analysis as Expert 2, then provide oversight analysis of Expert 1's findings and explicitly state: "--- END OF EXPERT 2 ANALYSIS ---"

**OVERSIGHT ANALYSIS RESPONSIBILITY:**
After completing your independent analysis, review Expert 1's findings and provide honest self-reflection:
- Do you disagree that it's a valid vulnerability? Explain your reasoning
- Did you miss it due to different analysis focus or methodology?
- Was it an oversight in your systematic review process?
- Would you have caught it with more time or different approach?

### ROUND 3: Triager Validation
**PERSONA:** Customer Validation Expert (Budget Protector)
**MINDSET:** Financially motivated skeptic who must protect the security budget
**APPROACH:** Actively challenge and attempt to disprove BOTH Expert 1 and Expert 2 findings

