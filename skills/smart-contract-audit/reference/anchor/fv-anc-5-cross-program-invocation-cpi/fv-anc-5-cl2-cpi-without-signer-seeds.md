# FV-ANC-5-CL2 CPI Without Signer Seeds

## TLDR

When a CPI requires a PDA to sign on behalf of the program, `invoke_signed` must be called with the correct signer seeds. Using `invoke` or passing empty seeds to `invoke_signed` causes the CPI to fail or to execute without the PDA's authority, breaking the intended access control.

## Detection Heuristics

**invoke Used Where PDA Signature Is Required**
- `invoke(&instruction, &accounts)?` called when one of the accounts listed is a PDA that needs to sign; the PDA will not be recognized as a signer by the callee
- CPI to the Token Program for a PDA-owned token account using `invoke` instead of `invoke_signed`

**invoke_signed With Empty Seeds**
- `invoke_signed(&instruction, &accounts, &[])` where one of the accounts is a PDA, providing no signing authority
- Seeds array passed to `invoke_signed` does not include the seeds for all PDAs that must sign

**Incorrect or Incomplete Seeds**
- Signer seeds passed to `invoke_signed` do not match the seeds used to derive the PDA, causing signature verification to fail at the callee
- Bump seed omitted from the signer seeds array

## False Positives

- CPI is initiated on behalf of a user who signed the transaction; the user's `AccountInfo` carries `is_signer = true` and no PDA signature is needed
- `invoke` is correct when none of the accounts in the CPI need to be PDAs signing on behalf of the program
