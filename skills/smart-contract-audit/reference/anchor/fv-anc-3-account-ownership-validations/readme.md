---
description: Verify account state and permissions.
---

# FV-ANC-3 Account/Ownership Validations



## Classifications

Run `cat $SKILL_DIR/reference/anchor/fv-anc-3-account-ownership-validations/<filename>` to read any case file listed below.

#### fv-anc-3-cl1-trying-to-modify-an-account-without-checking-if-its-writeable.md
#### fv-anc-3-cl10-using-ctx.remaining_accounts-without-non-zero-data-check.md
#### fv-anc-3-cl11-no-reload-after-account-mutation.md
#### fv-anc-3-cl12-not-validating-a-set-address.md
#### fv-anc-3-cl13-init-if-needed-without-reinit-guard.md
#### fv-anc-3-cl14-realloc-without-zero-init.md
#### fv-anc-3-cl2-trying-to-access-account-data-without-ownership-checks.md
#### fv-anc-3-cl3-usage-of-uncheckedaccount-without-manual-ownership-check.md
#### fv-anc-3-cl4-usage-of-uncheckedaccount-without-manual-signer-check.md
#### fv-anc-3-cl5-no-is_initialized-check-when-operating-on-an-account.md
#### fv-anc-3-cl6-missing-account-constraints.md
#### fv-anc-3-cl7-duplicate-mutable-accounts.md
#### fv-anc-3-cl8-using-ctx.remaining_accounts-without-manual-ownership-check.md
#### fv-anc-3-cl9-using-ctx.remaining_accounts-without-manual-discriminator-check.md