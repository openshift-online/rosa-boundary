# Rotate Static Credentials

Static Credential List:
- GitHub bot user (rosa-zoa-bot)
- Terraform user for rosa-zoa-bot
- TFE_TOKEN Terraform API key

## GitHub Bot User

https://github.com/rosa-zoa-bot

Credentials stored in [app-SRE Vault](https://vault.devshift.net/ui/vault/secrets/rosa-boundary/kv/CICD). Vault UI
does not currently support TOTP, authenticate via CLI and use the following:
```
$ vault read -field=code totp/rosa-boundary/code/github-rosa-zoa-bot
```

Steps:
1. Log in using the credentials from vault
2. In account settings, update the password
3. Create a new vault secret version with the updated password

## Terraform user for rosa-zoa-bot

A Terraform HCP user exists for rosa-zoa-bot. Credentials stored in [app-SRE Vault](https://vault.devshift.net/ui/vault/secrets/rosa-boundary/kv/CICD). Vault UI
does not currently support TOTP, authenticate via CLI and use the following:
```
$ vault read -field=code totp/rosa-boundary/code/terraform-rosa-zoa-bot
```

Steps:
1. Log into [Terraform HCP](https://app.terraform.io) using the credentials from vault
2. Navigate to Account Settings -> Password
3. Set a new password
4. Update the vault entry

## TFE_TOKEN Terraform API Key

A Terraform HCP user exists for rosa-zoa-bot. Credentials stored in [app-SRE Vault](https://vault.devshift.net/ui/vault/secrets/rosa-boundary/kv/CICD). Vault UI
does not currently support TOTP, authenticate via CLI and use the following:
```
$ vault read -field=code totp/rosa-boundary/code/terraform-rosa-zoa-bot
```

Steps:
1. Log into [Terraform HCP](https://app.terraform.io) using the credentials from vault
2. Navigate to Account Settings -> Tokens
3. Create a new API Token, name it to adequately reflect that it is new
4. Copy this new token - this is the only time you'll be able to view it.
5. With a privileged terraform HCP user (your own, most likely), update the `rosa-admin-creds` variable set in the
   `meta-rosa` project to contain this new API token value as `TFE_TOKEN`. Update the description to reflect it
   was rotated, as the "updated date" of the variable set doesn't seem to reflect updates to variable values
   - which is misleading.
6. Initiate plan-only runs in each of the `meta-` workspaces utilizing the variable set.
7. Delete the old token.
