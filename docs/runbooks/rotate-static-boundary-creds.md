# Rotate Static Credentials

Static Credential List:
- GitHub bot user (rosa-zoa-bot)
- TFE_TOKEN Terraform API key

The HCP Terraform user for rosa-zoa-bot signs in through GitHub (APPSRE-15670), so a separate HCP Terraform
password and TOTP are no longer required for sign-in. Rotating the GitHub bot user credentials covers its sign-in.

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

A Terraform HCP user exists for rosa-zoa-bot. That account is already linked to the GitHub machine user
[rosa-zoa-bot](https://github.com/rosa-zoa-bot) and signs in through GitHub, so the legacy HCP Terraform password
and TOTP are no longer required for sign-in. No new HCP Terraform account or organization is required.

Sign-in steps:
1. Open [Terraform HCP](https://app.terraform.io)
2. Continue with the HCP account
3. Select "Sign in with GitHub"
4. Authenticate as the GitHub machine user rosa-zoa-bot using the credentials from
   [app-SRE Vault](https://vault.devshift.net/ui/vault/secrets/rosa-boundary/kv/CICD)
5. Complete GitHub two-factor authentication. Vault UI does not currently support TOTP, authenticate via CLI and
   use the following:
```
$ vault read -field=code totp/rosa-boundary/code/github-rosa-zoa-bot
```

To rotate the underlying credentials, follow [GitHub Bot User](#github-bot-user) above.

## TFE_TOKEN Terraform API Key

`TFE_TOKEN` is a user API token belonging to the rosa-zoa-bot HCP Terraform user. Rotating it is independent of
GitHub sign-in: signing in with GitHub does not rotate `TFE_TOKEN`, and rotating `TFE_TOKEN` does not change the
GitHub bot credentials.

Steps:
1. Sign into [Terraform HCP](https://app.terraform.io) as rosa-zoa-bot following the sign-in steps in
   [Terraform user for rosa-zoa-bot](#terraform-user-for-rosa-zoa-bot) above
2. Navigate to Account Settings -> Tokens
3. Create a new API Token, name it to adequately reflect that it is new
4. Copy this new token - this is the only time you'll be able to view it.
5. With a privileged terraform HCP user (your own, most likely), update the `rosa-admin-creds` variable set in the
   `meta-rosa` project to contain this new API token value as `TFE_TOKEN`. Update the description to reflect it
   was rotated, as the "updated date" of the variable set doesn't seem to reflect updates to variable values
   - which is misleading.
6. Initiate plan-only runs in each of the `meta-` workspaces utilizing the variable set.
7. Delete the old token.
