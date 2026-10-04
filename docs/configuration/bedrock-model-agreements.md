# Bedrock model agreements

Set `bedrock_model_agreements` for the regional Terraform deployment to manage
account-level agreements. It defaults to an empty map. Keep each environment's
manifest in its normal Terraform variable source; staging variables are managed
in `hcp-terraform/rosa-boundary/main.tf`.

Within an environment, key each model by its **foundation model ID**, not an
inference profile ID. The value is the selected PUBLIC offer ID, after reviewing
its terms and pricing. If the offer changes, review it again before updating
the manifest. Never commit offer tokens or signed legal-document URLs.

## Finding IDs

Use the credentials for the target AWS account and the Region configured for
the regional stack. The example map is in
`deploy/regional/terraform.tfvars.example`. Set `AWS_REGION` to that Region and
`MODEL_ID` to the foundation model ID selected in step 1.

1. Confirm the account with `aws sts get-caller-identity`. Find candidate
   foundation model IDs in the Bedrock model catalog or list them with:

   ```bash
   aws bedrock list-foundation-models --region "$AWS_REGION" \
     --query 'modelSummaries[].modelId' --output text
   ```

2. For each chosen foundation model ID, retrieve its PUBLIC offer IDs:

   ```bash
   aws bedrock list-foundation-model-agreement-offers \
     --region "$AWS_REGION" --model-id "$MODEL_ID" --offer-type PUBLIC \
     --query 'offers[].offerId' --output text
   ```

   Review that offer's legal terms and pricing before using its ID as the
   model's value in the manifest. The full offers response includes terms,
   short-lived offer tokens, and signed legal-document URLs; do not put tokens
   or signed URLs in Git, tickets, or logs. Terraform fetches the token itself.

Offer IDs identify offers, **not AWS accounts**. A PUBLIC offer ID may be
available in multiple accounts, but do not assume it is valid or approved in a
different account or Region: query and review the offers for each deployment.
PRIVATE offers are not selected by this configuration.

## Adopting an agreement already in the account

Terraform does not discover existing agreements automatically. If a model is
already enabled in the target account and Region, confirm it before adding it
to the manifest:

```bash
aws bedrock get-foundation-model-availability \
  --region "$AWS_REGION" --model-id "$MODEL_ID" \
  --query 'agreementAvailability.status' --output text
```

If the status is `AVAILABLE`, add the model and approved offer ID to that
environment's manifest, then use a **one-time Terraform import block** for the
same model ID, for example:

```hcl
import {
  to = aws_bedrock_foundation_model_agreement.approved["anthropic.claude-sonnet-5"]
  id = "anthropic.claude-sonnet-5"
}
```

Review the plan to ensure the agreement is **imported**, not created or
destroyed, then apply through the environment's normal Terraform workflow.
Remove the temporary import block once the agreement is in that workspace's
state. Do not leave an account-specific import block in the shared configuration
or apply it in an account where that agreement does not already exist. This is
an operator action, not automatic pre-existing-agreement handling in the module.

Removing an entry deletes the agreement **for the account**, potentially
affecting other workloads. The manifest does not configure clients or enforce
which models a task can invoke: Bedrock invocation IAM and endpoint policies
are separate, and the task role has no Marketplace subscription permissions.

Offer tokens are resolved at plan time and stored in Terraform state. Updating
`offer_id` on an already-managed agreement does not renegotiate it because
token changes are ignored; treat an offer change as a separate migration.

See [AWS model access](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html).
