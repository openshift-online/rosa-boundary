# Manage account-wide model activation once, retaining the original regional
# Bedrock API endpoint in var.aws_region. Marketplace entitlement propagates to
# other supported regions; regional availability and invocation IAM remain separate.

# An offer ID is reviewed and pinned in the manifest; the short-lived offer
# token is retrieved at plan time, never stored in Git or selected by position.
data "aws_bedrock_foundation_model_agreement_offers" "approved" {
  for_each   = var.bedrock_model_agreements
  model_id   = each.key
  offer_type = "PUBLIC"
}

import {
  for_each = var.adopt_existing_resources ? var.bedrock_model_agreements : {}
  to       = aws_bedrock_foundation_model_agreement.approved[each.key]
  id       = each.key
}

resource "aws_bedrock_foundation_model_agreement" "approved" {
  for_each = var.bedrock_model_agreements

  model_id = each.key
  offer_token = one([
    for offer in data.aws_bedrock_foundation_model_agreement_offers.approved[each.key].offers :
    offer.offer_token if offer.offer_id == each.value
  ])

  # Offer tokens can rotate even when the approved offer ID is unchanged.
  lifecycle {
    ignore_changes = [offer_token]

    precondition {
      condition = length([
        for offer in data.aws_bedrock_foundation_model_agreement_offers.approved[each.key].offers :
        offer.offer_id if offer.offer_id == each.value
      ]) == 1
      error_message = "The approved Bedrock offer ID for ${each.key} is not available; review the account's current offers and terms before applying."
    }
  }
}
