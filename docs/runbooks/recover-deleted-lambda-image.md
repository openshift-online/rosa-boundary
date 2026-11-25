# Recover a deleted create-investigation image

## Symptoms and cause

The `create-investigation` Lambda reports `Inactive` / `ImageDeleted` after its
deployed ECR image is deleted. Investigation API requests fail. Terraform may
spend about ten minutes retrying `UpdateFunctionConfiguration`, then fail with
HTTP 409: “the provided Image ID cannot be found.”

Restoring the ECR image alone is insufficient: AWS requires restoring access
**and updating the function**. The AWS provider used during the incident
(`6.58.0`) updates configuration before code, so a combined Terraform update
can fail before reaching the image update.

## 1. Authorize and identify

- Obtain incident/change approval for break-glass ECR publication and a direct
  Lambda code update. Use the **approved AWS account-access flow** for the target
  environment to obtain short-lived credentials; do not use shared/static keys
  or depend on the broken Boundary API for access. Record the actor and approval.
- Confirm the account, affected Region, function, and owning HCP workspace.
  Coordinate with other operators; let any existing apply finish before recovery.
  Do not recreate the function or edit Terraform state.

Set these values explicitly (commands below assume Bash, AWS CLI, and `skopeo`):

```bash
set -euo pipefail
ACCOUNT='<approved-account-id>'
REGION='<affected-region>'
FUNCTION='rosa-boundary-<stage>-create-investigation'
REPOSITORY='rosa-boundary/create-investigation-lambda'
PUBLISH_REGION='<source-ecr-region>'
test "$(aws sts get-caller-identity --query Account --output text)" = "$ACCOUNT"

aws lambda get-function --region "$REGION" --function-name "$FUNCTION" \
  --query '{State:Configuration.State,Reason:Configuration.StateReasonCode,Image:Code.ImageUri,Resolved:Code.ResolvedImageUri}'
```

Record the old image tag and **resolved digest** from this response.

## 2. Restore the exact old image (preferred)

Find the original artifact in Quay or another approved registry. Verify its
provenance; a rebuilt image with the same tag is **not** the same digest.

```bash
TAG='<old-commit-sha-tag>'
DIGEST='sha256:<old-resolved-digest>'
SOURCE='quay.io/redhat-user-workloads/rosa-tenant/create-investigation-lambda'
REGISTRY="${ACCOUNT}.dkr.ecr.${PUBLISH_REGION}.amazonaws.com"

# Temporary registry credentials; never print or commit them.
AUTHFILE=$(mktemp)
trap 'rm -f "$AUTHFILE"' EXIT
printf '{"auths":{}}\n' > "$AUTHFILE"
aws ecr get-login-password --region "$PUBLISH_REGION" |
  skopeo login --authfile "$AUTHFILE" --username AWS --password-stdin "$REGISTRY"
skopeo copy --preserve-digests --authfile "$AUTHFILE" \
  "docker://${SOURCE}@${DIGEST}" "docker://${REGISTRY}/${REPOSITORY}:${TAG}"
```

Where configured, publish to the source Region and let ECR replication deliver
the image. **Do not assume replication succeeded.** Before proceeding, verify
the tag resolves to the expected digest in the affected Region:

```bash
test "$(aws ecr describe-images --region "$REGION" \
  --repository-name "$REPOSITORY" --image-ids "imageTag=$TAG" \
  --query 'imageDetails[0].imageDigest' --output text)" = "$DIGEST"
```

## 3. Explicitly redeploy, then verify recovery

This is the approved **out-of-band AWS mutation**, not a Terraform apply.
Redeploy the restored image without invoking the function or changing its
configuration:

```bash
REVISION=$(aws lambda get-function-configuration --region "$REGION" \
  --function-name "$FUNCTION" --query RevisionId --output text)
aws lambda update-function-code --region "$REGION" \
  --function-name "$FUNCTION" --revision-id "$REVISION" \
  --image-uri "${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/${REPOSITORY}:${TAG}" \
  --query '{State:State,LastUpdateStatus:LastUpdateStatus}'
aws lambda wait function-updated-v2 --region "$REGION" --function-name "$FUNCTION"
aws lambda get-function --region "$REGION" --function-name "$FUNCTION" \
  --query '{State:Configuration.State,Update:Configuration.LastUpdateStatus,Reason:Configuration.StateReason,Resolved:Code.ResolvedImageUri}'
```

**Stop unless** the function is `Active`, the update is `Successful`, and the
resolved digest matches `$DIGEST`. On failure, inspect the state/update reasons,
image availability, and ECR access; escalate rather than repeatedly retrying.

## 4. Reconcile through Terraform

Only after recovery is verified, queue a fresh run in the owning HCP regional
workspace. Review the plan and follow its apply approval requirements; do not
use local dev Terraform commands or directly edit HCP-managed variables.
See [staging delivery](../staging-deployment.md).

Verify the apply succeeds and Lambda is `Active` / `Successful` on the
**Git-pinned desired image digest**, which may differ from the restored image.
Record the image digests, AWS update result, and HCP run link in the incident.
API availability still requires a separately approved functional check.

## Alternative: deploy a new image instead

If the old artifact is unavailable, build/release an approved replacement through
the normal image pipeline and publish it to ECR. Verify architecture, provenance,
and availability in every target Region. Review and merge the new immutable
`lambda_image_tag` in `hcp-terraform/rosa-boundary/main.tf`; do not change HCP
variables directly. Follow the staging guide's gating procedure **before merging**
if auto-apply must be held during recovery.

Use the replacement tag and digest as `$TAG` and `$DIGEST`, then perform the
**same explicit code update and recovery checks in step 3**, followed by Terraform
reconciliation in step 4. A pin-only PR does not bypass configuration-first
ordering. This path runs new code against the existing configuration first, so
check compatibility and obtain approval for that transition.

**Follow-up:** fix image retention so deployed and required rollback digests are
not expired. Restoring service does not resolve the retention defect.

References: [AWS function-state recovery](https://docs.aws.amazon.com/lambda/latest/dg/functions-states.html),
[UpdateFunctionCode](https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionCode.html),
[incident ROSAENG-76760](https://redhat.atlassian.net/browse/ROSAENG-76760).
