# Regional delivery of the create-investigation Lambda image

Status: proposed; no infrastructure changes authorized by this document.

## Problem and decision

AWS Lambda requires its container image in ECR in the same account and Region as the function. Boundary currently builds `create-investigation-lambda` in Konflux, publishes it to Quay, and manually copies selected images into regional ECR repositories under a Quay pull-through-cache prefix. Lambda's image pull does not populate that cache. Every new image and Region therefore creates manual publication and recovery work.

**Propose keeping image packaging and publishing once per environment to an ordinary ECR source repository, followed by ECR private-registry replication to that environment's other Boundary Regions.** Staging and production use separate AWS accounts, release decisions, credentials and image pins. The ECS investigation image continues to come directly from Quay; this proposal does not mirror it to ECR or change the local-development ZIP option.

```text
Konflux build: create-investigation-lambda (Lambda-compatible linux/amd64 image)
  ├─ existing Quay release, including the ECS image: unchanged
  ├─ approved staging release → stage account / source Region / ordinary ECR repo
  │                                 └─ ECR replication → other stage Regions
  └─ independently approved production release → prod account / source Region / ordinary ECR repo
                                            └─ ECR replication → other prod Regions

Regional Lambda → image in ECR in its own account and Region, pinned by approved SHA
```

The source Region is selected from the approved deployment inventory, not inferred from old rollout plans. Replication is asynchronous, non-transitive and does not propagate deletes or repository policies. A source push is not a regional deployment or a production approval.

## End-state configuration and ownership

| System | Proposed responsibility |
| --- | --- |
| Boundary `deploy/account/` | Own the ordinary source ECR repository in the account's selected source Region and the account's single, narrowly filtered ECR registry replication configuration. Inventory existing registry rules before taking ownership; do not overwrite rules belonging to another workload. |
| Boundary `deploy/regional/` | Own ordinary ECR repositories and their settings in **destination** Regions, but not a duplicate repository in the account-owned source Region. Construct the Lambda image URI from the local account, Region, repository name and approved tag. Remove the obsolete Terraform-managed pull-through-cache rule only after all consumers have migrated. Existing cache-created repositories and rollback images require separate inventory and cleanup. |
| `service/app-interface` | Register each publishing account/source-Region ECR registry under `data/aws/<account>/ecr/` using the existing `aws-ecr-image-pull-secrets` integration. This provides refreshed, short-lived Docker credentials in Vault; it does **not** create the repository. Separate stage and prod registrations are required. |
| `releng/konflux-release-data` | Sync each generated credential with an `ExternalSecret`, link it to the approved release pipeline service account, and configure a Lambda-only ECR `ReleasePlanAdmission` and a release selection for each environment. Changes are authored as reviewed MRs; `config/` is managed release configuration, while `tenants-config/` requires generated manifests and its separate reconciliation path. |
| Boundary `hcp-terraform/rosa-boundary/` | Keep regional Lambda image pins in Git-managed workspace variables. Promotion remains a PR/review operation gated on the actual ECR images being available in **all** intended Regions. Do not change HCP-managed regional variables through the UI/API. |

The source and destination repositories have the **same ordinary repository name**, distinct from the existing `${project}-quay/...` pull-through-cache namespace. Use immutable commit-SHA tags, consistent encryption, repository policies and lifecycle rules, and retain known-good images in every Region for rollback. Since repositories are created by Terraform, ECR repository-creation templates do not configure them. Replication must have one Terraform owner per account; regional Terraform states must not each manage the registry-wide policy. Cross-account replication is not part of this design.

## Konflux release and credential boundary

The current [Boundary release admission](https://gitlab.cee.redhat.com/releng/konflux-release-data/-/blob/main/config/kflux-prd-rh02.0fk9.p1/service/ReleasePlanAdmission/rosa/rosa.yaml) publishes Boundary's components to Quay, and the existing Boundary ReleasePlan targets that admission. Preserve this behavior, especially for the ECS image. The working [kube-applier ECR admission](https://gitlab.cee.redhat.com/releng/konflux-release-data/-/blob/main/config/kflux-prd-rh02.0fk9.p1/service/ReleasePlanAdmission/rosa/hyperfleet-kube-applier-ecr.yaml) is a template for `rh-push-to-external-registry`, SHA/digest tags, Pyxis metadata and the ECR release service account. The new ECR admission should map **only** `create-investigation-lambda`; it must not publish the ECS image to ECR or automatically change the Quay admission.

A ReleasePlanAdmission alone does not initiate a release. Define a distinct, approved ReleasePlan or other supported release selection for each environment, and validate how multiple plans for the same Boundary application interact. Boundary's base ReleasePlan currently has `auto-release: "true"`. A successful build or staging release **must not** implicitly push to production. The production approval mechanism, admission policy and service-account access must be confirmed before enabling production publication; if the existing shared ECR service account grants overly broad stage/prod access, use a reviewed isolation design rather than silently attaching both credentials. Do not introduce static AWS keys into Git, images, or investigations.

App-interface needs separate [ECR registrations](https://gitlab.cee.redhat.com/service/app-interface/-/blob/master/data/aws/rosa-hyperfleet-image-registry/ecr/ecr.yml) for Boundary stage and prod; neither registration was present on upstream `master` checked 2026-10-28. Its integration writes credentials to `app-sre/integrations-output/aws-ecr-image-pull-secrets/<account>/<region>/dockercfg`. The release-data [ExternalSecret pattern](https://gitlab.cee.redhat.com/releng/konflux-release-data/-/blob/main/tenants-config/lib/releng/external-secrets/common/ecr-token-rosa-hyperfleet-image-registry.yaml) uses the existing Vault SecretStore, and the release service account links the resulting secret. Check Vault generation, ExternalSecret health, service-account linkage and actual repository push access; an MR or a passing build does not prove these steps. Submit normal app-interface and release-data MRs for review rather than assuming all configuration lives in release-data.

### Staging source publication: merge and activation order

1. Merge the `service/app-interface` staging account/`us-east-1` ECR registration and wait for AppSRE reconciliation. Verify the generated Vault credential exists; registration does not create the ECR repository or establish push permission.
2. Merge the `rosa-boundary` account-root repository and Git-managed workspace switch. Review the speculative/account plan, check for an existing repository and unrelated account changes, then approve the account workspace's **manual** apply separately. Confirm the ordinary repository exists in staging `us-east-1`; merging code alone does not create it. Do not apply a plan that re-creates account resources awaiting the separate state handoff.
3. Merge the `konflux-release-data` staging ExternalSecret, dedicated release service account, Lambda-only admission and manual ReleasePlan. Wait for tenant reconciliation and secret sync, verify the credential can push to this repository, then request an approved staging release. Confirm the full-SHA tag and amd64 image in ECR. The existing automatic Quay plan remains unchanged; **do not** select the ECR plan until the repository and secret are ready. No production destination or Lambda cutover is part of this sequence.

The first two code merges can be reviewed independently, but the required *activation* sequence is credential registration → source repository apply → Konflux secret sync and manual release. Keep the account and region values aligned across all three repos.

## Artifact availability contract

Git promotion is separate from publication: an approved SHA may be pinned for deployment only after its Lambda-compatible image is present in ECR in **every target account/Region**. Replication is asynchronous, so neither a successful Konflux release nor a Terraform plan establishes availability. The promotion mechanism and owner remain to be defined; it must enforce this check before a pin merges or a regional apply starts, including if HCP auto-apply is enabled. Retain known-good images in each Region for rollback. Existing images need an explicit [replication backfill](https://docs.aws.amazon.com/AmazonECR/latest/userguide/replication-backfill.html) or repush because enabling replication does not copy them retroactively. Record the Konflux release, source digest, ECR manifest and SHA tag so a registry-format change is not mistaken for a different build.

## Cost and scale

Replication is **not free**: AWS [charges cross-Region ECR replication data transfer out](https://aws.amazon.com/ecr/pricing/) from the source Region and private-repository storage in **each** Region. In-Region ECR-to-Lambda transfers are free. This is a small image: inspection of the current Konflux-built `create-investigation-lambda:d9c5746ebee2a2e2f93ff618377f13a7aa0d9c30` in Quay on 2026-10-28 showed two compressed layers of 40,708,738 and 46,302,000 bytes, **87,010,738 bytes total (87 MB / 83 MiB)**. The corresponding local Podman image is approximately 227 MB *uncompressed*; that number should not be used as ECR storage or replication transfer volume. An older, different Lambda image in the personal dev ECR repository reports 276,904,922 bytes in `DescribeImages`, so remeasure an actual release into the new repository rather than treating the Quay estimate as a guarantee.

**Illustrative monthly cost per environment**, assuming a single 87 MB image per release, four releases per month, ten retained versions in every Region, `$0.10/GB-month` for private ECR storage, and `$0.02/GB` cross-Region transfer out from `us-east-1` to each destination (rates checked with the [AWS Price List Query API](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/using-price-list-query-api.html) on 2026-10-28 for ECR storage in the currently listed production Regions and for `us-east-1` outbound transfer to those Regions; additional Region pairs must be priced separately):

| Footprint (including source) | Storage: `0.087 GB × Regions × 10 × $0.10` | Replication: `0.087 GB × destinations × 4 × $0.02` | Approximate total/month |
| --- | ---: | ---: | ---: |
| Two Regions, e.g. staging | $0.17 | $0.01 | **$0.18** |
| Five Regions, e.g. current production account inventory | $0.44 | $0.03 | **$0.46** |
| Sixteen Regions (source + 15 destinations) | $1.39 | $0.10 | **$1.50** |

This is **per account**, excludes the existing ECS image and other ECR usage, and assumes every retained version consumes the full 87 MB; shared layers can lower storage and transferred bytes. Actual rates, bytes, retained versions, image signing, enhanced scanning and any customer-managed KMS charges must be checked for the chosen Regions and repository settings. Storage is the dominant modeled cost; even the 16-Region estimate is dollars rather than hundreds of dollars per month. Keep sufficient versions for rollback instead of reducing retention solely to save a small storage charge.

ECR permits up to **25 unique replication destinations per source registry across all rules**. The design also depends on the destination Regions being enabled and included in account configuration. At the time of review, the app-interface stage account listed only `us-east-1` as a supported deployment Region despite a Boundary staging workspace in `us-west-2`; confirm whether that configuration must change. Account-wide ECR replication rules shared with other workloads count toward the quota and must not be overwritten.

## Alternatives and boundaries

Direct Konflux pushes into every Region multiply release destinations and credentials. The existing Quay pull-through-cache prefix cannot be relied on for Lambda initialization, and direct pushes into cache-managed repositories are unsupported. ZIP packaging would replace the present remote-runner image path with a separate trusted build and same-Region S3 distribution problem; it is not proposed here. ECR replication does **not** automate HCP image-pin promotion, audit storage, or ECS image delivery.

## References

- Boundary: [`deploy/regional/ecr.tf`](../../deploy/regional/ecr.tf), [`deploy/regional/lambda-create-investigation.tf`](../../deploy/regional/lambda-create-investigation.tf), [`hcp-terraform/rosa-boundary/main.tf`](../../hcp-terraform/rosa-boundary/main.tf), [staging delivery](../staging-deployment.md).
- [App-interface regional ECR and Konflux guide](https://gitlab.cee.redhat.com/service/app-interface/-/blob/master/docs/tenant-services/rosa-hcp-log-forwarder/konflux-ecr-mirroring-multi-region.md); [ECR replication behavior](https://docs.aws.amazon.com/AmazonECR/latest/userguide/replication.html); [replication backfill](https://docs.aws.amazon.com/AmazonECR/latest/userguide/replication-backfill.html).
- Tracking: [ROSAENG-67186](https://redhat.atlassian.net/browse/ROSAENG-67186) (manual ECR copies) and [ROSAENG-67168](https://redhat.atlassian.net/browse/ROSAENG-67168) (image-pin promotion). Confirm current issue scope and owners before implementation.
