# ROSA Boundary: bootstrap a personal dev account

Use a current ROSA Boundary checkout and **your own** AWS account with administrator access, AWS CLI, Terraform `>= 1.15, < 2.0`, Podman, Go, a GitHub token for image builds, and an SRE login provisioned in an approved development Keycloak realm. This is a local-state **dev** deployment, not the HCP staging workflow. Keep Terraform state, `.env`, and credentials private. Do not deploy the Keycloak manifests when reusing an existing identity provider. Obtain your account, region, OIDC provider, client, required group/role, and approved test cluster from your operator; no other contributor's values are defaults.

1. **Request Keycloak access.** Ask an administrator to create your SRE user in the approved realm and assign the required realm role/group (for example, `ai-sd-sre`). Do not use an administrator login for the CLI. Confirm the public OIDC client emits the configured role and the principal tag matching `abac_tag_key` (for example, `principal_tags.username`). Distinguish the provider's **base URL** (CLI input) from the issuer (base URL plus `/realms/<realm>` for this Keycloak setup). Independently verify the issuer TLS thumbprint; do not copy a historical thumbprint.

2. **Account IAM first.** Set `ACCOUNT` and `REGION` to your approved values and confirm `aws sts get-caller-identity` returns **your** account. Copy `deploy/account/terraform.tfvars.example` to `deploy/account/terraform.tfvars`. Supply your account/region, issuer/thumbprint/client, budget email/limit, `legacy_policy_region` and `legacy_role_tag_region` matching your original region, `adopt_existing_resources = false`, and your approved OIDC group enforcement settings (`enable_oidc_group_enforcement = true` and the actual `required_oidc_role`, if applicable). For minimal dev without approved Bedrock agreements use `bedrock_model_agreements = {}`; that alone does not prove Bedrock access is restricted. Inspect `deploy/account/Makefile`, then `make -C deploy/account init plan`; review the plan before `make -C deploy/account apply`. If the account already has regional/IAM state, follow the [ownership handoff](../../deploy/account/README.md#existing-deployment-handoff) instead of creating duplicate roles or importing automatically.

3. **Network.** For a new network, create `deploy/network/terraform.tfvars` with your account/region and `stage = "dev"`; select non-overlapping CIDRs. Inspect the network Makefile, run `make -C deploy/network init plan`, review, then `make -C deploy/network apply`. Use `make -C deploy/network output` to obtain the VPC and **private** subnet IDs; the network provides internet/NAT routing for Fargate. Reuse an existing VPC only after verifying its subnet/routing and ownership instead of provisioning another one.

4. **Build and publish the task image before regional apply.** Supply `GITHUB_TOKEN` securely. If unset and `gh` is authenticated, `export GITHUB_TOKEN="$(gh token)"` may be used without printing the token. Build through the root Makefile and verify the image architecture before publishing. For an AMD64 task:

   ```bash
   make build-amd64
   podman image inspect rosa-boundary:latest-amd64 --format '{{.Architecture}}' # amd64
   ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
   REGION="${REGION:?Set REGION to your approved AWS region first}"
   TAG="${TAG:?Set TAG to a unique approved source revision tag first}"
   ECR="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com"
   aws ecr create-repository --repository-name rosa-boundary --region "$REGION" # new repository only
   aws ecr get-login-password --region "$REGION" | podman login --username AWS --password-stdin "$ECR"
   podman tag rosa-boundary:latest-amd64 "$ECR/rosa-boundary:$TAG"
   podman push "$ECR/rosa-boundary:$TAG"
   aws ecr describe-images --repository-name rosa-boundary \
     --image-ids "imageTag=$TAG" --region "$REGION" \
     --query 'imageDetails[0].imageDigest' --output text
   ```

   Replace the tag placeholder and record the observed digest. Configure Terraform using an `@sha256:...` image URI when possible: a mutable `:latest` tag or a local Podman image is not proof of which image a task launched. Do not publish until the account, tag, revision, architecture and test scope are approved.

5. **Regional.** Copy `deploy/regional/terraform.tfvars.example` to `deploy/regional/terraform.tfvars`. Supply your account/region, `stage = "dev"`, the account root's `legacy_policy_region`/role prefix, VPC/private subnet IDs, pushed image URI, OIDC issuer/thumbprint/client, `required_groups`, and `abac_tag_key` matching the token's principal tag. Use `enable_kube_proxy = false` if no working sidecar secret is configured. Leave Lambda packaging at the default `Zip` unless intentionally testing another mode. A gitignored root `.env` must include `KEYCLOAK_ISSUER_URL` for the regional Makefile; also set `TF_VAR_abac_tag_key` and `TF_VAR_enable_kube_proxy` to the intended values because that Makefile's fallbacks override tfvars. Inspect the Makefile and effective variable precedence **without printing secrets**. Run `make -C deploy/regional init`, `make -C deploy/regional validate`, and `make -C deploy/regional plan`; review the account guard, changes, cost, IAM/ABAC and audit effects before `make -C deploy/regional apply` (which builds Lambda dependencies). Do not run Terraform directly or use the targeted, auto-approved `lambda` target.

6. **Configure CLI.** Run `make build-cli` (and optionally `make install-cli`); install `session-manager-plugin`. For a development provider other than CLI defaults, explicitly supply the contributor's base URL, realm and client ID. Use isolated `XDG_CONFIG_HOME` and `XDG_CACHE_HOME` for dev so an existing staging config/token cannot be reused:

   ```bash
   rosa-boundary --keycloak-url "$KEYCLOAK_BASE_URL" \
     --realm "$REALM" --client-id "$CLIENT_ID" configure \
     --account-id "$ACCOUNT" --region "$REGION" --project rosa-boundary --environment dev
   ```

   Discovery writes `config.yaml` under the selected XDG config directory. Verify its Lambda, invoker/SRE role ARNs and EFS filesystem belong to **your** account, and its region/ECS cluster and OIDC settings match the intended stack; do not copy another person's config. See [user access guide](user-access-guide.md) for manual configuration or troubleshooting.

7. **Validate on an approved cluster** (with explicit approval to create an investigation). Authenticate as the SRE user, choose a unique investigation ID, bound the task lifetime, and record the task ID:

   ```bash
   CLUSTER_ID="approved-cluster-id"; INV_ID="unique-smoke-test-id"
   rosa-boundary login
   rosa-boundary start-task --cluster-id "$CLUSTER_ID" --investigation-id "$INV_ID" --task-timeout 900
   TASK_ID="task-id-from-start-task"
   rosa-boundary join-task "$TASK_ID"
   # In task: printf 'boundary smoke test\n' > ~/boundary-smoke-test.txt ; exit
   rosa-boundary stop-task "$TASK_ID" --wait
   # Verify CloudWatch session logs, container sync status, and S3 marker object
   # with a separately authorized audit-reader identity.
   rosa-boundary close-investigation --cluster-id "$CLUSTER_ID" --investigation-id "$INV_ID" --yes
   ```

   `exit` only disconnects ECS Exec; `stop-task --wait` does not prove S3 sync succeeded. Verify evidence *before* closure, do not use `--force` to skip stopping, and report any incomplete cleanup. See the [investigation workflow](investigation-workflow.md) for audit and recovery details.

Check the current [account README](../../deploy/account/README.md), [network root](../../deploy/network/), and [regional Makefile](../../deploy/regional/Makefile) before deployment. Older [regional README](../../deploy/regional/README.md) examples put ECR after apply and use a specific region; follow the verified image-first order and your approved region instead.
