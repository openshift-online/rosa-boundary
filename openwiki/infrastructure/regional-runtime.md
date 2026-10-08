---
type: infrastructure
title: Regional AWS runtime infrastructure
description: Describes the Terraform-owned regional ECS, EFS, IAM, audit storage, Lambda, encryption, and Bedrock resources and their key configuration constraints.
tags: [terraform, aws, ecs, efs, iam, bedrock]
sources:
  - id: openwiki-source-af67bd84d6fb827de35fd527
    resource: repo://deploy/regional/bedrock-endpoint.tf
  - id: openwiki-source-43a5f7fe8e3da821d41a4dba
    resource: repo://deploy/regional/bedrock-large-payloads.tf
  - id: openwiki-source-86eaa81471e45a1fc5290cf1
    resource: repo://deploy/regional/bedrock-logging.tf
  - id: openwiki-source-1b95528602e54ea488eb9250
    resource: repo://deploy/regional/bedrock-model-agreements.tf
  - id: openwiki-source-f1bd1e0a9201f149b775a09c
    resource: repo://deploy/regional/ecs.tf
  - id: openwiki-source-e1ea6906f2471c7921ff32ce
    resource: repo://deploy/regional/efs.tf
  - id: openwiki-source-d176128a85129af793772942
    resource: repo://deploy/regional/lambda-create-investigation.tf
  - id: openwiki-source-a7f1ddde1efa89d5bfad2d5c
    resource: repo://deploy/regional/lambda-reap-tasks.tf
  - id: openwiki-source-a467cf2af07b3f58e60a50ab
    resource: repo://deploy/regional/main.tf
  - id: openwiki-source-dcec1f4680246d4606ff71f8
    resource: repo://deploy/regional/s3.tf
  - id: openwiki-source-92cccd8107e9e4386a317d7a
    resource: repo://deploy/regional/tests/claude_default_model.tftest.hcl
  - id: openwiki-source-a055ff9a3fcbd2c0a0fc4ee2
    resource: repo://deploy/regional/variables.tf
generated: { by: "opencode", at: "2026-10-05T17:08:59.471Z" }
verified:
  - by: openwiki/0.7.0
    at: 2026-10-05T19:18:44.075Z
---

# Regional AWS runtime infrastructure

`deploy/regional/` defines the AWS resources that host investigations. Terraform takes the account, region, VPC, subnet, container-image, and identity inputs; the provider restricts deployment to the configured 12-digit account ID. Configuration includes checks for at least two task subnets and usable default routes, because Fargate needs outbound access to ECR. The directory Makefile sources the repository `.env`, exposes Terraform targets, and builds create-investigation Lambda dependencies before apply.

## ECS, EFS, and task roles

The regional stack creates an ECS cluster with Container Insights and ECS Exec logging/encryption configuration, CloudWatch log groups, a Fargate security group, and a task definition. The task definition runs the `rosa-boundary` container, mounts the baseline EFS home through an EFS access point, and overlays empty task-scoped volumes at `/home/sre/.config/ocm` and `/home/sre/.kube`. An optional `kube-proxy` sidecar consumes a cluster kubeconfig secret and exposes its proxy only on localhost; the main container waits for its health check when enabled.

EFS is encrypted and mounted through dedicated per-subnet mount targets. The baseline access point presents UID/GID 1000 and `/home/sre`; the filesystem policy requires the task role to mount via an access point. At investigation creation, Lambda creates a separate access point rooted at `/<cluster-id>/<investigation-id>` and rewrites the per-investigation task definition to use it.

IAM separates the ECS execution role from the task role. The execution role supports image pulls/logging and secret retrieval; the task role carries runtime permissions for audit S3 writes, Bedrock, ECS Exec messaging, session logging, KMS, and EFS access. The shared SRE operator role is separately defined with OIDC/ABAC permissions; see [identity and access](../architecture/identity-and-access.md) for its trust and task-level controls.

## Audit and session records

The investigation audit bucket is versioned, uses S3 Object Lock compliance retention, blocks public access, encrypts objects with AES-256, and denies non-TLS requests. An optional cross-account replication configuration requires the destination account ID and transfers ownership to the destination account. Container shutdown syncs the SRE home to this bucket; task-scoped credential paths are excluded by the runtime script.

ECS Exec sessions use a rotating KMS key. The ECS cluster sends session output to a dedicated encrypted CloudWatch log group; container stdout uses its own log group. Bedrock invocation payload logging has separate resources and retention: CloudWatch receives enabled text payload delivery and a dedicated S3 bucket receives large payloads. This logging configuration is account/Region-wide rather than limited to Boundary tasks, so access to those logs and objects has broader sensitivity implications than container logs.

## Lambda deployment and task timeout

The create-investigation Lambda can be packaged as ZIP (the default) or as a container image; both modes receive the same runtime configuration. Image mode requires a repository and an immutable tag. Its AWS-IAM-authorized Function URL is configured separately from the CLI's direct SDK invocation path. A scheduled reaper Lambda is packaged from its single handler file and gets scoped ECS list/describe/stop permissions; EventBridge invokes it at the configured schedule to stop tasks with expired deadline tags.

## Bedrock access and approved models

Fargate tasks use a private Bedrock Runtime interface endpoint with private DNS, task-only HTTPS ingress, and one subnet per availability zone in the configured VPC. The endpoint policy grants inference calls to the task role. Task IAM does not grant Marketplace subscription, so Terraform separately manages model agreements from an explicit model-to-offer map. The default Claude inference profile is checked against a pinned profile-to-foundation-model mapping and the approved agreement set; it is not inferred by stripping a prefix. Terraform tests use a mocked AWS provider to accept an approved profile and reject a bare foundation-model ID or a profile whose foundation model is not approved.

## Evidence-backed claims

- Regional Terraform guards the target account, subnet count, outbound routes, and Bedrock endpoint subnet/VPC/AZ shape. [provider and routing checks](repo://deploy/regional/main.tf#L1-L69) · [subnet input validation](repo://deploy/regional/variables.tf#L165-L178) · [Bedrock endpoint preconditions](repo://deploy/regional/bedrock-endpoint.tf#L30-L71)
- The Fargate task definition mounts persistent EFS home plus empty task-scoped credential overlays, with an optional kube-proxy sidecar whose health gates the main container. [task volumes and container configuration](repo://deploy/regional/ecs.tf#L61-L159) · [sidecar](repo://deploy/regional/ecs.tf#L175-L224)
- EFS is encrypted and its filesystem policy allows the task role to mount via an access point; the baseline access point uses the `sre` UID/GID. [filesystem and mount targets](repo://deploy/regional/efs.tf#L1-L42) · [access point and policy](repo://deploy/regional/efs.tf#L44-L97)
- The audit bucket enables versioning and compliance-mode Object Lock, blocks public access, encrypts with AES-256, and denies non-TLS requests; replication is optional and account-scoped. [audit bucket controls](repo://deploy/regional/s3.tf#L1-L73) · [replication](repo://deploy/regional/s3.tf#L75-L120)
- Create-investigation Lambda ZIP and container-image modes share environment configuration, while image mode requires an image repository and tag; a separate EventBridge schedule invokes the deadline reaper. [Lambda package modes](repo://deploy/regional/lambda-create-investigation.tf#L97-L229) · [reaper schedule](repo://deploy/regional/lambda-reap-tasks.tf#L110-L133)
- Bedrock model agreement offers are explicitly matched by offer ID, and the configured default inference profile must map to an approved foundation model; Terraform tests reject invalid profile/agreement combinations. [model agreements](repo://deploy/regional/bedrock-model-agreements.tf#L1-L33) · [default model validation](repo://deploy/regional/variables.tf#L16-L50) · [Terraform tests](repo://deploy/regional/tests/claude_default_model.tftest.hcl#L68-L124)
- Bedrock Runtime uses a private interface endpoint and invocation payload logging sends text to encrypted CloudWatch storage and larger payloads to a separate S3 bucket. [runtime endpoint](repo://deploy/regional/bedrock-endpoint.tf#L1-L71) · [invocation logging](repo://deploy/regional/bedrock-logging.tf#L1-L121) · [large-payload bucket](repo://deploy/regional/bedrock-large-payloads.tf#L1-L86)
