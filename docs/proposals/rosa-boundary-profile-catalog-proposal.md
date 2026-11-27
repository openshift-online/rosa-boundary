# Proposal: Sync Boundary Profiles from an Internal Catalog

## PROBLEM

SREs currently configure each Boundary deployment through an interactive discovery flow. Updating deployment settings requires repeating that process or manually editing profiles.

Configuration discovery is coupled to the create-investigation Lambda. Although discovery is **IAM-authenticated, not anonymous**, it exposes deployment metadata through a runtime action that is unnecessary if configuration can be distributed separately. Static profile distribution lets us remove the discovery action, while retaining the Lambda for investigation creation. We should also retire that same Lambda’s IAM-protected Function URL after confirming no consumers require it; the CLI already invokes Lambda directly through the AWS SDK.

Additionally, the Boundary repository is public, but not all deployment information should be. Moving profiles to an internal catalog will not address deployment values already committed in Terraform definitions; those require a separate review.

## WHAT

Provide a centrally maintained, internally accessible YAML catalog of supported Boundary deployment profiles:

```sh
rosa-boundary config sync-profiles --url https://<internal-host>/rosa-boundary-profiles.yaml
```

Example output:

```text
Gathering profiles...
Found 8 new profiles and 1 modification to an existing profile.
Saving to ~/.config/rosa-boundary/config.yaml
```

Sync profiles into the existing configuration without replacing personal development profiles, the active-profile selection, or other supported client settings.

Publish the strict schema and sanitized examples in the public Boundary repository. Store actual deployment catalogs in an access-controlled location.

## WHY

- **Simpler onboarding:** SREs gather all supported profiles with one command.
- **Repeatable updates:** The same command refreshes deployment settings when they change.
- **Smaller runtime surface:** Configuration distribution no longer depends on the investigation Lambda.
- **Controlled disclosure:** Deployment identifiers are not credentials, but they do not need to be publicly published.
- **Developer flexibility:** Personal profiles remain independent of centrally managed profiles.

## HOW

1. **Define a versioned, strict schema.** Validate profile names, required settings, account/role consistency, and approved URL formats. Reject unknown fields, duplicate profiles, and credential material.

2. **Host the catalog internally; hosting choice is undecided.** Use an access-controlled internal location, preferably an existing publishing service rather than a new application. Evaluate the alternatives below before selecting a host.

3. **Maintain the catalog centrally.** Gather settings once per deployment, preferably from deployment outputs. Review catalog changes through PRs and refresh it when deployments change—not during each SRE’s onboarding.

4. **Merge safely.**
   - Track which catalog manages each imported profile.
   - Automatically update previously imported profiles that have no local modifications.
   - Require explicit approval for local modifications or unmanaged name collisions.
   - Preserve the active profile and do not silently delete profiles absent from the catalog.
   - Provide `--dry-run`, change counts, and atomic saves. Download or validation failures leave configuration untouched.

5. **Protect catalog integrity and access.** Require HTTPS, controlled publishing permissions, and appropriate read access. Highlight issuer/account changes and never embed authentication tokens in catalog URLs.

6. **Transition existing clients.** Make profile sync the normal SRE setup path while retaining manual profile creation for developers. Retire `get_config` after supported clients migrate. Separately verify Function URL consumers before removing that ingress.

7. **Address public deployment configuration separately.** Move information unsuitable for publication into private, review-controlled configuration. Removing values from the current branch does not remove historical copies.

Existing named-profile support and atomic configuration writes provide a foundation for this change.

## ALTERNATIVES

| Option | Assessment |
|---|---|
| **Existing internal SRE static host** | Preferred if one offers controlled access, stable URLs, and CLI-friendly downloads. No general-purpose service was confirmed in the targeted search. |
| **Existing internal documentation hosting** | Potentially reuses an established publishing service. Confirm support for unchanged YAML, stable download URLs, timely updates, and CLI-compatible authentication. |
| **Private operational repository** | Low-infrastructure option with existing access controls and PR review. Use authenticated fetching rather than copied temporary raw-file URLs. Handle rate limits; occasional explicit syncs should generate modest traffic. |
| **Shared engineering cluster** | Reasonable fallback, but adds service ownership and availability work. Hosting there requires explicit access controls; a Route alone does not make content private. |
| **Private managed object storage** | Avoids operating an application, but requires suitable workstation authentication. Do not introduce shared credentials solely to download profiles. |
| **Keep runtime discovery** | Avoids maintaining a catalog, but retains per-deployment setup and couples configuration retrieval to investigation infrastructure. |

## RECOMMENDATION

Adopt the static catalog and safe-merge model, with the catalog hosted internally. The hosting choice remains undecided. First investigate existing internal publishing; if no suitable download service exists, evaluate a private operational repository with authenticated fetching before deploying another application.

Treat removal of the Function URL and cleanup of publicly committed deployment information as separate, explicit follow-up work.
