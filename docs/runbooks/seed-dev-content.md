# Manually seed personal-dev published content

A new regional deployment creates the content bucket and S3 Files mounts, not
sample SOPs, notifications or skills. Empty source prefixes can therefore leave
`/opt/rosa-content/rosa-claude-plugins/`, `~/.agents/skills/` and
`~/.claude/skills/` empty even when the mount and reconciler are healthy. Empty
listings alone do not prove health: verify the source objects and mounted paths.

This is a **manual, separately approved personal-dev action**, not an automatic
onboarding upload or a staging/production publishing procedure. Content is shared
with other investigations using this bucket. Treat published skills as trusted
instructions: review every fixture before publishing. Use only harmless synthetic
text, never credentials, customer data, real notifications or executable payloads.

## 1. Confirm storage, identity and approval

After the regional deployment, obtain these non-secret outputs from its owning
state (do not dump state or copy another contributor's bucket):

```bash
terraform -chdir=deploy/regional output -raw content_bucket_name
terraform -chdir=deploy/regional output -raw content_bucket_region
terraform -chdir=deploy/regional output -json content_prefixes
```

Confirm the personal account with `aws sts get-caller-identity --region "$REGION"`
and verify the output bucket/region against the approved deployment. Use the
**content bucket**, never the audit/Object Lock bucket or `_bootstrap/`. For a
replicated topology, publish only in the approved primary/source region and
verify replication separately; do not seed replicas independently.

Agree on the exact object keys, writer identities, visibility to other tasks,
small S3/KMS costs and cleanup before uploading. Use the authorized publisher
identity for each source, or an explicitly approved personal-dev operator. A
publisher for one prefix is not authorized to write the others. Do not grant
writes to the read-only investigation task role to make seeding work.

## 2. Prepare and review a tiny fixture locally

Set `BUCKET`, `REGION`, `SKILLS_PREFIX`, `SOP_PREFIX` and `NOTIFICATIONS_PREFIX`
from the verified outputs. Match keys `rosa-claude-plugins`, `ops-sop` and
`managed-notifications` to their configured prefix values; values end in `/`.
Do not assume the default values or replace existing publisher content. Set
`FIXTURE_ID` to a unique lowercase alphanumeric/hyphen run label, such as a date
plus a random suffix, and check that the chosen destination keys do not exist.

The following only creates local synthetic files; inspect them before uploading:

```bash
umask 077
: "${FIXTURE_ID:?Set a unique reviewed fixture run label}"
COLLECTION="onboarding-${FIXTURE_ID}"
FIXTURE_DIR=$(mktemp -d)
mkdir -p "$FIXTURE_DIR/skill/assets"
printf 'BOUNDARY_CONTENT_SMOKE_V1\n' > "$FIXTURE_DIR/skill/assets/marker.txt"
cat > "$FIXTURE_DIR/skill/SKILL.md" <<'SKILL'
---
name: content-smoke
description: Manually invoked synthetic onboarding check for published content.
---
When explicitly invoked, read assets/marker.txt relative to this skill and report
its marker. Do not run shell commands, make network requests or change files.
SKILL
printf 'Synthetic onboarding SOP fixture; not operational guidance.\n' > "$FIXTURE_DIR/sop.txt"
printf 'Synthetic onboarding content; not a real notification.\n' > "$FIXTURE_DIR/notification.txt"
```

The required skill object layout is:

```text
<skills-prefix>/<collection>/skills/content-smoke/SKILL.md
<skills-prefix>/<collection>/skills/content-smoke/assets/marker.txt
```

The prefix already ends in `/`; do not add a leading slash to object keys. A
`SKILL.md` directly at the prefix root or under `<collection>/SKILL.md` is not
discovered. No plugin catalog/manifest is required by the symlink reconciler.
The SOP/notification text below only tests visibility, not a production format or
notification delivery.

## 3. Manually publish the reviewed objects

In the S3 console, upload each file to its exact reviewed key in the content
bucket. Alternatively, run these commands **only after upload approval**, in the
appropriate authorized publisher/operator session for each source. Preserve
bucket SSE-KMS encryption; do not change bucket policy, ACLs or KMS keys.

```bash
: "${BUCKET:?}" "${REGION:?}" "${SKILLS_PREFIX:?}" "${SOP_PREFIX:?}" "${NOTIFICATIONS_PREFIX:?}"
: "${FIXTURE_DIR:?}" "${FIXTURE_ID:?}" "${COLLECTION:?}"
aws s3 cp "$FIXTURE_DIR/skill/assets/marker.txt" \
  "s3://${BUCKET}/${SKILLS_PREFIX}${COLLECTION}/skills/content-smoke/assets/marker.txt" \
  --region "$REGION" --sse aws:kms
aws s3 cp "$FIXTURE_DIR/skill/SKILL.md" \
  "s3://${BUCKET}/${SKILLS_PREFIX}${COLLECTION}/skills/content-smoke/SKILL.md" \
  --region "$REGION" --sse aws:kms
aws s3 cp "$FIXTURE_DIR/sop.txt" \
  "s3://${BUCKET}/${SOP_PREFIX}_onboarding/${FIXTURE_ID}/sop.txt" \
  --region "$REGION" --sse aws:kms
aws s3 cp "$FIXTURE_DIR/notification.txt" \
  "s3://${BUCKET}/${NOTIFICATIONS_PREFIX}_onboarding/${FIXTURE_ID}/notification.txt" \
  --region "$REGION" --sse aws:kms
```

Publish the asset before `SKILL.md` if other users may discover the skill during
the upload. Never run `sync --delete`, recursively overwrite a source prefix, or
upload your checkout/home directory. Record only the fixture keys/version IDs
and status privately, not unrelated bucket contents.

## 4. Verify each boundary in an approved existing session

Confirm the four exact objects exist in S3. In an already-approved investigation
shell running as `sre`, verify their content under:

- `/opt/rosa-content/rosa-claude-plugins/$COLLECTION/skills/content-smoke/`
- `/opt/rosa-content/ops-sop/_onboarding/$FIXTURE_ID/sop.txt`
- `/opt/rosa-content/managed-notifications/_onboarding/$FIXTURE_ID/notification.txt`

Use the literal run label/collection in that shell; local workstation variables
are not transferred by ECS Exec. The mount paths use **source keys**, even when
the S3 prefix values differ. Allow S3 Files visibility to converge first, then
allow a completed skill reconciliation pass (60 seconds by default). Do not
promise immediate visibility or restart/stop somebody's task as a shortcut.

Verify `boundary--$COLLECTION--content-smoke` is a readable symlink in **both**
`~/.agents/skills/` and `~/.claude/skills/`, and that its `SKILL.md` and relative
asset resolve to the published fixture. If objects exist but the mount is empty,
investigate the bucket/prefix mapping, S3 Files and permissions before blaming
skill discovery. If the mount has the correct layout but links are absent, check
`BOUNDARY_SKILLS_ENABLED`, the helper process and `boundary-skills:` warnings.
Do not manually write into the read-only mounts or replace personal skills.

Finally verify discovery in each intended client. Reload/restart only the client
if needed; readable links do not prove agent discovery or hot reload. Invoking
the fixture with a model requires separate bounded inference approval. Creating
a new investigation also requires separate approval. See
[skill reconciliation and troubleshooting](../configuration/claude-skills.md).

## 5. Clean up only this run's fixtures

After cleanup approval, delete only the four recorded object keys using the
appropriate publisher identity (console or individual `aws s3 rm` commands with
explicit region). Do not recursively delete a published prefix or delete other
versions/content. This is a versioned bucket: ordinary deletion creates delete
markers, not permanent erasure of all versions. Follow the existing lifecycle
and retention policy rather than purging history.

Verify fixture disappearance from the mounts and removal of the two managed
links after visibility/reconciliation converges; unrelated/personal skills must
remain. Remove only the local temporary fixture directory when no longer needed.
Record cleanup status and any replication, mount, agent-discovery or audit gaps.
Do not claim live verification from documentation examples or local tests alone.
