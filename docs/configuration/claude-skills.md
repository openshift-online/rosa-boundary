# Boundary-managed Claude Code skills

The Boundary entrypoint starts an unprivileged Python 3 helper to expose the
read-only published skills as user-global Claude Code skills. Python 3 and pip
are already installed by the runtime image's `dnf` recipe; the helper uses only
Python's standard library. Invoke Python as `python3`.

## Discovery and ownership

Every pass discovers `/opt/rosa-content/rosa-claude-plugins/*/skills/*/SKILL.md`,
without a fixed collection list. Each skill directory is linked as:

```text
~/.claude/skills/boundary--<collection>--<skill>
  -> /opt/rosa-content/rosa-claude-plugins/<collection>/skills/<skill>
```

The whole directory is linked so relative assets/scripts within it remain
available. Collection and skill directory names must start with an ASCII letter
or number and contain only ASCII letters, numbers, underscores, or hyphens.
Ambiguous generated names and oversized names are skipped with warnings. Links
and skill definitions resolving outside the mounted plugin content root are
rejected. Skill directories containing `.claude-plugin` are skipped to avoid
implicitly registering plugin hooks, agents, or MCP configuration. The helper
does not execute skill contents or install marketplaces. Published skill
instructions remain trusted operational content requiring upstream review.

Existing user files, directories, and unrelated symlinks are never overwritten.
Only unchanged symlinks recorded in `~/.claude/.boundary-skills/state.json` are
eligible for removal. Do not edit that bookkeeping. A nonblocking file lock in
the same directory serializes passes from overlapping tasks sharing an EFS home;
each task retains its own helper. Tasks sharing a home should expose the same
content source. Differing regional views can still produce link churn despite
serialization; locking does not make regional content snapshots consistent.

Skill additions appear on the next successful pass. An absent skill must be
missing in two successful passes before its managed link is removed. An
unreadable or absent source root does not advance deletion counters. A readable
but temporarily empty or partial mount is not distinguishable from deletions;
the two-pass grace reduces churn but cannot establish source completeness.
Updates to existing targets need no recopying. Source visibility still depends
on S3 Files; a scan is not proof of upstream S3 replication completion.

## Configuration and lifecycle

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `BOUNDARY_SKILLS_ENABLED` | `1` | Start the helper only when exactly `1`; set to `0` to disable on the next task start. Existing links are preserved. |
| `BOUNDARY_SKILL_RECONCILE_INTERVAL` | `60` | Seconds between completed passes; integer from 5 through 86400. Invalid configuration logs an error and exits the helper without failing the workload. |

The first pass starts asynchronously after skeleton configuration is copied.
Neither content availability nor helper success gates SRE startup. Scan failures
log a warning and retry after the configured interval; the helper is not an ECS
health dependency. Logs use the `boundary-skills:` prefix on container stderr.
There is no external service or new AWS permission. An unexpected process exit
is not automatically restarted; inspect logs and replace the task if necessary.

The process tree includes `entrypoint.sh -> runuser (sre) -> python3`. The
entrypoint terminates/reaps the helper before normal or signal-driven audit sync
and also stops it via an EXIT trap on workload/setup failures. Existing audit
sync logic and its `--no-follow-symlinks` protection remain unchanged. Linked
content is not copied into the EFS home or followed into audit escrow.

The skeleton `~/.claude/settings.json` includes Bedrock, disabled self-updates,
and `"theme": "auto"`. Existing settings are preserved by the entrypoint's
no-clobber skeleton copy; absent settings are created. No settings entry is
required for these user-global skills.

## Checking behavior in a deployed task

```bash
python3 --version
ps -eo user,pid,ppid,stat,args
ls -l ~/.claude/skills/
claude --version
```

Use `/skills` in Claude to check actual discovery and invoke a representative
skill whose supporting assets are needed. Namespaced directory aliases avoid
filesystem collisions; frontmatter `name` values can still overlap, so check
actual command naming in the deployed client. Verify user-created skills and
settings survive, then test collection/skill additions, edits, deletions, and
source outages. Allow two successful passes for removals.

Claude documents support for symlinked user-global skills and live skill
changes, but notification behavior behind S3 Files-backed targets requires
live verification with the pinned client. If skills are absent or stale, use
`/reload-skills` when supported or restart Claude. The asynchronous first pass
can create the skills directory after Claude starts; that can require an
explicit reload. Do not claim automatic hot discovery based on link tests alone.

Local coverage: `make test-github-dl`, `bats tests/shell/`, and
`shellcheck entrypoint.sh`. These verify projection, failure/ownership cases,
and entrypoint lifecycle without AWS; they do not prove live S3 Files, EFS lock
behavior, Claude discovery, or both container architectures.
