# Boundary-managed Claude Code skills

Boundary is the sole source of user-global skills in investigation sessions.
The **entire `~/.claude/skills/` directory is managed**: files not in the published
source are deleted. Do not store personal skills there. ECS tasks are ephemeral,
but the EFS home and copied skills can persist across tasks.

## Bash and rsync loop

The entrypoint starts `utils/rosa-boundary-skill-sync.sh` as `sre`, independently
of interactive shells. The published layout is unchanged. Each pass:

1. Uses `find` to discover `<collection>/skills/<skill>` directories under
   `/opt/rosa-content/rosa-claude-plugins`.
2. Copies skills containing `SKILL.md` into task-local staging with rsync, using
   destination names `boundary--<collection>--<skill>`.
3. Only after discovery and every staging copy succeed, runs rsync with
   `--delete --delay-updates` from staging into `~/.claude/skills/`.
4. Removes staging and sleeps, then repeats.

There is no ownership ledger, deletion counter, Python helper, or change to the
publishers. Runtime rsync is installed with `dnf`; Bash, coreutils (`timeout`),
findutils (`find`), and util-linux (`flock`) supply the other commands. Python 3
and pip remain available in the image but are not used for skill syncing.

Missing/unreadable source and failed staging preserve the previous destination.
A readable empty source intentionally clears all skills. Staging is not an
upstream consistency protocol: partially visible S3 Files content can still
cause deletions. Final rsync is not an atomic tree swap; failure can leave a
partially updated destination until the next successful pass.

Directory symlinks in the published tree are not followed, and symlinked
`SKILL.md` files are rejected. Names must start with an ASCII letter or number
and use only letters, numbers, underscores, and hyphens. Ambiguous/oversized
names and plugin-bearing skill directories fail the pass. Rsync preserves
executable scripts and safe relative asset links, but ignores absolute/escaping
links (`--safe-links`); package supporting assets within each skill directory.
This exposes skills only, without installing marketplaces or registering full
plugins. Published instructions/scripts still require upstream review.

## Configuration and shutdown

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `BOUNDARY_SKILLS_ENABLED` | `1` | Start only when exactly `1`; set `0` to disable on the next task start. Existing copies remain. |
| `BOUNDARY_SKILL_RECONCILE_INTERVAL` | `60` | Seconds between completed passes; integer from 5 through 86400. Invalid values exit the helper, not the workload. |

A nonblocking `flock` at `~/.claude/.boundary-skills.lock` serializes passes from
overlapping tasks sharing a home. Those tasks must expose the same source;
locking cannot reconcile different regional snapshots. The helper rejects
symlinked `.claude`/`skills` roots. Settings and other `.claude` files are outside
the mirror and remain untouched. The skeleton creates absent settings with
Bedrock, disabled self-updates, and `"theme": "auto"`; existing settings survive.

Content availability never gates startup. Failures emit `boundary-skills:`
warnings and retry after the interval. Unexpected process exits are not
supervised/restarted; inspect logs and replace the task if necessary.

The process tree is `entrypoint.sh -> runuser (sre) -> bash`, with `timeout` and
rsync children while copying. Copies have a 120-second timeout and two-second
kill grace. Shutdown traps stop active copies and sleep, remove staging, and
allow the entrypoint to reap the helper before normal/signal-driven audit sync.
The existing credential exclusions and `--no-follow-symlinks` are unchanged.
Copied skill files live on EFS and enter normal home audit backups; assess the
added backup size and shutdown time in live acceptance.

## Verification

Check `rsync --version`, `ps -eo user,pid,ppid,stat,args`, and
`ls ~/.claude/skills/`. In Claude, use `/skills` and invoke representative skills
with assets. Test additions, edits, deletions, failures, shared-home locking,
and settings preservation. Directory aliases are namespaced; frontmatter names
can still collide, so verify actual command naming in the deployed client.

Test discovery with the pinned Claude version; do not assume hot reload. Use
`/reload-skills` when supported or restart Claude if stale. An asynchronous first
pass can create the skills directory after Claude starts and require a reload.

Local checks: `bats tests/shell/` (requires rsync and GNU utilities),
`shellcheck entrypoint.sh utils/rosa-boundary-skill-sync.sh`, and
`make test-github-dl` for existing image/build contracts. Local tests do not prove
Linux image builds, both architectures, EFS locking, S3 Files visibility, Claude
discovery, or audit shutdown timing.
