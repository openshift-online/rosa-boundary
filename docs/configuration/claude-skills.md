# Boundary-managed Claude Code skills

Boundary keeps both `~/.claude/skills/` and the shared agent discovery directory
`~/.agents/skills/` up to date with the published skills under
`/opt/rosa-content/rosa-claude-plugins`. Personal skills, regular files/directories,
and unrelated links are preserved. ECS tasks are ephemeral, but the EFS home and
skill links can persist across tasks.

## Symlink reconciliation

The entrypoint starts `utils/rosa-boundary-skill-sync.sh` as `sre`, independently
of interactive shells. Each pass:

1. Finds `<collection>/skills/<skill>` directories containing `SKILL.md` using
   Bash globs, without following collection, skills-directory, skill-directory,
   or `SKILL.md` symlinks.
2. Creates or refreshes absolute links named `boundary--<collection>--<skill>`
   in both `~/.claude/skills/` and `~/.agents/skills/`. Conflicting files, directories, and unrelated links
   are preserved with a warning.
3. Removes Boundary-managed links that no longer correspond to a published skill.
4. Sleeps, then repeats.

Content edits are visible immediately through the links; only additions and
removals need reconciliation. No content is copied, and no staging directory or
rsync process is needed. Whole-directory links preserve executable scripts and
relative assets. Published instructions, scripts, and nested asset links remain
trusted content requiring upstream review; the helper is not a content validator.
Collection and skill names should be unambiguous when joined with `--`.

A link is considered Boundary-managed only if its name starts with `boundary--`
and its absolute target, both as written and after normalization, is inside the
content root. This also recognizes dangling links for deleted skills. Manually
created links matching this convention are managed too; keep personal entries
outside this namespace/target combination.

A missing or inaccessible source root leaves existing links unchanged. A failed
link update skips stale-link cleanup, but earlier updates in that pass remain.
An empty source removes stale managed links. Directory listing and link updates
are not an atomic snapshot: partially visible or unreadable published collections
can cause removals until a later pass restores them. Links depend on S3 Files;
they do not preserve content availability during a mount outage. Legacy copied
directories remain conflicts; relocate them explicitly to allow managed links.

## Configuration and shutdown

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `BOUNDARY_SKILLS_ENABLED` | `1` | Start only when exactly `1`; set `0` to disable on the next task start. Existing links remain. |
| `BOUNDARY_SKILL_RECONCILE_INTERVAL` | `60` | Seconds between completed passes; integer from 5 through 86400. Invalid values exit the helper, not the workload. |

A nonblocking `flock` at `~/.boundary-skills.lock` serializes passes from
overlapping tasks sharing a home. Those tasks must expose the same source;
locking cannot reconcile different regional snapshots or arbitrary concurrent
user edits. Both destinations are reconciled under that same lock. Each pass
rejects symlinked `.claude`, `.agents`, or their `skills` directories; a failed
destination does not stop reconciliation of the other or later retries. The lock
lives outside both discovery roots, so an unsafe or uncreatable `.claude` cannot
redirect lock acquisition or block a healthy `.agents/skills`. Symlinked lock
files are rejected; failed lock opens are retried on subsequent passes. Settings
and other files outside the two skills directories remain untouched.

The lock location changed from `~/.claude/.boundary-skills.lock`; replace older
helper processes before running the new version against the same shared home,
since different lock paths do not serialize each other.

Content availability never gates startup. Failed passes emit `boundary-skills:`
warnings and retry after the interval. Unexpected process exits are not
supervised/restarted; inspect logs and replace the task if necessary.

The process tree is `entrypoint.sh -> runuser (sre) -> bash`. Shutdown interrupts
the background sleep and exits the helper. Filesystem operations no longer have
an explicit timeout. The entrypoint reaps the helper before audit sync. Existing
credential exclusions and `--no-follow-symlinks` are unchanged: skill targets are
not followed into home audit backups. No skill content is duplicated onto EFS,
and no new AWS permissions are introduced.

## Verification

Check `ps -eo user,pid,ppid,stat,args` and
`ls -l ~/.claude/skills/ ~/.agents/skills/`. In Claude,
use `/skills` and invoke representative skills with assets. Test additions,
edits, deletions, shared-home locking, and settings preservation. Directory
aliases are namespaced; frontmatter names can still collide, so verify actual
command naming.

Test discovery with the deployed Claude version. Changes behind S3 Files-backed
symlink targets and link additions/removals may have different notification
behavior. Use `/reload-skills` when supported or restart Claude if stale. The
asynchronous first pass can create the skills directory after Claude starts and
require a reload. Working links alone do not prove hot discovery.

Other agents can consume `~/.agents/skills/` when they support that discovery
location. Linking does not configure a client's search paths or prove discovery
or hot reload: verify those behaviors separately for each pinned client.

Local checks: `bats tests/shell/` (requires GNU utilities),
`shellcheck entrypoint.sh utils/rosa-boundary-skill-sync.sh`, and
`make test-github-dl` for existing image/build contracts. Local tests do not prove
Linux image builds, both architectures, EFS locking, S3 Files visibility, Claude
discovery, or audit shutdown timing.
