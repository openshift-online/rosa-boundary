# Boundary-managed Claude Code skills

Boundary manages only its namespaced symlinks in `~/.claude/skills/`.
Personal skills, regular files/directories, and unrelated links are preserved.
ECS tasks are ephemeral, but the EFS home and skill links can persist across tasks.

## Bash symlink loop

The entrypoint starts `utils/rosa-boundary-skill-sync.sh` as `sre`, independently
of interactive shells. The published collection layout is unchanged. Each pass:

1. Uses `find` to discover `<collection>/skills/<skill>` directories under
   `/opt/rosa-content/rosa-claude-plugins`.
2. Validates each skill containing `SKILL.md` and stages an absolute symlink:
   `boundary--<collection>--<skill> -> /opt/rosa-content/rosa-claude-plugins/<collection>/skills/<skill>`.
3. Only after discovery and every link creation succeed, checks destination
   collisions and runs `rsync --recursive --links` for absent entries or existing
   Boundary-managed links. Conflicting files, directories, and unrelated links
   are preserved with a warning.
4. Removes stale Boundary-managed links, never unrelated entries.
5. Removes staging and sleeps, then repeats.

A link is considered Boundary-managed only if its name starts with `boundary--`
and its absolute target, both as written and after normalization, is inside the
content root. This convention also recognizes dangling links for deleted skills;
there is no ownership database. A manually created link matching this convention
is also treated as managed. Keep personal entries outside this namespace/target
combination. Checks and the lock serialize cooperating helpers, not arbitrary
concurrent edits by a user process.

Rsync copies the links themselves, never skill contents. Do not add `--delete`
(which could delete personal skills). Do not add
`--copy-links` (would copy contents) or `--safe-links` (would discard the intended
absolute targets outside the destination). There is no ownership ledger,
deletion counter, Python helper, or publisher change. Runtime rsync and findutils
are installed with `dnf`; Bash, coreutils (`realpath`, `timeout`), and util-linux
(`flock`) provide the other commands. Python 3 and pip remain in the image but
are not used for skill linking.

A missing/unreadable source, failed validation, or failed staging leaves existing
entries unchanged. Failed rsync skips stale-link cleanup. This does not keep their contents available during a mount
outage: skill links depend directly on S3 Files. A readable empty source
intentionally removes only stale Boundary-managed links. Staging is not an upstream consistency
protocol: partially visible S3 Files content can still cause deletions. Final
rsync is not an atomic tree swap; failure can leave a partial link update until
retry. Legacy copied directories are treated as conflicts and left unchanged;
remove or relocate them explicitly if a managed link should replace them.

Directory symlinks in the published tree are not followed, and symlinked
`SKILL.md` files are rejected. Link targets are canonicalized and must stay
inside the content root. Names must start with an ASCII letter or number and
use only letters, numbers, underscores, and hyphens. Ambiguous/oversized names
and plugin-bearing skill directories fail the pass. Whole-directory links
preserve relative scripts/assets without copying. Nested contents are not
sanitized or rewritten: published instructions, scripts, asset links, and future
changes remain trusted content requiring upstream review. Validation during a
scan is not a permanent guarantee about a mutable target.

## Configuration and shutdown

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `BOUNDARY_SKILLS_ENABLED` | `1` | Start only when exactly `1`; set `0` to disable on the next task start. Existing links remain. |
| `BOUNDARY_SKILL_RECONCILE_INTERVAL` | `60` | Seconds between completed passes; integer from 5 through 86400. Invalid values exit the helper, not the workload. |

A nonblocking `flock` at `~/.claude/.boundary-skills.lock` serializes passes from
overlapping tasks sharing a home. Those tasks must expose the same source;
locking cannot reconcile different regional snapshots. The helper rejects
symlinked `.claude`/`skills` roots. Settings and other `.claude` files remain
untouched. Skeleton settings include Bedrock, disabled self-updates, and
`"theme": "auto"`; the no-clobber copy preserves existing settings.

Content availability never gates startup. Failures emit `boundary-skills:`
warnings and retry after the interval. Unexpected process exits are not
supervised/restarted; inspect logs and replace the task if necessary.

The process tree is `entrypoint.sh -> runuser (sre) -> bash`, with `timeout` and
rsync children while mirroring links. Rsync has a 120-second timeout and
two-second kill grace. Shutdown traps stop active rsync and sleep, remove
staging, and let the entrypoint reap the helper before normal/signal-driven
audit sync. Existing credential exclusions and `--no-follow-symlinks` are
unchanged: skill targets are not followed into home audit backups. No skill
content is duplicated onto EFS, and no new AWS permissions are introduced.

## Verification

Check `rsync --version`, `ps -eo user,pid,ppid,stat,args`, and
`ls -l ~/.claude/skills/`. In Claude, use `/skills` and invoke representative
skills with assets. Test additions, edits, deletions, failures, shared-home
locking, and settings preservation. Directory aliases are namespaced;
frontmatter names can still collide, so verify actual command naming.

Test discovery with the deployed Claude version. Changes behind S3 Files-backed
symlink targets and link additions/removals may have different notification
behavior. Use `/reload-skills` when supported or restart Claude if stale. The
asynchronous first pass can create the skills directory after Claude starts and
require a reload. Working links alone do not prove hot discovery.

Local checks: `bats tests/shell/` (requires rsync and GNU utilities),
`shellcheck entrypoint.sh utils/rosa-boundary-skill-sync.sh`, and
`make test-github-dl` for existing image/build contracts. Local tests do not prove
Linux image builds, both architectures, EFS locking, S3 Files visibility, Claude
discovery, or audit shutdown timing.
