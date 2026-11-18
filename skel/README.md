# SRE home skeleton

`Containerfile` copies `sre/` to `/etc/skel-sre/`. On startup, `entrypoint.sh`
copies it into the EFS-backed `/home/sre` with `cp -rn`, preserving existing files.

## Shared agent instructions

Edit `sre/AGENTS.md` as the single source of investigation guidance. It becomes
`/home/sre/AGENTS.md` at runtime. Discovery uses the tools' default locations:

| Tool | Runtime instruction path | Discovery |
|------|--------------------------|-----------|
| pi | `/home/sre/AGENTS.md` | Ancestor of workspaces under the SRE home |
| OpenCode | `/home/sre/.config/opencode/AGENTS.md` | Global symlink to `../../AGENTS.md` |
| Codex | `/home/sre/.codex/AGENTS.md` | Global symlink to `../AGENTS.md` |
| Claude Code | `/home/sre/.claude/CLAUDE.md` | User-level compatibility symlink to `../AGENTS.md` |

Global links keep the container guidance available inside cloned repositories,
even when project instruction discovery stops at the repository root. pi walks
ancestors beyond the repository root; launch it under `/home/sre` to inherit the
guidance. Custom config/home directories or disabled instruction loading can
bypass these defaults. This layout does not install additional agents.

Existing investigations retain their files: startup adds missing paths but does
not replace an existing `.claude/CLAUDE.md` or other customized instructions.
To adopt the shared file in an existing home, review/back up those instructions
and replace the old file with the corresponding relative symlink. No automatic
overwrite of persistent workspace files is performed.
