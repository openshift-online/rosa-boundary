# Agent & Skill Definition Security Reference

Security checks specific to Claude Code agent definitions, skill files, MCP server configurations, and plugin manifests.

## SKILL.md Security Checks

### Tool Access

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unrestricted Bash | `allowed-tools` includes `Bash` without command scoping | HIGH | Scope Bash commands: `Bash(git diff *)`, `Bash(npm test *)`. Never allow unrestricted `Bash` |
| Write access when unnecessary | `allowed-tools` includes `Write` or `Edit` for read-only analysis skills | MEDIUM | Remove `Write`/`Edit` from read-only skills. Use `[Read, Grep, Glob]` for analysis skills |
| Agent tool access | `allowed-tools` includes `Agent` — can spawn unrestricted sub-agents | HIGH | Remove `Agent` unless sub-agent spawning is core to the skill's purpose. Document why if kept |
| All tools granted | `allowed-tools` not specified (defaults to all tools) | HIGH | Always specify `allowed-tools` explicitly with minimum required tools |
| WebSearch for non-research skills | `allowed-tools` includes `WebSearch` for skills that shouldn't need internet | LOW | Remove `WebSearch` unless the skill needs to look up external information (threat intel, package info) |

**Recommended patterns:**
```yaml
# Read-only analysis skill
allowed-tools: [Read, Grep, Glob]

# Skill needing controlled git access
allowed-tools: [Read, Grep, Glob, Bash(git diff *), Bash(git log *)]

# Skill needing controlled npm/build access
allowed-tools: [Read, Grep, Glob, Bash(npm test *), Bash(npm run lint *)]
```

### Instruction Injection Risks

| Check | Description | Severity | Remediation |
|-------|-------------|----------|-------------|
| User input in tool calls | Skill instructions that pass user input directly into Bash commands without validation | HIGH | Add validation instructions: "First validate input matches expected format (alphanumeric, hyphens only). Reject inputs containing shell metacharacters" |
| Dynamic file path construction | Building file paths from user-provided values without sanitization | MEDIUM | Add path validation: "Resolve the path and verify it is within the project directory. Reject paths containing `..`" |
| Unvalidated URL fetches | Using WebFetch with URLs derived from user input or file content | HIGH | Add URL validation: "Verify URL starts with `https://` and the domain is in the allowed list" |
| Template injection | Skill constructs prompts/commands from external data without escaping | MEDIUM | Validate all external data before interpolation. Use allowlists for expected values |

**Vulnerable pattern and fix:**
```markdown
# VULNERABLE — user could inject shell commands
Run: `oc login --cluster=$CLUSTER_NAME`

# FIXED — add validation step
First validate the cluster name matches ^[a-zA-Z0-9-]+$.
Reject if it contains spaces, quotes, semicolons, or shell metacharacters.
Then run: `oc login --cluster=$VALIDATED_NAME`
```

### Privilege Boundaries

| Check | Description | Severity | Remediation |
|-------|-------------|----------|-------------|
| Elevation commands | Skills that execute `sudo`, `ocm-backplane elevate`, or similar without requiring user confirmation | CRITICAL | Add explicit confirmation gate: "STOP and ask the user for confirmation before running any elevation command" |
| Destructive operations | Skills that delete resources, force-push, or reset without safeguards | HIGH | Add safeguard instructions: "Before any destructive operation (delete, force-push, reset), list what will be affected and ask the user to confirm" |
| Missing confirmation gates | Dangerous operations without explicit "STOP and ask user" instructions | HIGH | Add confirmation gates before any operation that modifies external state or cannot be undone |
| Scope creep | Skill instructions that go beyond its stated purpose (e.g., a "read-only diagnostic" skill that also applies fixes) | MEDIUM | Align skill instructions with its `description`. If a skill says "analyze", it should not also "fix" unless explicitly stated |

## Agent Definition Security

### Agent Configuration

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Overly broad tool list | `tools:` including write/execute tools not needed for the agent's purpose | HIGH | List only tools the agent genuinely needs. A research agent doesn't need Write/Edit |
| Missing model constraints | No `model:` field — may default to most expensive/powerful model unnecessarily | LOW | Set `model:` to the appropriate level. Use `haiku` for simple tasks, `sonnet` for moderate, `opus` for complex |
| Excessive sub-agent spawning | Agent instructions encouraging spawning many sub-agents without limits | MEDIUM | Add limits: "Spawn at most 3 sub-agents. Prefer sequential work unless tasks are genuinely independent" |
| Missing safety guardrails | Agent instructions without explicit "do NOT" constraints | MEDIUM | Add explicit constraints: "Do NOT modify files. Do NOT execute destructive commands. Do NOT push to remote repositories" |

### Agent Orchestration Risks

| Check | Description | Severity | Remediation |
|-------|-------------|----------|-------------|
| Unbounded loops | Agent instructions that could create infinite loops of tool calls | HIGH | Add loop guards: "If a task fails 3 times, stop and report the error. Never retry indefinitely" |
| Recursive agent spawning | Agent that spawns sub-agents which spawn more sub-agents | MEDIUM | Add depth limit: "Do not spawn sub-agents from within a sub-agent" |
| Data exfiltration paths | Agent with both Read and WebFetch/WebSearch — could read local files and send data externally | HIGH | If the agent needs both, add constraint: "Do NOT include file contents in WebFetch URLs or WebSearch queries" |
| Cross-trust-boundary operations | Agent that reads from untrusted sources and writes to trusted locations | HIGH | Add trust boundary: "Validate all data from external sources before writing to local files. Never execute code from external sources" |

## MCP Server Security

### .mcp.json Configuration

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Untrusted MCP endpoints | `url` pointing to non-organizational domains | HIGH | Only connect to MCP servers from trusted, verified sources. Review the server's tool list before enabling |
| HTTP endpoints | `url` using `http://` instead of `https://` | HIGH | Always use `https://` for MCP endpoints. Request the provider upgrade to HTTPS |
| Hardcoded credentials | API keys or tokens in `.mcp.json` | CRITICAL | Use environment variable references: `"env": {"API_KEY": "from_env"}`. Add `.mcp.json` to `.gitignore` if it contains secrets |
| Overly broad tool grants | MCP server providing tools that exceed the plugin's purpose | MEDIUM | Review and restrict MCP tool access. Disable tools you don't need |
| Missing authentication | MCP endpoint without authentication mechanism | HIGH | Ensure MCP server requires authentication. Use API keys or OAuth tokens |

**Check patterns:**
```bash
grep -E '"url"\s*:\s*"http://' .mcp.json
grep -E '(token|key|password|secret)' .mcp.json
```

**Remediation — Secure .mcp.json:**
```json
{
  "servers": {
    "myserver": {
      "url": "https://mcp.internal.company.com",
      "auth": {
        "type": "bearer",
        "token_env": "MCP_API_TOKEN"
      }
    }
  }
}
```

### MCP Tool Verification

| Check | Description | Severity | Remediation |
|-------|-------------|----------|-------------|
| Tool name collisions | MCP tools that shadow built-in Claude tools | HIGH | Rename MCP tools to avoid collisions. Use namespaced names: `myserver_read` not `read` |
| Excessive permissions | MCP tools that can write/delete when only read is needed | MEDIUM | Configure tool-level permissions in MCP server. Disable write operations if only read is needed |
| Missing tool descriptions | Tools without clear descriptions of what they do and what data they access | LOW | Add descriptions to all MCP tools. Users need to understand what data flows where |
| Data flow concerns | MCP tools that send local data to external services | MEDIUM | Document data flow. Ensure sensitive data is not sent to external services without user consent |

## Plugin Manifest Security

### plugin.json Checks

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Version format | Non-semver version strings that could confuse update checks | LOW | Use semantic versioning: `"version": "1.2.3"` |
| Author impersonation | Author name impersonating official teams without being one | MEDIUM | Use your actual team/org name. Don't claim to be from a team you're not part of |
| Description mismatch | Plugin description claiming capabilities not present in skills/agents | LOW | Align description with actual capabilities. Don't claim features the plugin doesn't provide |

### Marketplace Registration

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| External source trust | Marketplace entries with `source.type: "github"` pointing to unverified repos | HIGH | Verify the source repository is from a trusted organization. Check commit history and contributors |
| Missing OWNERS | Plugin without OWNERS file — no clear accountability | MEDIUM | Add an OWNERS file listing responsible maintainers and review requirements |
| Inconsistent naming | Marketplace `name` doesn't match `plugin.json` `name` | MEDIUM | Synchronize names across marketplace entry and plugin.json |

## Reference Document Trust

### Content Safety

| Check | Description | Severity | Remediation |
|-------|-------------|----------|-------------|
| Executable instructions in references | Reference docs containing commands that Claude might execute verbatim | MEDIUM | Mark commands as examples only. Add "verify before executing" instructions in SKILL.md |
| External URLs in references | References linking to external resources that could change | LOW | Use versioned links (e.g., GitHub permalink with commit hash) or copy critical content inline |
| Conflicting instructions | Reference docs that contradict SKILL.md safety constraints | HIGH | Remove conflicting instructions. SKILL.md safety constraints should always take precedence |
| Hidden instructions | Reference docs containing prompt injection attempts disguised as documentation | CRITICAL | Review all reference documents for hidden instructions. Remove any content that attempts to override SKILL.md behavior |

### Review Guidance

When reviewing reference documents:
1. Verify all bash commands are read-only unless the skill explicitly requires write access
2. Check that no reference document overrides safety constraints from SKILL.md
3. Ensure URLs point to known, trusted domains
4. Look for instructions that could cause the agent to behave unexpectedly
5. Check for invisible Unicode characters or homoglyphs that could disguise malicious instructions
