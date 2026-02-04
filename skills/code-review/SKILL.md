# Code Review Skill

Orchestrates a comprehensive code review using zrok agents and subagent delegation.

## Invocation

This skill is invoked when the user asks for a code review using zrok, such as:
- "Run a code review using zrok"
- "Use zrok to review this codebase"
- "Do a security review with zrok agents"

## Prerequisites

- zrok binary must be built and available (either in PATH or specify location)
- Target project directory must be accessible
- (Optional) For semantic search: run `zrok index enable && zrok index build`

## Workflow

This skill orchestrates multiple specialized subagents:

```
1. Setup          → zrok init && zrok onboard --auto
2. Recon Agent    → Maps codebase structure, tech stack
3. Analysis Agents → Run in parallel (security, guards, architecture, content)
4. Validation     → Reviews and confirms findings
5. Export         → Generate markdown/SARIF reports
```

## Phase 1: Project Setup

Initialize zrok in the target project:

```bash
cd <target-project>
zrok init                    # Creates .zrok directory
zrok onboard --auto          # Auto-detects tech stack
zrok lsp status              # Check available LSP servers

# Optional: Enable semantic search (requires Ollama, OpenAI, or Hugging Face)
zrok index enable --provider ollama
zrok index build
```

## Phase 2: Spawn Recon Agent

Use the Task tool to spawn the recon-agent:

```
Task tool:
- subagent_type: "general-purpose"
- description: "recon-agent: map codebase"
- prompt: |
    You are running as the recon-agent for a zrok code review.

    Working Directory: <target-project>
    zrok Binary: <path-to-zrok>

    {output from: zrok agent prompt recon-agent}

    Create these memories:
    - project_overview
    - tech_stack
    - api_endpoints
    - auth_patterns
    - review_targets
```

## Phase 3: Spawn Analysis Agents (Parallel)

Spawn multiple analysis agents in a SINGLE message with multiple Task tool calls:

### Available Agents

| Agent | Focus | When to Use |
|-------|-------|-------------|
| security-agent | Auth, authz, crypto, secrets | Always for security reviews |
| guards-agent | Validation, CSRF, error handling | Always |
| architecture-agent | Code patterns, dead code, tech debt | Always |
| content-agent | XSS, file uploads, logging | Web apps |
| logging-agent | Audit trails, sensitive data | Production apps |
| dependencies-agent | Outdated deps, vulnerabilities | All projects |
| references-agent | External URLs, hardcoded paths | Web apps |

### Subagent Prompt Template

```
You are running as the {agent-name} for a zrok code review.

Working Directory: <target-project>
zrok Binary: <path-to-zrok>

{output from: zrok agent prompt <agent-name>}

Available Commands:
- zrok search "<pattern>" --regex
- zrok semantic "<query>"              # Natural language search
- zrok semantic "<query>" --multi-hop  # Explore related code
- zrok read <file>
- zrok symbols <file>
- zrok symbols --method lsp <file>
- zrok memory read <name>
- zrok finding create --file /tmp/finding.yaml

Finding YAML Format:
title: "Issue Title"
severity: high  # critical, high, medium, low, info
confidence: high
cwe: CWE-XXX
location:
  file: "path/to/file"
  line_start: 47
description: |
  Description...
impact: |
  Impact...
remediation: |
  How to fix...
tags:
  - tag1
created_by: {agent-name}
```

## Phase 4: Spawn Validation Agent

After all analysis agents complete:

```
Task tool:
- subagent_type: "general-purpose"
- description: "validation-agent: verify findings"
- prompt: |
    You are running as the validation-agent.

    {output from: zrok agent prompt validation-agent}

    Review all findings:
    - zrok finding list
    - zrok finding show <id>
    - Verify code at each location
    - Update status: zrok finding update <id> --status confirmed
    - Identify duplicates
```

## Phase 5: Export

Generate final reports:

```bash
zrok finding stats                              # Summary
zrok finding export --format md -o report.md    # Markdown
zrok finding export --format sarif -o report.sarif  # SARIF for CI
```

## Key Principles

1. **Always delegate** - Spawn subagents for each phase, don't analyze directly
2. **Parallel analysis** - Spawn security, guards, architecture agents together
3. **Use LSP** - `zrok symbols --method lsp` for accurate symbol extraction
4. **Use semantic search** - `zrok semantic` for natural language queries like "SQL injection" or "password handling"
5. **Validate findings** - Always run validation-agent before exporting
6. **Share context** - Use `zrok memory write` to share discoveries between agents

## zrok Commands Reference

### Navigation
```bash
zrok list <dir> [--recursive] [--depth N]
zrok find "<pattern>"
zrok read <file> [--lines N:M]
zrok search "<pattern>" [--regex]
zrok symbols <file>
zrok symbols --method lsp <file>
zrok symbols find "<name>"
```

### Semantic Search
```bash
# Index management (one-time setup)
zrok index enable [--provider ollama|openai|huggingface]
zrok index build [--force]
zrok index update
zrok index status

# Natural language code search
zrok semantic "<query>"                    # e.g., "authentication middleware"
zrok semantic "<query>" --multi-hop        # Explore related code across layers
zrok semantic "<query>" --type function    # Filter by chunk type
zrok semantic "<query>" --file "*.go"      # Filter by file pattern
zrok semantic related <file>               # Find code related to a file
```

### Memory
```bash
zrok memory write <name> --type <type> --content "..." --tags "t1,t2"
zrok memory read <name>
zrok memory list
zrok memory search "<query>"
```

### Findings
```bash
zrok finding create --file <yaml>
zrok finding list [--severity high]
zrok finding show <id>
zrok finding update <id> --status <status>
zrok finding export --format <md|sarif|html|csv|json>
zrok finding stats
```

### Agents
```bash
zrok agent list
zrok agent show <name>
zrok agent prompt <name>
```

### Thinking
```bash
zrok think collected
zrok think adherence
zrok think done
zrok think next
zrok think hypothesis "<context>"
```
