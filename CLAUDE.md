# zrok - LLM-Assisted Code Review Tool

zrok is a CLI tool for LLM-assisted security and code quality reviews. It provides agent configurations, memory management, and finding tracking.

## Code Review Orchestration

When asked to perform a code review using zrok, you MUST delegate to specialized subagents. Each agent has a specific focus area and should run as a separate subagent using the Task tool.

### Workflow Overview

```
1. Initialize Project    → zrok init && zrok onboard --auto
2. Spawn Recon Agent    → Task tool with recon-agent prompt
3. Spawn Analysis Agents → Task tool (can run in parallel)
4. Spawn Validation Agent → Task tool to validate findings
5. Export Report         → zrok finding export
```

## Phase 1: Project Setup

Before spawning agents, initialize the project:

```bash
zrok init                    # Initialize .zrok directory
zrok onboard --auto          # Auto-detect tech stack
zrok lsp status              # Check available LSP servers
```

## Phase 2: Reconnaissance (Spawn Subagent)

**IMPORTANT**: Spawn the recon-agent as a subagent using the Task tool.

```
Use the Task tool with:
- subagent_type: "general-purpose"
- description: "recon-agent: map codebase"
- prompt: Get the prompt from `zrok agent prompt recon-agent` and include it
```

The recon-agent will:
- Map project structure using `zrok list`, `zrok find`
- Identify tech stack and frameworks
- Extract symbols using `zrok symbols --method lsp`
- Save discoveries to memory using `zrok memory write`

## Phase 3: Analysis (Spawn Multiple Subagents)

After recon completes, spawn analysis agents. These CAN run in parallel using multiple Task tool calls in a single message.

### Available Analysis Agents

| Agent | Focus Area | When to Use |
|-------|------------|-------------|
| architecture-agent | Code structure, patterns, frameworks | Always |
| security-agent | Auth, authz, crypto, secrets | Always for security reviews |
| guards-agent | Validation, error handling, defensive coding | Always |
| content-agent | Input/output handling, text processing | Web apps, APIs |
| logging-agent | Logging, monitoring, audit trails | Production apps |
| dependencies-agent | Dependency management, versions | All projects |
| references-agent | External URLs, domains, file paths | Web apps |

### Spawning Analysis Agents

For each relevant agent:

```
Use the Task tool with:
- subagent_type: "general-purpose"
- description: "<agent-name>: <brief focus>"
- prompt: Include the full prompt from `zrok agent prompt <agent-name>`
```

**Example**: For a security-focused review, spawn these in parallel:
- security-agent (auth, authz, crypto)
- guards-agent (validation, defensive coding)
- architecture-agent (code patterns)

Each analysis agent will:
- Use `zrok search`, `zrok read`, `zrok symbols` to analyze code
- Create findings using `zrok finding create --file <yaml>`
- Save patterns to memory using `zrok memory write`

## Phase 4: Validation (Spawn Subagent)

After all analysis agents complete, spawn the validation-agent:

```
Use the Task tool with:
- subagent_type: "general-purpose"
- description: "validation-agent: verify findings"
- prompt: Get the prompt from `zrok agent prompt validation-agent`
```

The validation-agent will:
- Review all findings using `zrok finding list` and `zrok finding show`
- Verify evidence and update confidence levels
- Update finding status using `zrok finding update`

## Phase 5: Export

After validation, export the final report:

```bash
zrok finding stats                              # Show summary
zrok finding export --format md -o report.md    # Markdown report
zrok finding export --format sarif -o report.sarif  # SARIF for CI/CD
```

## Subagent Prompt Template

When spawning a subagent, use this structure:

```
You are running as the {agent-name} for a zrok code review.

## Agent Instructions
{paste output from: zrok agent prompt <agent-name>}

## Your Task
1. Use the zrok CLI tools to analyze the codebase
2. Create findings for any issues discovered
3. Save important context to memory
4. Use `zrok think` tools to verify your work

## Finding Creation
When you find an issue, create a YAML file and run:
zrok finding create --file /tmp/finding.yaml

Finding YAML format:
title: "Issue Title"
severity: high  # critical, high, medium, low, info
confidence: high  # high, medium, low
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
  - tag2
created_by: {agent-name}
```

## Available zrok Tools

### File Operations
- `zrok list <dir> [--recursive] [--depth N]` - List directory contents
- `zrok find <pattern>` - Find files by glob pattern
- `zrok read <file> [--lines N:M]` - Read file contents
- `zrok search <pattern> [--regex]` - Search file contents

### Code Analysis
- `zrok symbols <file>` - Extract symbols (functions, classes)
- `zrok symbols --method lsp <file>` - LSP-powered symbol extraction (preferred)
- `zrok symbols find <name>` - Find symbols globally

### Memory Management
- `zrok memory write <name> --type <type> --content "..."` - Store memory
- `zrok memory read <name>` - Retrieve memory
- `zrok memory list` - List memories
- Types: `context`, `pattern`, `stack`

### Findings Management
- `zrok finding create --file <yaml>` - Create finding from YAML
- `zrok finding list` - List all findings
- `zrok finding show <id>` - Show finding details
- `zrok finding update <id> --status <status>` - Update status
- `zrok finding export --format <fmt>` - Export (md, sarif, html)

### Thinking Tools
- `zrok think collected` - Verify collected information
- `zrok think adherence` - Check adherence to context
- `zrok think done` - Check if task complete
- `zrok think next` - Plan next step

## Example: Full Code Review

When user asks: "Run a security code review of this project"

1. **Setup**:
   ```bash
   zrok init && zrok onboard --auto
   ```

2. **Spawn recon-agent** (Task tool):
   - Get prompt: `zrok agent prompt recon-agent`
   - Spawn subagent with that prompt

3. **Spawn analysis agents in parallel** (multiple Task tools in one message):
   - security-agent
   - guards-agent
   - architecture-agent
   - content-agent (if web app)

4. **Spawn validation-agent** (Task tool):
   - Reviews and prioritizes findings

5. **Export**:
   ```bash
   zrok finding export --format md -o security-review.md
   ```

## Key Principles

1. **Always delegate to subagents** - Don't do the analysis yourself, spawn specialized agents
2. **Use LSP when available** - `zrok symbols --method lsp` is more accurate
3. **Create specific findings** - Include file, line number, CWE, remediation
4. **Save context to memory** - Helps agents share information
5. **Validate findings** - Always run validation-agent before exporting
