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

### Optional: Semantic Search

Semantic search enables natural language queries against the codebase. It requires an embedding provider:

```bash
# Check if semantic search is available
zrok index status

# If not enabled, set up with one of:
zrok index enable --provider ollama      # Local, free (requires Ollama)
zrok index enable --provider openai      # Cloud, paid (requires OPENAI_API_KEY)
zrok index enable --provider huggingface # Cloud, free tier (requires HF_API_KEY)

# Build the index (one-time, can take a while for large codebases)
zrok index build
```

## Workflow Overview

```
1. Setup          → zrok init && zrok onboard --auto
2. Recon Agent    → Maps codebase structure, tech stack
3. Analysis Agents → Run in parallel (security, guards, architecture, content)
4. Validation     → Reviews all findings (dedup, priority, triage)
5. Review Agents  → Deep validation per finding (one agent per finding, parallel)
6. Export         → Generate markdown/SARIF reports
```

---

## Phase 1: Project Setup

Initialize zrok in the target project:

```bash
cd <target-project>
zrok init                    # Creates .zrok directory
zrok onboard --auto          # Auto-detects tech stack
zrok lsp status              # Check available LSP servers

# Optional: Enable semantic search
zrok index status            # Check if already enabled
```

---

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

    # If semantic search is available, also use:
    # zrok semantic "entry points"
    # zrok semantic "configuration"
```

---

## Phase 3: Spawn Analysis Agents (Parallel)

Spawn multiple analysis agents in a SINGLE message with multiple Task tool calls.

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

{output from: zrok agent prompt <agent-name|}

## Available Commands

### Standard Navigation
- zrok list <dir> [--recursive]    # List directory contents
- zrok find "<pattern>"            # Find files by pattern
- zrok search "<pattern>" --regex  # Search file contents (grep-like)
- zrok read <file> [--lines N:M]   # Read file contents
- zrok symbols <file>              # Extract code symbols
- zrok symbols --method lsp <file> # LSP-based symbol extraction (more accurate)

### Semantic Search (if available)
Check availability: zrok index status
If enabled:
- zrok semantic "<query>"              # Natural language search
- zrok semantic "<query>" --multi-hop  # Explore related code paths
- zrok semantic "<query>" --type function  # Filter by type
- zrok semantic related <file>         # Find related code

Example semantic queries for {agent-name}:
{agent-specific semantic query examples}

### Memory & Findings
- zrok memory read <name>              # Read shared context
- zrok finding create --file /tmp/finding.yaml  # Create finding

## Finding YAML Format
title: "Issue Title"
severity: high  # critical, high, medium, low, info
confidence: high  # high, medium, low
cwe: CWE-XXX
location:
  file: "path/to/file"
  line_start: 47
  line_end: 52
description: |
  Description of the issue...
impact: |
  What could happen if exploited...
remediation: |
  How to fix...
tags:
  - tag1
created_by: {agent-name}
```

### Agent-Specific Semantic Queries

When semantic search is available, agents should use these queries:

**security-agent:**
```bash
zrok semantic "authentication bypass"
zrok semantic "password validation"
zrok semantic "session management"
zrok semantic "authorization check"
zrok semantic "SQL query construction"
zrok semantic "crypto key handling"
```

**guards-agent:**
```bash
zrok semantic "input validation"
zrok semantic "error handling"
zrok semantic "CSRF protection"
zrok semantic "rate limiting"
```

**architecture-agent:**
```bash
zrok semantic "database connection"
zrok semantic "external API calls"
zrok semantic "configuration loading"
zrok semantic "dependency injection"
```

**content-agent:**
```bash
zrok semantic "HTML rendering"
zrok semantic "file upload handling"
zrok semantic "user content display"
```

---

## Phase 4: Spawn Validation Agent

After all analysis agents complete, spawn the validation-agent to triage findings:

```
Task tool:
- subagent_type: "general-purpose"
- description: "validation-agent: triage findings"
- prompt: |
    You are running as the validation-agent.

    Working Directory: <target-project>
    zrok Binary: <path-to-zrok>

    {output from: zrok agent prompt validation-agent}

    ## Your Tasks
    1. List all findings: zrok finding list
    2. For each finding:
       - Read the finding: zrok finding show <id>
       - Verify code exists at location: zrok read <file> --lines N:M
       - Check for duplicates
       - Assess initial priority
    3. Update findings:
       - Confirmed: zrok finding update <id> --status confirmed
       - False positive: zrok finding update <id> --status false_positive
       - Duplicate: zrok finding update <id> --status duplicate

    ## Output
    Provide a summary of:
    - Total findings reviewed
    - Confirmed findings by severity
    - False positives identified
    - Duplicates merged
    - Findings needing deep review (high/critical severity)
```

---

## Phase 5: Spawn Review Agents (Per-Finding Deep Validation)

After validation-agent completes, spawn a **dedicated review-agent for each high-severity finding** that needs deep investigation.

### Key Distinction from Validation

| Agent | Scope | Focus |
|-------|-------|-------|
| `validation-agent` | ALL findings | Quick triage: dedup, obvious false positives, initial priority |
| `review-agent` | ONE finding | Deep investigation: exploitability, data flow, mitigations, fix priority |

### When to Spawn Review Agents

Spawn review-agents for findings that are:
- Severity: high or critical
- Status: confirmed (not false_positive or duplicate)
- Confidence: any (review-agent will validate)

### Skip Review When

- Finding is marked `false_positive` or `duplicate`
- Finding is `severity: info` or `severity: low`
- Finding was already thoroughly investigated by validation-agent

### Orchestration Pattern

```bash
# 1. Get the list of findings needing review
zrok finding list --status confirmed --json

# 2. Filter for high/critical severity (parse JSON output)
# 3. For each finding, spawn a review-agent (see below)
```

### Review Agent Prompt Template

For EACH finding that needs review, spawn a dedicated agent:

```
Task tool:
- subagent_type: "general-purpose"
- description: "review-agent: validate FIND-XXX"
- prompt: |
    You are a code review specialist validating a single finding.

    Working Directory: <target-project>
    zrok Binary: <path-to-zrok>

    ## Finding to Investigate
    {output from: zrok finding show FIND-XXX}

    ## Your Mission
    Deeply investigate this finding to determine:
    1. Does the issue actually exist at the reported location?
    2. Is it exploitable? How easily?
    3. What is the appropriate fix priority?

    ## Investigation Process

    ### Step 1: Verify the Issue Exists
    - Read the code: zrok read <file> --lines <start>:<end+10>
    - Check symbols: zrok symbols --method lsp <file>
    - Search for related code: zrok search "<pattern>" --regex

    ### Step 2: Trace Data Flow (if semantic search available)
    - zrok semantic "user input to <sink>"
    - zrok semantic "<function-name> callers"
    - zrok semantic "validation of <parameter>"

    ### Step 3: Search for Mitigations
    - Look for input validation
    - Check for authorization guards
    - Find sanitization/encoding
    - Identify if code path is reachable

    ### Step 4: Assess Exploitability
    Rate as one of:
    - **proven**: Clear unmitigated path from user input to vulnerable sink
    - **likely**: Path exists with minimal barriers
    - **possible**: Theoretically exploitable but barriers exist
    - **unlikely**: Significant mitigations found in code

    ### Step 5: Determine Fix Priority
    Rate as one of:
    - **immediate**: Actively exploitable, high impact
    - **high**: Exploitable with effort, significant impact
    - **medium**: Possible exploitation, moderate impact
    - **low**: Unlikely exploitation or low impact
    - **defer**: Technical debt, not a security concern

    ### Step 6: Update the Finding
    zrok finding update FIND-XXX \
      --status <confirmed|false_positive> \
      --exploitability <proven|likely|possible|unlikely> \
      --fix-priority <immediate|high|medium|low|defer>

    ## Output Format
    Provide a structured assessment:

    **Finding:** FIND-XXX
    **Verdict:** [confirmed/false_positive]
    **Exploitability:** [level] - [brief justification]
    **Fix Priority:** [level] - [brief justification]
    **Evidence:** [what you found during investigation]
    **Recommendations:** [additional remediation context]
```

### Parallel Execution

Spawn ALL review-agents in a SINGLE message with multiple Task tool calls:

```
Single message with multiple Task tool calls:
- Task 1: review-agent for FIND-001
- Task 2: review-agent for FIND-002
- Task 3: review-agent for FIND-003
- Task 4: review-agent for FIND-004
```

This allows parallel investigation of multiple findings simultaneously.

---

## Phase 6: Export

After all review-agents complete, generate final reports:

```bash
# Summary statistics
zrok finding stats

# Export reports
zrok finding export --format md -o report.md           # Human-readable
zrok finding export --format sarif -o report.sarif     # CI/CD integration
zrok finding export --format html -o report.html       # Web report
zrok finding export --format json -o report.json       # Machine-readable
```

---

## Key Principles

1. **Always delegate** - Spawn subagents for each phase, don't analyze code directly
2. **Parallel analysis** - Spawn security, guards, architecture agents together in one message
3. **Parallel review** - Spawn all review-agents together in one message
4. **Use LSP when available** - `zrok symbols --method lsp` for accurate symbol extraction
5. **Use semantic search when available** - Check `zrok index status` first, use for natural language queries
6. **Validate findings** - Always run validation-agent before review-agents
7. **Deep review for high severity** - Always spawn review-agents for high/critical findings
8. **Share context** - Use `zrok memory write` to share discoveries between agents

---

## Complete Workflow Example

```bash
# Phase 1: Setup
cd /path/to/target-project
zrok init
zrok onboard --auto
zrok index status  # Check if semantic search available

# Phase 2: Recon (spawn via Task tool)
# → Creates memories: project_overview, tech_stack, etc.

# Phase 3: Analysis (spawn 3-4 agents in parallel via Task tool)
# → Creates findings

# Phase 4: Validation (spawn via Task tool)
# → Triages findings, marks false positives/duplicates

# Phase 5: Review (spawn N agents in parallel, one per high-severity finding)
# Get findings needing review:
zrok finding list --status confirmed --severity high --json
# → Spawn review-agent for each

# Phase 6: Export
zrok finding stats
zrok finding export --format md -o security-report.md
```

---

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

### Semantic Search (Optional)
```bash
# Check availability
zrok index status

# Setup (if not enabled)
zrok index enable [--provider ollama|openai|huggingface]
zrok index build [--force]
zrok index update

# Search
zrok semantic "<query>"                    # Natural language search
zrok semantic "<query>" --multi-hop        # Explore related code
zrok semantic "<query>" --type function    # Filter by chunk type
zrok semantic "<query>" --file "*.go"      # Filter by file pattern
zrok semantic related <file>               # Find related code
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
zrok finding list [--severity high] [--status confirmed] [--json]
zrok finding show <id>
zrok finding update <id> --status <status> [--exploitability <level>] [--fix-priority <level>]
zrok finding export --format <md|sarif|html|csv|json> [-o <file>]
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
