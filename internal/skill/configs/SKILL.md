# Code Review Skill

Orchestrates a comprehensive code review using quokka agents and subagent delegation.

## Invocation

This skill is invoked when the user asks for a code review using quokka, such as:
- "Run a code review using quokka"
- "Use quokka to review this codebase"
- "Do a security review with quokka agents"

## Prerequisites

- quokka binary must be built and available (either in PATH or specify location)
- Target project directory must be accessible

### Optional: Semantic Search

Semantic search enables natural language queries against the codebase. It requires an embedding provider:

```bash
# Check if semantic search is available
quokka index status

# If not enabled, set up with one of:
quokka index enable --provider ollama      # Local, free (requires Ollama)
quokka index enable --provider openai      # Cloud, paid (requires OPENAI_API_KEY)
quokka index enable --provider huggingface # Cloud, free tier (requires HF_API_KEY)

# Build the index (one-time, can take a while for large codebases)
quokka index build
```

## Workflow Overview

```
1. Project Setup    → quokka init && quokka onboard (outputs recon prompt)
2. Recon Agent      → Spawn recon-agent with prompt, creates memories
3. Analysis Agents  → Run in parallel (security, guards, architecture, content)
4. Validation       → Reviews all findings (triage, false positives, priority)
5. Review Agents    → Deep validation per finding (one agent per finding, parallel)
6. Export           → Generate reports (markdown, SARIF, HTML, CSV, JSON)
```

---

## Phase 1: Project Setup

```bash
cd <target-project>
quokka init                    # Creates .quokka directory
quokka onboard                 # Runs static detection, outputs recon-agent prompt
```

The `quokka onboard` command will:
1. Run quick static tech stack detection
2. Detect sensitive areas
3. Create initial memories
4. Output the recon-agent prompt for Phase 2

**JSON output for programmatic use:**
```bash
quokka onboard --json
# Returns: { "status": "ready_for_recon", "tech_stack": {...}, "agent_prompt": "..." }
```

### Optional: Enable Semantic Search

```bash
quokka index status            # Check if already enabled

# If not enabled:
quokka index enable --provider ollama
quokka index build
```

> **Note:** For quick setup without LLM involvement, use `quokka onboard --static` to skip recon-agent prompt output and rely on static detection only. If using static mode, get the recon prompt separately with `quokka agent prompt recon-agent`.

---

## Phase 2: Spawn Recon Agent

Get the recon-agent prompt (if not captured from `quokka onboard` output):

```bash
quokka agent prompt recon-agent
```

Spawn the recon-agent using the Task tool:

```
Task tool:
- subagent_type: "general-purpose"
- description: "recon-agent: map codebase"
- prompt: |
    You are running as the recon-agent for a quokka code review.

    Working Directory: <target-project>
    quokka Binary: <path-to-quokka>

    {output from: quokka agent prompt recon-agent}

    Create these memories:
    - project_overview
    - tech_stack
    - api_endpoints
    - auth_patterns
    - review_targets
    - coding_standards

    # If semantic search is available, also use:
    # quokka semantic "entry points"
    # quokka semantic "configuration"
```

After recon-agent completes, verify memories were created:
```bash
quokka memory list
# Should show: project_overview, tech_stack, coding_standards, api_endpoints, auth_patterns, review_targets
```

---

## Phase 3: Spawn Analysis Agents (Parallel)

Spawn multiple analysis agents in a SINGLE message with multiple Task tool calls.

**CRITICAL: You MUST spawn all agents listed by `quokka onboard` in the "Suggested agents" output.** The onboarding step detects the tech stack and recommends agents accordingly. Do not skip agents or select a subset — spawn them ALL in parallel. Skipping specialized agents (especially `injection-agent` and `security-agent`) dramatically reduces review quality.

### Mandatory Agents

These agents MUST always be spawned for any security review:

| Agent | Focus |
|-------|-------|
| security-agent | Auth, authz, crypto, secrets |
| guards-agent | Validation, CSRF, error handling |
| architecture-agent | Code patterns, dead code, tech debt |
| injection-agent | SQL/command/XPath/template injection (**always for web apps or projects with databases**) |
| config-agent | Debug modes, default creds, CORS, headers |

### Additional Agents (spawn when suggested by onboarding)

Onboarding classifies the project into types (`web-app`, `api-service`, `cli-tool`, `library`, `worker`) and traits (`has-datastore`, `has-auth`, `has-infrastructure`, `has-sensitive-data`). Agents are suggested based on these classifications.

| Agent | Focus | Project Types / Traits |
|-------|-------|------------------------|
| content-agent | XSS, file uploads, logging | `web-app` |
| ssrf-agent | SSRF, URL manipulation, DNS rebinding | `web-app`, `api-service` |
| logging-agent | Audit trails, sensitive data | `has-infrastructure` |
| dependencies-agent | Outdated deps, vulnerabilities | Always |
| references-agent | External URLs, hardcoded paths | `web-app`, `api-service`, `has-infrastructure` |

### Subagent Prompt Template

```
You are running as the {agent-name} for a quokka code review.

Working Directory: <target-project>
quokka Binary: <path-to-quokka>

{output from: quokka agent prompt <agent-name>}

## Available Commands

### Standard Navigation
- quokka list <dir> [--recursive]    # List directory contents
- quokka find "<pattern>"            # Find files by pattern
- quokka search "<pattern>" --regex  # Search file contents (grep-like)
- quokka read <file> [--lines N:M]   # Read file contents
- quokka symbols <file>              # Extract code symbols
- quokka symbols --method treesitter <file> # Tree-sitter symbol extraction (fast, in-process)
- quokka symbols --method lsp <file>        # LSP symbol extraction (accurate, needs server)

### Semantic Search (if available)
Check availability: quokka index status
If enabled:
- quokka semantic "<query>"              # Natural language search
- quokka semantic "<query>" --multi-hop  # Explore related code paths
- quokka semantic "<query>" --type function  # Filter by type
- quokka semantic related <file>         # Find related code

Example semantic queries for {agent-name}:
{agent-specific semantic query examples}

### Memory & Findings
- quokka memory list                     # See shared memories
- quokka memory read <name>              # Read shared context
- quokka memory write <name> --type <type> --content "..."  # Share discoveries
- quokka finding create --file /tmp/finding.yaml  # Create finding

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
quokka semantic "authentication bypass"
quokka semantic "password validation"
quokka semantic "session management"
quokka semantic "authorization check"
quokka semantic "SQL query construction"
quokka semantic "crypto key handling"
```

**guards-agent:**
```bash
quokka semantic "input validation"
quokka semantic "error handling"
quokka semantic "CSRF protection"
quokka semantic "rate limiting"
```

**architecture-agent:**
```bash
quokka semantic "database connection"
quokka semantic "external API calls"
quokka semantic "configuration loading"
quokka semantic "dependency injection"
```

**content-agent:**
```bash
quokka semantic "HTML rendering"
quokka semantic "file upload handling"
quokka semantic "user content display"
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
    quokka Binary: <path-to-quokka>

    {output from: quokka agent prompt validation-agent}

    ## Your Tasks
    1. Read context memories first: quokka memory list && quokka memory read auth_patterns
    2. List all findings: quokka finding list
    3. For each finding:
       - Read the finding: quokka finding show <id>
       - Verify code exists at location: quokka read <file> --lines N:M
       - Check for duplicates
       - Assess initial priority
    4. Update findings:
       - Confirmed: quokka finding update <id> --status confirmed
       - False positive: quokka finding update <id> --status false_positive
       - Duplicate: quokka finding update <id> --status false_positive
         (Record which finding it duplicates in the validation_summary memory)
    5. Create validation_summary memory with statistics

    ## Output
    Provide a summary of:
    - Total findings reviewed
    - Confirmed findings by severity
    - False positives identified (including duplicates)
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
- Status: confirmed (not false_positive)
- Confidence: any (review-agent will validate)

### Skip Review When

- Finding is marked `false_positive`
- Finding is `severity: info` or `severity: low`
- Finding was already thoroughly investigated by validation-agent

### Orchestration Pattern

```bash
# 1. Get the list of findings needing review
quokka finding list --status confirmed --json

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
    quokka Binary: <path-to-quokka>

    ## Finding to Investigate
    {output from: quokka finding show FIND-XXX}

    ## Context Memories
    IMPORTANT: Read these memories FIRST to understand the codebase:
    - quokka memory read auth_patterns
    - quokka memory read coding_standards
    - quokka memory read input_validation_patterns (if exists)

    ## Your Mission
    Deeply investigate this finding to determine:
    1. Does the issue actually exist at the reported location?
    2. Is it exploitable? How easily?
    3. What is the appropriate fix priority?

    ## Investigation Process

    ### Step 1: Read Context Memories
    Start by reading relevant memories to understand project patterns.

    ### Step 2: Verify the Issue Exists
    - Read the code: quokka read <file> --lines <start>:<end+10>
    - Check symbols: quokka symbols <file>
    - Search for related code: quokka search "<pattern>" --regex

    ### Step 3: Trace Data Flow (if semantic search available)
    - quokka semantic "user input to <sink>"
    - quokka semantic "<function-name> callers"
    - quokka semantic "validation of <parameter>"

    ### Step 4: Search for Mitigations
    - Look for input validation
    - Check for authorization guards
    - Find sanitization/encoding
    - Identify if code path is reachable

    ### Step 5: Assess Exploitability
    Rate as one of:
    - **proven**: Clear unmitigated path from user input to vulnerable sink
    - **likely**: Path exists with minimal barriers
    - **possible**: Theoretically exploitable but barriers exist
    - **unlikely**: Significant mitigations found in code

    ### Step 6: Determine Fix Priority
    Rate as one of:
    - **immediate**: Actively exploitable, high impact
    - **high**: Exploitable with effort, significant impact
    - **medium**: Possible exploitation, moderate impact
    - **low**: Unlikely exploitation or low impact
    - **defer**: Technical debt, not a security concern

    ### Step 7: Update the Finding
    quokka finding update FIND-XXX \
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
quokka finding stats

# Export reports
quokka finding export --format md -o report.md           # Human-readable
quokka finding export --format sarif -o report.sarif     # CI/CD integration
quokka finding export --format html -o report.html       # Web report
quokka finding export --format csv -o report.csv         # Spreadsheet
quokka finding export --format json -o report.json       # Machine-readable
```

---

## Key Principles

1. **Always delegate** - Spawn subagents for each phase, don't analyze code directly
2. **Agent onboarding by default** - Use `quokka onboard` (agent mode) for richer context
3. **Parallel analysis** - Spawn security, guards, architecture agents together in one message
4. **Parallel review** - Spawn all review-agents together in one message
5. **Use best available method** - `quokka symbols` auto-selects tree-sitter → LSP → regex; use `--method lsp` when tree-sitter fails
6. **Use semantic search when available** - Check `quokka index status` first, use for natural language queries
7. **Validate findings** - Always run validation-agent before review-agents
8. **Deep review for high severity** - Always spawn review-agents for high/critical findings
9. **Share context via memories** - Use `quokka memory write` to share discoveries between agents
10. **Read memories first** - Agents should read context memories before starting analysis

---

## Complete Workflow Example

```bash
# Phase 1: Project Setup
cd /path/to/target-project
quokka init
quokka onboard                 # Runs static detection, outputs recon-agent prompt
quokka index status            # Check if semantic search available

# Phase 2: Recon Agent (spawn via Task tool)
# → Creates memories: project_overview, tech_stack, coding_standards, api_endpoints, auth_patterns, review_targets
quokka memory list             # Verify recon complete

# Phase 3: Analysis (spawn 3-4 agents in parallel via Task tool)
# → Creates findings

# Phase 4: Validation (spawn via Task tool)
# → Triages findings, marks false positives

# Phase 5: Review (spawn N agents in parallel, one per high-severity finding)
# Get findings needing review:
quokka finding list --status confirmed --severity high --json
# → Spawn review-agent for each

# Phase 6: Export
quokka finding stats
quokka finding export --format md -o security-report.md
```

---

## quokka Commands Reference

### Navigation
```bash
quokka list <dir> [--recursive] [--depth N]
quokka find "<pattern>"
quokka read <file> [--lines N:M]
quokka search "<pattern>" [--regex]
quokka symbols <file>
quokka symbols --method treesitter <file>
quokka symbols --method lsp <file>
quokka symbols find "<name>"
```

### Semantic Search (Optional)
```bash
# Check availability
quokka index status

# Setup (if not enabled)
quokka index enable [--provider ollama|openai|huggingface]
quokka index build [--force]
quokka index update

# Search
quokka semantic "<query>"                    # Natural language search
quokka semantic "<query>" --multi-hop        # Explore related code
quokka semantic "<query>" --type function    # Filter by chunk type
quokka semantic "<query>" --file "*.go"      # Filter by file pattern
quokka semantic related <file>               # Find related code
```

### Memory
```bash
quokka memory write <name> --type <type> --content "..." --tags t1 --tags t2
quokka memory read <name>
quokka memory list
quokka memory search "<query>"
```

### Findings
```bash
quokka finding create --file <yaml>
quokka finding list [--severity high] [--status confirmed] [--json]
quokka finding show <id>
quokka finding update <id> --status <status> [--exploitability <level>] [--fix-priority <level>]
quokka finding export --format <md|sarif|html|csv|json> [-o <file>]
quokka finding stats
```

### Agents
```bash
quokka agent list
quokka agent show <name>
quokka agent prompt <name>
```

### Onboarding
```bash
quokka init                    # Initialize .quokka directory
quokka onboard                 # Agent-assisted onboarding (default, outputs recon prompt)
quokka onboard --static        # Static detection only (fast, no LLM)
quokka onboard --wizard        # Interactive wizard mode
quokka onboard --json          # JSON output for programmatic use
```

### Thinking
```bash
quokka think collected
quokka think adherence
quokka think done
quokka think next
quokka think hypothesis "<context>"
quokka think validate <finding-id>
```
