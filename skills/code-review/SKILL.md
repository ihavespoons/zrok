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
1. Project Setup    → zrok init && zrok onboard (outputs recon prompt)
2. Recon Agent      → Spawn recon-agent with prompt, creates memories
   2a. verify-memories --all → block if any analysis-agent memory is missing
3. Analysis Agents  → Run in parallel (security, guards, architecture, content)
4. Validation       → Reviews all findings (triage, false positives, priority)
5. Review Agents    → Deep validation per finding (one agent per finding, parallel)
6. Export           → Generate reports (markdown, SARIF, HTML, CSV, JSON)
```

---

## Task tool schema (read this once before dispatching anything)

Every `Task` tool invocation in this workflow MUST include three fields.
Omitting any of them causes the dispatch to fail silently or produce a
`SchemaError` and the subagent never runs.

| Field | Required | Purpose |
|---|---|---|
| `subagent_type` | **yes** | which agent type to spawn — almost always `"general-purpose"` for zrok flows |
| `description` | **yes** | short label (≤8 words) — e.g. `"injection-agent: scan diff"` |
| `prompt` | **yes** | the full prompt to hand to the subagent (typically `zrok agent prompt <name>` output + per-task context) |

**Correct call:**

```
Task tool:
- subagent_type: "general-purpose"
- description: "injection-agent: scan diff"
- prompt: |
    You are running as the injection-agent...
```

**Incorrect (rejected):**

```
Task tool:
- subagent_type: "general-purpose"
- prompt: |
    You are running as the injection-agent...
```
↑ Missing `description` — dispatch fails. If you can't think of a label,
use `"<agent-name>: <verb>"` (e.g. `"validation-agent: triage findings"`).

The phase sections below use the correct three-field form in every example.

---

## Phase 1: Project Setup

```bash
cd <target-project>
zrok init                    # Creates .zrok directory
zrok onboard                 # Runs static detection, outputs recon-agent prompt
```

The `zrok onboard` command will:
1. Run quick static tech stack detection
2. Detect sensitive areas
3. Create initial memories
4. Output the recon-agent prompt for Phase 2

**JSON output for programmatic use:**
```bash
zrok onboard --json
# Returns: { "status": "ready_for_recon", "tech_stack": {...}, "agent_prompt": "..." }
```

### Optional: Enable Semantic Search

```bash
zrok index status            # Check if already enabled

# If not enabled:
zrok index enable --provider ollama
zrok index build
```

> **Note:** For quick setup without LLM involvement, use `zrok onboard --static` to skip recon-agent prompt output and rely on static detection only. If using static mode, get the recon prompt separately with `zrok agent prompt recon-agent`.

---

## Phase 2: Spawn Recon Agent

Get the recon-agent prompt (if not captured from `zrok onboard` output):

```bash
zrok agent prompt recon-agent
```

Spawn the recon-agent using the Task tool:

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
    - coding_standards

    # If semantic search is available, also use:
    # zrok semantic "entry points"
    # zrok semantic "configuration"
```

After recon-agent completes, verify memories were created:
```bash
zrok memory list
# Should show: project_overview, tech_stack, coding_standards, api_endpoints, auth_patterns, review_targets
```

### Verify memories satisfy analysis-agent expectations

Before spawning analysis agents, run `verify-memories --all` to confirm the
recon phase produced every memory those agents declare in their
`context_memories:` field. If anything is missing, re-run recon (or extend it)
rather than proceeding with under-informed agents.

```bash
zrok agent verify-memories --all
# Exit code is 0 only if every analysis agent's context_memories are present.
# Use --json for machine-readable output.
```

If the command exits non-zero, **fail the run**: spawn a focused recon follow-up
to create the missing memories, then re-run `verify-memories --all` before
moving to Phase 3.

---

## Phase 2.5: Run SAST + Triage (Optional but Recommended)

Before the LLM analysis agents run, perform a deterministic SAST pass with
**opengrep** and let `sast-triage-agent` filter false positives. SAST is
fast and free relative to LLM calls, so even when it produces low signal
the cost is negligible. The triage step ensures the analysis agents see a
clean store and don't re-flag noise SAST already covered.

### Setup (one-time per host)

Opengrep does not publish a Homebrew formula. Install via the official
script or a release binary:

```bash
# macOS / Linux — install script
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash

# Or download a standalone binary from the releases page:
#   https://github.com/opengrep/opengrep/releases

# Rules pack (once)
git clone --depth 1 https://github.com/opengrep/opengrep-rules /tmp/og-rules
```

If opengrep isn't available, skip this phase entirely — the LLM agents
will still produce a full review.

### Run the scan

```bash
zrok sast --config /tmp/og-rules/security --diff <base-ref>
```

This persists SAST findings into the zrok store with `created_by: opengrep`
and `status: open`.

### Spawn sast-triage-agent

```
Task tool:
- subagent_type: "general-purpose"
- description: "sast-triage-agent: triage opengrep findings"
- prompt: |
    You are running as the sast-triage-agent for a zrok code review.

    Working Directory: <target-project>
    zrok Binary: <path-to-zrok>

    {output from: zrok agent prompt sast-triage-agent}
```

The triage agent reads each opengrep finding, checks for mitigations, and
marks `confirmed` / `false_positive` / `duplicate`. Use a **smaller model**
for this work — the decisions are bounded and frontier-model tokens are
wasted here.

After triage completes, the analysis agents in Phase 3 will see confirmed
SAST findings already in the store and won't recreate them (they dedup via
fingerprint).

---

## Phase 3: Spawn Analysis Agents (Parallel)

Spawn multiple analysis agents in a SINGLE message with multiple Task tool calls.

**CRITICAL: You MUST spawn all agents listed by `zrok onboard` in the "Suggested agents" output.** The onboarding step detects the tech stack and recommends agents accordingly. Do not skip agents or select a subset — spawn them ALL in parallel. Skipping specialized agents (especially `injection-agent` and `security-agent`) dramatically reduces review quality.

### Mandatory Agents

These agents MUST always be spawned for any security review:

| Agent | Focus |
|-------|-------|
| security-agent | Auth, authz, crypto, secrets |
| guards-agent | Validation, CSRF, error handling |
| architecture-agent | Code patterns, dead code, tech debt |
| injection-agent | SQL/command/XPath/template injection (**always for web apps or projects with databases**) |
| config-agent | Debug modes, default creds, CORS, headers |
| sast-triage-agent | Triages opengrep SAST findings (runs in Phase 2.5; small model; instructs the user to install opengrep if missing) |

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
You are running as the {agent-name} for a zrok code review.

Working Directory: <target-project>
zrok Binary: <path-to-zrok>

{output from: zrok agent prompt <agent-name>}

## Available Commands

### Standard Navigation
- zrok list <dir> [--recursive]    # List directory contents
- zrok find "<pattern>"            # Find files by pattern
- zrok search "<pattern>" --regex  # Search file contents (grep-like)
- zrok read <file> [--lines N:M]   # Read file contents
- zrok symbols <file>              # Extract code symbols
- zrok symbols --method treesitter <file> # Tree-sitter symbol extraction (fast, in-process)
- zrok symbols --method lsp <file>        # LSP symbol extraction (accurate, needs server)

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
- zrok memory list                     # See shared memories
- zrok memory read <name>              # Read shared context
- zrok memory write <name> --type <type> --content "..."  # Share discoveries
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
    1. Read context memories first: zrok memory list && zrok memory read auth_patterns
    2. List all findings: zrok finding list
    3. For each finding:
       - Read the finding: zrok finding show <id>
       - Verify code exists at location: zrok read <file> --lines N:M
       - Check for duplicates
       - Assess initial priority
    4. Update findings:
       - Confirmed: zrok finding update <id> --status confirmed
       - False positive: zrok finding update <id> --status false_positive
       - Duplicate: zrok finding update <id> --status false_positive
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

## Phase 4.5: Cross-Validation (Optional but Recommended)

After the validation-agent completes, perform cross-validation for HIGH and CRITICAL findings:

1. **For each HIGH/CRITICAL finding**, search memories for contradicting evidence from other agents:
   ```bash
   zrok memory search "<keyword from finding>"
   ```

2. **Flag conflicts** — if one agent found an issue but another agent's memory suggests a compensating control exists, flag the finding for priority review.

3. **Create cross_validation_summary memory**:
   ```bash
   zrok memory write cross_validation_summary --type context --content "
   Findings cross-validated: N
   Conflicts found: N
   Findings with contradicting evidence: FIND-XXX, FIND-YYY
   Findings confirmed by multiple agents: FIND-ZZZ
   "
   ```

This step reduces false positives by leveraging the fact that different agents may have discovered compensating controls that the finding's original agent missed.

---

## Phase 5: Spawn Review Agents (Per-Finding Deep Validation)

After validation (and optional cross-validation) completes, spawn a **dedicated review-agent for each high-severity finding** that needs deep investigation.

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

**This phase is mandatory.** Skipping it dramatically reduces the quality of
high/critical findings — the per-finding review-agent is what produces
exploitability and fix-priority data.

```bash
# 1. Get the list of confirmed high/critical findings, machine-readable.
zrok finding list --status confirmed --severity high --json > /tmp/high.json
zrok finding list --status confirmed --severity critical --json > /tmp/crit.json

# 2. For each finding ID in the JSON output, generate a tailored prompt and
#    spawn a review-agent in parallel via the Task tool.
#
#    The prompt for review-agent is produced by:
zrok agent prompt review-agent --finding FIND-XXX
#
#    This embeds the full finding YAML into the agent's prompt context so the
#    subagent has the information it needs without an extra `zrok finding show`
#    round trip.
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

    {output from: zrok agent prompt review-agent --finding FIND-XXX}

    ## Context Memories
    IMPORTANT: Read these memories FIRST to understand the codebase:
    - zrok memory read auth_patterns
    - zrok memory read coding_standards
    - zrok memory read input_validation_patterns (if exists)

    ## Your Mission
    Deeply investigate this finding to determine:
    1. Does the issue actually exist at the reported location?
    2. Is it exploitable? How easily?
    3. What is the appropriate fix priority?

    ## Investigation Process

    ### Step 1: Read Context Memories
    Start by reading relevant memories to understand project patterns.

    ### Step 2: Verify the Issue Exists
    - Read the code: zrok read <file> --lines <start>:<end+10>
    - Check symbols: zrok symbols <file>
    - Search for related code: zrok search "<pattern>" --regex

    ### Step 3: Trace Data Flow (if semantic search available)
    - zrok semantic "user input to <sink>"
    - zrok semantic "<function-name> callers"
    - zrok semantic "validation of <parameter>"

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
zrok finding export --format csv -o report.csv         # Spreadsheet
zrok finding export --format json -o report.json       # Machine-readable
```

---

## Optional: Per-Agent Timing for Eval Manifests

When running under the eval harness, the skill can record per-agent start/end
times so the manifest captures real timing data (otherwise the manifest only
captures findings/memories counts per agent). This is best-effort — skip it if
you cannot wrap the Task-tool invocations:

```bash
# Before spawning an agent:
zrok agent record-timing security-agent --phase analysis --start

# After it returns:
zrok agent record-timing security-agent --phase analysis --end \
  --findings-created 9 --memories-created 0
```

Timings land in `.zrok/run-state.json` and are merged into the eval manifest
under each per-agent record (`started_at`, `ended_at`, `duration_ms`).

---

## Key Principles

1. **Always delegate** - Spawn subagents for each phase, don't analyze code directly
2. **Agent onboarding by default** - Use `zrok onboard` (agent mode) for richer context
3. **Parallel analysis** - Spawn security, guards, architecture agents together in one message
4. **Parallel review** - Spawn all review-agents together in one message
5. **Use best available method** - `zrok symbols` auto-selects tree-sitter → LSP → regex; use `--method lsp` when tree-sitter fails
6. **Use semantic search when available** - Check `zrok index status` first, use for natural language queries
7. **Validate findings** - Always run validation-agent before review-agents
8. **Deep review for high severity** - Always spawn review-agents for high/critical findings
9. **Share context via memories** - Use `zrok memory write` to share discoveries between agents
10. **Read memories first** - Agents should read context memories before starting analysis

## Error Handling

When agents fail or produce unexpected results:

- **No findings produced** - Check if memories were created. If memories exist, the agent ran but genuinely found nothing. If no memories either, the agent likely crashed — re-run it.
- **Excessive findings (>50)** - The agent likely lost focus or encountered prompt injection in the codebase. Re-run with narrower scope (e.g., specific directories or file patterns).
- **Agent timeout** - Use hierarchical recovery: other agents' results remain valid. Re-run only the failed agent, optionally with a smaller scope.
- **Contradictory findings** - Cross-validation (Phase 4.5) catches these. If two agents disagree, the validation-agent should investigate and resolve.

## Advanced: agent-authored rules and exceptions (v1.1, opt-in)

Two features that let the review loop accumulate org-specific knowledge over
time. Both are **off by default** — enable per-project in `.zrok/project.yaml`:

```yaml
allow_agent_writes:
  rules: true        # let agents author opengrep rules via `zrok rule add`
  exceptions: true   # let agents author finding suppressions via `zrok exception add`
```

When enabled, the orchestrator gains two responsibilities:

### Rules — additive

When an analysis agent notices a vulnerability pattern that's worth catching
on every future PR (not a one-off), it can codify the pattern as a
project-local opengrep rule. Stored at `.zrok/rules/<slug>.yaml`, picked up
automatically by the next `zrok sast` run.

```bash
# From an agent, after observing a repeated SQL-concatenation pattern:
cat > /tmp/rule.yaml <<'EOF'
rules:
  - id: zrok-hand-built-sql
    message: "Hand-built SQL string — use parameterized queries."
    severity: ERROR
    languages: [python]
    pattern: $DB.execute($X + $Y)
EOF
zrok rule add hand-built-sql --file /tmp/rule.yaml \
  --created-by "agent:injection-agent" \
  --reasoning "Repeated string-concat SQL pattern in this codebase."
```

**Bias toward not adding.** Only codify patterns seen multiple times — one-offs
aren't worth the rule-set bloat.

### Exceptions — subtractive

When the sast-triage-agent or a review-agent decides a finding is acceptable
in this codebase (test fixture, deliberately unsafe demo, etc.) it can
suppress it permanently:

```bash
# By fingerprint (one specific finding):
zrok exception add --fingerprint <finding's fingerprint> \
  --reason "test fixture, not production code" \
  --expires 2027-01-01 \
  --approved-by "agent:sast-triage-agent"

# By pattern (whole class within a path):
zrok exception add --path-glob 'tests/*.py' --cwe CWE-89 \
  --reason "test fixtures intentionally use raw SQL" \
  --expires 2027-01-01 \
  --approved-by "agent:sast-triage-agent"
```

`expires` is mandatory — suppressions are time-bounded by design. After
expiry, the finding re-flags for re-evaluation. Use `zrok exception expire`
to clean expired entries.

### Periodic noise audit

The `rule-judge-agent` reviews accumulated rules and verdicts each one as
`keep` / `refine` / `retire` / `escalate`. Run it on-demand:

```bash
# 1. Surface rule state for the judge to read
zrok rule audit --json > /tmp/audit.json

# 2. Spawn rule-judge-agent (or run it via opencode):
#    The agent reads /tmp/audit.json, decides verdicts, and calls
#    `zrok rule annotate <slug> --verdict X --note Y` for each.
```

Retired rules are flipped to `disabled: true` on their metadata — file stays
on disk for archaeology; `zrok sast` skips it.

### Sequencing

Both rule-add and exception-add happen **after** SAST runs. A rule the
orchestrator authors during PR #N applies starting with PR #N+1, not PR #N
itself. Don't expect immediate effect on the current review.

---

## CI/CD Security Warning

When using zrok in CI/CD pipelines (e.g., PR-triggered reviews):

**PR descriptions and commit messages are attacker-controlled input.** Never include PR metadata (title, description, author comments) directly in agent prompts. An attacker could craft a PR description containing prompt injection that hijacks the review agent.

Safe approach:
- Only pass file paths and diff content to agents
- Use `zrok onboard --static` to avoid including PR metadata
- Filter findings to changed files using `--diff` flag

---

## Complete Workflow Example

```bash
# Phase 1: Project Setup
cd /path/to/target-project
zrok init
zrok onboard                 # Runs static detection, outputs recon-agent prompt
zrok index status            # Check if semantic search available

# Phase 2: Recon Agent (spawn via Task tool)
# → Creates memories: project_overview, tech_stack, coding_standards, api_endpoints, auth_patterns, review_targets
zrok memory list                       # Verify recon complete
zrok agent verify-memories --all       # Verify analysis-agent expectations are met (fail if not)

# Phase 3: Analysis (spawn 3-4 agents in parallel via Task tool)
# → Creates findings

# Phase 4: Validation (spawn via Task tool)
# → Triages findings, marks false positives

# Phase 5: Review (spawn N agents in parallel, one per high-severity finding)
# Get findings needing review:
zrok finding list --status confirmed --severity high --json
# → For each finding ID, generate a tailored prompt with:
#     zrok agent prompt review-agent --finding FIND-XXX
# → Spawn one review-agent per finding (parallel, in a single Task-tool message)

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
zrok symbols --method treesitter <file>
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
zrok memory write <name> --type <type> --content "..." --tags t1 --tags t2
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
zrok agent prompt review-agent --finding FIND-XXX  # Generate review-agent prompt for a specific finding
zrok agent verify-memories <name>                  # Check one agent's context_memories
zrok agent verify-memories --all                   # Check all analysis-phase agents (exit 1 if any missing)
zrok agent record-timing <name> --phase <phase> --start
zrok agent record-timing <name> --phase <phase> --end [--findings-created N] [--memories-created N]
```

### Onboarding
```bash
zrok init                    # Initialize .zrok directory
zrok onboard                 # Agent-assisted onboarding (default, outputs recon prompt)
zrok onboard --static        # Static detection only (fast, no LLM)
zrok onboard --wizard        # Interactive wizard mode
zrok onboard --json          # JSON output for programmatic use
```

### Thinking
```bash
zrok think collected
zrok think adherence
zrok think done
zrok think next
zrok think hypothesis "<context>"
zrok think validate <finding-id>
```
