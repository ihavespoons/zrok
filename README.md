# quokka

A CLI tool for LLM-assisted security code review. quokka provides structured tooling for multi-agent workflows — project onboarding, code navigation, memory sharing, finding management, and report export.

## Installation

### Homebrew

```bash
brew install ihavespoons/homebrew-tap/quokka
```

### From Source

```bash
git clone https://github.com/diffsec/quokka.git
cd quokka
go build -o quokka .
```

### Go Install

```bash
go install github.com/diffsec/quokka@latest
```

## Adding the Skill to Claude Code

quokka ships with a Claude Code skill that orchestrates the full review workflow.

### Automatic (recommended)

```bash
quokka init --install-skill
```

This installs the skill to `~/.claude/skills/quokka-code-review/SKILL.md`, making it globally available across all projects.

### Manual

```bash
mkdir -p /path/to/your/project/.claude/skills
cp -r /path/to/quokka/skills/code-review /path/to/your/project/.claude/skills/code-review
```

Then open Claude Code in the target project and invoke it naturally:

> "Run a security code review using quokka"

The skill handles agent delegation, memory sharing, finding creation, and export automatically. See [`skills/code-review/SKILL.md`](skills/code-review/SKILL.md) for the full orchestration reference.

## End-to-End Example

```bash
# ── Setup ────────────────────────────────────────────────────────
cd /path/to/your/project
quokka init                        # Creates .quokka/ directory
quokka onboard                     # Detects tech stack, outputs recon-agent prompt

# ── Phase 1: Recon ───────────────────────────────────────────────
# The skill spawns recon-agent as a subagent with the onboard prompt.
# Recon explores the codebase and creates shared memories:
#   project_overview, tech_stack, coding_standards,
#   api_endpoints, auth_patterns, review_targets

quokka memory list                 # Verify memories were created

# ── Phase 2: Analysis (parallel) ────────────────────────────────
# The skill spawns analysis agents in parallel. Each reads the
# shared memories, navigates code with quokka, and creates findings.
#   security-agent   → auth, authz, crypto, secrets
#   guards-agent     → input validation, CSRF, error handling
#   architecture-agent → code patterns, technical debt
#   + optional: content-agent, logging-agent, dependencies-agent, references-agent

quokka finding list                # See what they found

# ── Phase 3: Validation ─────────────────────────────────────────
# validation-agent triages all findings — deduplicates, marks
# false positives, and confirms real issues.

quokka finding list --status confirmed

# ── Phase 4: Review (parallel) ──────────────────────────────────
# A dedicated review-agent is spawned per high/critical finding.
# Each traces data flow, checks mitigations, and rates
# exploitability and fix priority.

# ── Phase 5: Export ──────────────────────────────────────────────
quokka finding stats
quokka finding export --format md -o report.md       # Human-readable
quokka finding export --format sarif -o report.sarif  # CI/CD integration
quokka finding export --format html -o report.html    # Stakeholder report
```

## Built-in Agents

| Agent | Phase | Focus |
|-------|-------|-------|
| `recon-agent` | Recon | Maps attack surface, creates shared memories |
| `security-agent` | Analysis | Authentication, authorization, crypto, secrets |
| `guards-agent` | Analysis | Input validation, CSRF, error handling |
| `architecture-agent` | Analysis | Code patterns, technical debt |
| `content-agent` | Analysis | XSS, file uploads, logging |
| `logging-agent` | Analysis | Audit trails, sensitive data in logs |
| `dependencies-agent` | Analysis | Outdated deps, known vulnerabilities |
| `references-agent` | Analysis | External URLs, hardcoded paths |
| `validation-agent` | Validation | Deduplicates and triages all findings |
| `review-agent` | Review | Deep per-finding investigation |

```bash
quokka agent list              # List all agents
quokka agent show <name>       # Show agent details
quokka agent prompt <name>     # Generate agent prompt with project context
```

## Semantic Search

Optional natural language search over the codebase using vector embeddings.

```bash
# Enable with a provider (one-time)
quokka index enable --provider ollama       # Local, free (requires Ollama)
quokka index enable --provider openai       # Cloud, paid (requires OPENAI_API_KEY)
quokka index enable --provider huggingface  # Cloud, free tier (requires HF_API_KEY)

# Build the index
quokka index build

# Search
quokka semantic "authentication bypass"              # Natural language query
quokka semantic "SQL injection" --multi-hop          # Explore related code paths
quokka semantic "error handling" --type function     # Filter by chunk type
quokka semantic related cmd/agent.go                 # Find related code
```

## Export Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| SARIF | Static Analysis Results Interchange Format | CI/CD integration, GitHub Advanced Security |
| JSON | Structured JSON with metadata | API integration, custom processing |
| Markdown | Human-readable report | Documentation, code review |
| HTML | Styled web report | Sharing with stakeholders |
| CSV | Comma-separated values | Spreadsheet analysis |

## Development

```bash
go build -o quokka .    # Build
go test ./...         # Test
```

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE.md).
