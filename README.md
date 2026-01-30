# zrok

A Go CLI tool that provides structured tooling for LLM-assisted security code review. zrok is read-only (no code modification), focused on security analysis, and designed for multi-agent workflows.

## Features

- **Project Management**: Initialize, configure, and onboard projects with automatic tech stack detection
- **Code Navigation**: Read-only file access, directory listing, pattern search, and symbol extraction
- **Memory System**: Hierarchical memory storage for context, patterns, and tech stack specific information
- **Findings Management**: Create, update, and track security findings with full CVSS and CWE support
- **Multi-Format Export**: Export findings to SARIF, JSON, Markdown, HTML, and CSV formats
- **Agent System**: Built-in security analysis agents with customizable prompts
- **Thinking Tools**: Structured prompts for LLM self-reflection and task management
- **Web Dashboard**: Visual interface for browsing findings and project status

## Installation

### From Source

```bash
git clone https://github.com/ihavespoons/zrok.git
cd zrok
go build -o zrok .
```

### Go Install

```bash
go install github.com/ihavespoons/zrok@latest
```

## Quick Start

```bash
# Initialize zrok in your project
cd /path/to/your/project
zrok init

# Run automatic onboarding to detect tech stack
zrok onboard --auto

# Check project status
zrok status

# Read files
zrok read main.go

# Search for patterns
zrok search "TODO|FIXME" --regex

# Create a finding
zrok finding create --interactive

# Export findings
zrok finding export --format sarif --output report.sarif

# Start the dashboard
zrok dashboard
```

## CLI Commands

### Project Management

```bash
zrok init                     # Initialize .zrok in current project
zrok activate [path]          # Activate a project
zrok config get <key>         # Get config value
zrok config set <key> <value> # Set config value
zrok onboard --auto           # Auto-detect tech stack
zrok onboard --wizard         # Interactive wizard mode
zrok status                   # Show project status
```

### Code Navigation

```bash
zrok read <file>                    # Read file content
zrok read <file> --lines 10:20      # Read specific lines
zrok list <dir>                     # List directory
zrok list <dir> --recursive         # Recursive listing
zrok find "*.go"                    # Find files by pattern
zrok search "pattern"               # Search file contents
zrok search "pattern" --regex       # Regex search
zrok symbols <file>                 # Extract symbols from file
zrok symbols find <name>            # Find symbol globally
```

### Memory Management

```bash
zrok memory list                    # List all memories
zrok memory list --type context     # List by type
zrok memory read <name>             # Read a memory
zrok memory write <name> --content "..."  # Write memory
zrok memory write <name> --file input.md  # Write from file
zrok memory delete <name>           # Delete memory
zrok memory search <query>          # Search memories
```

### Findings Management

```bash
zrok finding create --interactive   # Create interactively
zrok finding create --file f.yaml   # Create from file
zrok finding update <id> --status confirmed
zrok finding list                   # List all findings
zrok finding list --severity high   # Filter by severity
zrok finding show <id>              # Show finding details
zrok finding export --format sarif  # Export findings
zrok finding stats                  # Show statistics
```

### Thinking Tools

```bash
zrok think collected    # Evaluate collected information
zrok think adherence    # Check task adherence
zrok think done         # Assess if task is complete
zrok think next         # Suggest next steps
zrok think hypothesis   # Generate security hypotheses
zrok think validate     # Validate a finding
```

### Agent Management

```bash
zrok agent list             # List available agents
zrok agent show <name>      # Show agent details
zrok agent create <name>    # Create custom agent
zrok agent prompt <name>    # Generate agent prompt
```

### Dashboard

```bash
zrok dashboard              # Start web dashboard on :8080
zrok dashboard --port 9000  # Custom port
```

### Utility

```bash
zrok instructions           # Print LLM onboarding instructions
zrok export-context         # Export full context for new conversation
```

## Project Structure

When initialized, zrok creates a `.zrok/` directory in your project:

```
.zrok/
├── project.yaml          # Project config & tech stack
├── memories/
│   ├── context/          # Project context memories
│   ├── patterns/         # Vulnerability pattern memories
│   └── stack/            # Tech stack specific memories
├── findings/             # Security findings
│   ├── raw/              # Individual finding files
│   └── exports/          # Exported reports
└── agents/               # Project-specific agent configs
```

## Finding Schema

Findings support comprehensive security metadata:

```yaml
id: FIND-001
title: "SQL Injection in user search"
severity: high           # critical, high, medium, low, info
confidence: high         # high, medium, low
status: open             # open, confirmed, false_positive, fixed
cwe: CWE-89
cvss:
  score: 8.6
  vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
location:
  file: "src/api/users.go"
  line_start: 45
  line_end: 52
  function: "SearchUsers"
  snippet: |
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", input)
description: |
  User input is directly concatenated into SQL query without sanitization.
impact: |
  Attacker can extract, modify, or delete database contents.
remediation: |
  Use parameterized queries or prepared statements.
evidence:
  - type: dataflow
    description: "Input flows from HTTP param to SQL query"
    trace: ["handlers/user.go:23", "services/user.go:45"]
references:
  - https://owasp.org/www-community/attacks/SQL_Injection
tags: [injection, database, owasp-top-10]
```

## Built-in Agents

### By Analysis Phase

| Agent | Phase | Description |
|-------|-------|-------------|
| `recon-agent` | Recon | Initial reconnaissance, maps attack surface |
| `static-agent` | Analysis | Static code analysis patterns |
| `dataflow-agent` | Analysis | Taint tracking, data flow analysis |
| `validation-agent` | Validation | Validates and deduplicates findings |

### By Vulnerability Class

| Agent | Focus Area |
|-------|------------|
| `injection-agent` | SQLi, XSS, Command injection |
| `auth-agent` | Authentication/authorization flaws |
| `crypto-agent` | Cryptographic issues |
| `config-agent` | Misconfigurations, hardcoded secrets |
| `logic-agent` | Business logic flaws |

## Export Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| SARIF | Static Analysis Results Interchange Format | CI/CD integration, GitHub Advanced Security |
| JSON | Structured JSON with metadata | API integration, custom processing |
| Markdown | Human-readable report | Documentation, code review |
| HTML | Styled web report | Sharing with stakeholders |
| CSV | Comma-separated values | Spreadsheet analysis |

## Tech Stack Detection

zrok automatically detects:

- **Languages**: Go, JavaScript/TypeScript, Python, Java, Rust, Ruby
- **Frameworks**: Gin, Echo, React, Vue, Angular, Django, Flask, Spring
- **Databases**: PostgreSQL, MySQL, MongoDB, Redis, SQLite
- **Infrastructure**: Docker, Kubernetes, Terraform
- **Authentication**: JWT, OAuth, Session-based

## LLM Integration

zrok is designed for LLM-assisted security review. Example workflow:

```bash
# 1. Get tool documentation
zrok instructions

# 2. Onboard the project
zrok onboard --auto

# 3. Generate agent prompt
zrok agent prompt injection-agent

# 4. Navigate and analyze code
zrok read src/handlers/user.go
zrok search "SELECT.*%s" --regex

# 5. Record findings
zrok finding create --file finding.yaml

# 6. Self-check progress
zrok think adherence
zrok think done

# 7. Export results
zrok finding export --format sarif
```

## Development

### Prerequisites

- Go 1.21 or later

### Building

```bash
go build -o zrok .
```

### Testing

```bash
go test ./...
```

### Project Layout

```
zrok/
├── cmd/                      # CLI commands (cobra)
├── internal/
│   ├── project/              # Project management
│   ├── navigate/             # Code navigation
│   ├── memory/               # Memory system
│   ├── finding/              # Findings management
│   │   └── export/           # Export formats
│   ├── agent/                # Agent system
│   ├── think/                # Thinking tools
│   └── dashboard/            # Web dashboard
├── go.mod
├── go.sum
├── main.go
└── README.md
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
