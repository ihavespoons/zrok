# zrok Development Guide

zrok is a CLI tool for LLM-assisted code review. It provides agent configurations, memory management, finding tracking, and code navigation tools.

## Project Structure

```
zrok/
├── cmd/                    # CLI commands (cobra)
│   ├── root.go            # Root command, global flags
│   ├── project.go         # init, onboard commands
│   ├── memory.go          # memory read/write/list/search
│   ├── finding.go         # finding create/list/show/update/export
│   ├── agent.go           # agent list/show/prompt/create
│   ├── navigate.go        # list, find, read, search, symbols
│   ├── lsp.go             # lsp status/install/list
│   ├── think.go           # think collected/adherence/done/next/hypothesis
│   ├── dashboard.go       # dashboard server
│   ├── index.go           # index enable/build/update/status/watch/clear
│   └── semantic.go        # semantic search commands
├── internal/
│   ├── project/           # Project config, tech detection, onboarding
│   ├── memory/            # Memory store with bleve full-text search
│   ├── finding/           # Finding store and exporters (md, sarif, html, csv, json)
│   ├── agent/             # Agent registry, config, prompt generation
│   ├── navigate/          # File operations, LSP client
│   │   └── lsp/           # LSP protocol, server management
│   ├── think/             # Thinking prompt templates
│   ├── dashboard/         # Web dashboard server
│   ├── skill/             # Embedded skill installer (go:embed)
│   ├── chunk/             # Code chunking for semantic search
│   ├── embedding/         # Embedding providers (Ollama, OpenAI, Hugging Face)
│   ├── vectordb/          # Vector storage (HNSW + SQLite)
│   └── semantic/          # Semantic search engine
├── skills/                # Claude Code skills for using zrok
│   └── code-review/       # Code review orchestration skill
└── configs/               # External configuration files (planned)
    ├── agents/            # Agent YAML configs
    └── prompts/           # Prompt templates
```

## Building

```bash
go build -o zrok .
go test ./...
```

## Key Components

### Agent System (`internal/agent/`)
- `registry.go` - Built-in agent definitions (recon, security, guards, etc.)
- `config.go` - Agent configuration types
- `prompt.go` - Prompt generation with project context

### Memory Store (`internal/memory/`)
- `store.go` - YAML-based memory persistence in `.zrok/memories/`
- `index.go` - Bleve full-text search index
- Types: `context`, `pattern`, `stack`

### Finding Store (`internal/finding/`)
- `store.go` - YAML-based finding persistence in `.zrok/findings/`
- `export/` - Multiple export formats (markdown, SARIF, HTML, CSV, JSON)
- Severity levels: `critical`, `high`, `medium`, `low`, `info`

### Navigation (`internal/navigate/`)
- `lister.go` - Directory listing with depth control
- `finder.go` - Glob pattern file finding
- `reader.go` - File reading with line ranges
- `symbols.go` - Code symbol extraction
- `lsp/` - LSP client for accurate symbol extraction

### Semantic Search (`internal/semantic/`, `internal/chunk/`, `internal/embedding/`, `internal/vectordb/`)
- `chunk/` - LSP-based code chunking with regex fallback
- `embedding/` - Embedding providers (Ollama, OpenAI, Hugging Face)
- `vectordb/` - HNSW vector index with SQLite metadata
- `semantic/` - Search coordinator with multi-hop exploration

### Project Config (`internal/project/`)
- `config.go` - Project configuration in `.zrok/project.yaml`
- `detector.go` - Tech stack auto-detection
- `onboard.go` - Interactive and auto onboarding

## Adding New Features

### New Agent
1. Add agent definition in `internal/agent/registry.go`
2. Or create YAML in `configs/agents/` (when implemented)

### New Export Format
1. Create exporter in `internal/finding/export/`
2. Implement `Exporter` interface
3. Register in `export.go`

### New CLI Command
1. Create command file in `cmd/`
2. Add to root command in `cmd/root.go`

## Testing

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./internal/finding/...

# With coverage
go test -cover ./...
```

## Semantic Search

zrok includes semantic code search using vector embeddings. This enables natural language queries against the codebase.

### Setup
```bash
# Enable with Ollama (local, free)
zrok index enable --provider ollama
ollama pull nomic-embed-text  # If not already installed

# Or use Hugging Face (cloud, free tier)
export HF_API_KEY=your_key
zrok index enable --provider huggingface

# Or use OpenAI (cloud, paid)
export OPENAI_API_KEY=your_key
zrok index enable --provider openai

# Build the index
zrok index build
```

### Usage
```bash
zrok semantic "authentication middleware"     # Natural language search
zrok semantic "SQL injection" --multi-hop     # Explore related code
zrok semantic "error handling" --type function
zrok semantic related cmd/index.go            # Find related code
```

## Skills

The `skills/` directory contains Claude Code skills for using zrok. See `skills/code-review/SKILL.md` for the code review orchestration skill that spawns specialized subagents.
