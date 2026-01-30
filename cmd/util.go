package cmd

import (
	"fmt"
	"strings"

	"github.com/ihavespoons/zrok/internal/agent"
	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/memory"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/spf13/cobra"
)

// instructionsCmd represents the instructions command
var instructionsCmd = &cobra.Command{
	Use:   "instructions",
	Short: "Print onboarding instructions for LLM",
	Long:  `Print comprehensive instructions for using zrok with an LLM agent.`,
	Run: func(cmd *cobra.Command, args []string) {
		instructions := `# zrok - Security Code Review CLI

zrok is a read-only CLI tool designed for LLM-assisted security code review.
All commands output JSON when --json flag is provided.

## Quick Start

1. Initialize a project:
   zrok init

2. Auto-detect tech stack:
   zrok onboard --auto

3. Start analyzing:
   zrok read <file>
   zrok search <pattern>
   zrok symbols <file>

4. Document findings:
   zrok finding create --file finding.yaml

5. Export results:
   zrok finding export --format sarif

## Command Reference

### Project Management
- zrok init                  Initialize .zrok in current directory
- zrok activate [path]       Activate a project
- zrok config [get|set]      View/modify project config
- zrok onboard --auto        Auto-detect tech stack
- zrok onboard --wizard      Interactive setup
- zrok status                Show project status

### Code Navigation (Read-Only)
- zrok read <file>           Read file contents
  --lines N:M                Read specific line range
- zrok list <dir>            List directory contents
  --recursive, -r            List recursively
  --tree, -t                 Display as tree
- zrok find <pattern>        Find files by pattern
  --type file|dir            Filter by type
- zrok search <pattern>      Search file contents
  --regex, -r                Use regex patterns
  --context N, -C            Show N lines of context
- zrok symbols <file>        Extract code symbols
- zrok symbols find <name>   Find symbol globally
- zrok symbols refs <name>   Find references to symbol

### Memory Management
- zrok memory list           List all memories
  --type context|pattern|stack
- zrok memory read <name>    Read a memory
- zrok memory write <name>   Create/update memory
  --content "..."            Memory content
  --file <path>              Read content from file
  --type context             Memory type
- zrok memory delete <name>  Delete a memory
- zrok memory search <query> Search memories

### Finding Management
- zrok finding create        Create a finding
  --file finding.yaml        From YAML file
- zrok finding list          List findings
  --severity high            Filter by severity
  --status open              Filter by status
- zrok finding show <id>     Show finding details
- zrok finding update <id>   Update a finding
  --status confirmed         Update status
- zrok finding export        Export findings
  --format sarif|json|md|html|csv
  --output <file>            Output file
- zrok finding stats         Show statistics
- zrok finding delete <id>   Delete a finding

### Thinking Tools
- zrok think collected       Evaluate collected info
- zrok think adherence       Check task adherence
- zrok think done            Assess task completion
- zrok think next            Suggest next steps
- zrok think hypothesis      Generate hypotheses
- zrok think validate <id>   Validate a finding

### Agent Management
- zrok agent list            List available agents
- zrok agent show <name>     Show agent config
- zrok agent prompt <name>   Generate agent prompt
- zrok agent generate        Generate recommended agents

### Dashboard
- zrok dashboard             Start web dashboard
  --port 8080                Dashboard port

## Finding YAML Format

title: "SQL Injection in user search"
severity: high              # critical, high, medium, low, info
confidence: high            # high, medium, low
status: open                # open, confirmed, false_positive, fixed
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
    query := fmt.Sprintf("SELECT * FROM users WHERE name LIKE '%%%s%%'", input)
description: |
  User input is directly concatenated into SQL query.
impact: |
  Attacker can extract, modify, or delete database contents.
remediation: |
  Use parameterized queries or prepared statements.
evidence:
  - type: code_path
    description: "Input flows from HTTP param to SQL query"
    trace: ["handlers/user.go:23", "services/user.go:45"]
references:
  - https://owasp.org/www-community/attacks/SQL_Injection
tags: [injection, database, owasp-top-10]
created_by: "injection-agent"

## Workflow Example

1. Initialize and onboard:
   zrok init && zrok onboard --auto

2. Get agent prompt:
   zrok agent prompt injection-agent

3. Explore codebase:
   zrok list --tree
   zrok find "*.go"
   zrok search "sql" --context 3

4. Analyze files:
   zrok read src/db/queries.go
   zrok symbols src/db/queries.go

5. Document findings:
   echo "..." > finding.yaml
   zrok finding create --file finding.yaml

6. Self-check:
   zrok think adherence "Find SQL injection"
   zrok think done "SQL injection analysis"

7. Export:
   zrok finding export --format sarif --output report.sarif
`

		if jsonOutput {
			outputJSON(map[string]string{"instructions": instructions})
		} else {
			fmt.Print(instructions)
		}
	},
}

// exportContextCmd represents the export-context command
var exportContextCmd = &cobra.Command{
	Use:   "export-context",
	Short: "Export full context for conversation handoff",
	Long:  `Export the complete project context including config, memories, and findings for handing off to a new conversation.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		// Collect all context
		context := map[string]interface{}{
			"project": p.Config,
			"path":    p.RootPath,
		}

		// Memories
		memStore := memory.NewStore(p)
		if memList, err := memStore.List(""); err == nil {
			context["memories"] = memList.Memories
		}

		// Findings
		findingStore := finding.NewStore(p)
		if findingList, err := findingStore.List(nil); err == nil {
			context["findings"] = findingList.Findings
		}

		// Stats
		if stats, err := findingStore.Stats(); err == nil {
			context["finding_stats"] = stats
		}

		// Available agents
		builtinAgents := agent.GetBuiltinAgents()
		var agentNames []string
		for _, a := range builtinAgents {
			agentNames = append(agentNames, a.Name)
		}
		context["available_agents"] = agentNames

		if jsonOutput {
			outputJSON(context)
		} else {
			// Text output
			fmt.Printf("# Context Export for %s\n\n", p.Config.Name)
			fmt.Printf("Path: %s\n\n", p.RootPath)

			// Tech stack
			fmt.Println("## Tech Stack")
			for _, lang := range p.Config.TechStack.Languages {
				fmt.Printf("- %s", lang.Name)
				if len(lang.Frameworks) > 0 {
					fmt.Printf(": %s", strings.Join(lang.Frameworks, ", "))
				}
				fmt.Println()
			}
			fmt.Println()

			// Memories
			if mems, ok := context["memories"].([]memory.Memory); ok && len(mems) > 0 {
				fmt.Println("## Memories")
				for _, m := range mems {
					fmt.Printf("### %s (%s)\n", m.Name, m.Type)
					fmt.Println(m.Content)
					fmt.Println()
				}
			}

			// Findings summary
			if stats, ok := context["finding_stats"].(*finding.FindingStats); ok {
				fmt.Println("## Findings Summary")
				fmt.Printf("Total: %d\n", stats.Total)
				for sev, count := range stats.BySeverity {
					fmt.Printf("- %s: %d\n", sev, count)
				}
				fmt.Println()
			}

			// Findings
			if findings, ok := context["findings"].([]finding.Finding); ok && len(findings) > 0 {
				fmt.Println("## Findings")
				for _, f := range findings {
					fmt.Printf("### [%s] %s - %s\n", f.ID, f.Title, f.Severity)
					fmt.Printf("Location: %s:%d\n", f.Location.File, f.Location.LineStart)
					if f.Description != "" {
						fmt.Printf("Description: %s\n", f.Description)
					}
					fmt.Println()
				}
			}

			fmt.Println("## Available Agents")
			fmt.Println(strings.Join(agentNames, ", "))
		}
	},
}

func init() {
	rootCmd.AddCommand(instructionsCmd)
	rootCmd.AddCommand(exportContextCmd)
}
