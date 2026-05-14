package cmd

import (
	"fmt"
	"strings"

	"github.com/ihavespoons/quokka/internal/agent"
	"github.com/ihavespoons/quokka/internal/finding"
	"github.com/ihavespoons/quokka/internal/memory"
	"github.com/ihavespoons/quokka/internal/project"
	"github.com/spf13/cobra"
)

// instructionsCmd represents the instructions command
var instructionsCmd = &cobra.Command{
	Use:   "instructions",
	Short: "Print onboarding instructions for LLM",
	Long:  `Print comprehensive instructions for using quokka with an LLM agent.`,
	Run: func(cmd *cobra.Command, args []string) {
		instructions := `# quokka - Security Code Review CLI

quokka is a read-only CLI tool designed for LLM-assisted security code review.
All commands output JSON when --json flag is provided.

## Quick Start

1. Initialize a project:
   quokka init

2. Auto-detect tech stack:
   quokka onboard --auto

3. Start analyzing:
   quokka read <file>
   quokka search <pattern>
   quokka symbols <file>

4. Document findings:
   quokka finding create --file finding.yaml

5. Export results:
   quokka finding export --format sarif

## Command Reference

### Project Management
- quokka init                  Initialize .quokka in current directory
- quokka activate [path]       Activate a project
- quokka config [get|set]      View/modify project config
- quokka onboard --auto        Auto-detect tech stack
- quokka onboard --wizard      Interactive setup
- quokka status                Show project status

### Code Navigation (Read-Only)
- quokka read <file>           Read file contents
  --lines N:M                Read specific line range
- quokka list <dir>            List directory contents
  --recursive, -r            List recursively
  --tree, -t                 Display as tree
- quokka find <pattern>        Find files by pattern
  --type file|dir            Filter by type
- quokka search <pattern>      Search file contents
  --regex, -r                Use regex patterns
  --context N, -C            Show N lines of context
- quokka symbols <file>        Extract code symbols
- quokka symbols find <name>   Find symbol globally
- quokka symbols refs <name>   Find references to symbol

### Memory Management
- quokka memory list           List all memories
  --type context|pattern|stack
- quokka memory read <name>    Read a memory
- quokka memory write <name>   Create/update memory
  --content "..."            Memory content
  --file <path>              Read content from file
  --type context             Memory type
- quokka memory delete <name>  Delete a memory
- quokka memory search <query> Search memories

### Finding Management
- quokka finding create        Create a finding
  --file finding.yaml        From YAML file
- quokka finding list          List findings
  --severity high            Filter by severity
  --status open              Filter by status
- quokka finding show <id>     Show finding details
- quokka finding update <id>   Update a finding
  --status confirmed         Update status
- quokka finding export        Export findings
  --format sarif|json|md|html|csv
  --output <file>            Output file
- quokka finding stats         Show statistics
- quokka finding delete <id>   Delete a finding

### Thinking Tools
- quokka think collected       Evaluate collected info
- quokka think adherence       Check task adherence
- quokka think done            Assess task completion
- quokka think next            Suggest next steps
- quokka think hypothesis      Generate hypotheses
- quokka think validate <id>   Validate a finding

### Agent Management
- quokka agent list            List available agents
- quokka agent show <name>     Show agent config
- quokka agent prompt <name>   Generate agent prompt
- quokka agent generate        Generate recommended agents

### Dashboard
- quokka dashboard             Start web dashboard
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
   quokka init && quokka onboard --auto

2. Get agent prompt:
   quokka agent prompt injection-agent

3. Explore codebase:
   quokka list --tree
   quokka find "*.go"
   quokka search "sql" --context 3

4. Analyze files:
   quokka read src/db/queries.go
   quokka symbols src/db/queries.go

5. Document findings:
   echo "..." > finding.yaml
   quokka finding create --file finding.yaml

6. Self-check:
   quokka think adherence "Find SQL injection"
   quokka think done "SQL injection analysis"

7. Export:
   quokka finding export --format sarif --output report.sarif
`

		if jsonOutput {
			if err := outputJSON(map[string]string{"instructions": instructions}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
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
			if err := outputJSON(context); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
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
