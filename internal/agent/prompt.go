package agent

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/ihavespoons/zrok/internal/memory"
	"github.com/ihavespoons/zrok/internal/project"
)

// PromptData contains data for template rendering
type PromptData struct {
	AgentName        string
	ProjectName      string
	ProjectContext   string
	TechStack        string
	ToolDescriptions string
	Memories         map[string]string
	SensitiveAreas   string
}

// PromptGenerator generates prompts for agents
type PromptGenerator struct {
	project      *project.Project
	memoryStore  *memory.Store
}

// NewPromptGenerator creates a new prompt generator
func NewPromptGenerator(p *project.Project, ms *memory.Store) *PromptGenerator {
	return &PromptGenerator{
		project:     p,
		memoryStore: ms,
	}
}

// Generate generates a complete prompt for an agent
func (g *PromptGenerator) Generate(config *AgentConfig) (string, error) {
	data := g.buildPromptData(config)

	// Parse and execute template
	tmpl, err := template.New("prompt").Parse(config.PromptTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse prompt template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute prompt template: %w", err)
	}

	return buf.String(), nil
}

// GenerateWithContext generates a prompt with additional context
func (g *PromptGenerator) GenerateWithContext(config *AgentConfig, context string) (string, error) {
	prompt, err := g.Generate(config)
	if err != nil {
		return "", err
	}

	if context != "" {
		prompt += "\n\n## Additional Context\n" + context
	}

	return prompt, nil
}

// buildPromptData builds the data structure for template rendering
func (g *PromptGenerator) buildPromptData(config *AgentConfig) *PromptData {
	data := &PromptData{
		AgentName: config.Name,
		Memories:  make(map[string]string),
	}

	if g.project != nil && g.project.Config != nil {
		data.ProjectName = g.project.Config.Name
		data.ProjectContext = g.buildProjectContext()
		data.TechStack = g.buildTechStackDescription()
		data.SensitiveAreas = g.buildSensitiveAreasDescription()
	}

	// Load configured memories
	if g.memoryStore != nil {
		for _, memName := range config.ContextMemories {
			mem, err := g.memoryStore.ReadByName(memName)
			if err == nil {
				data.Memories[memName] = mem.Content
			}
		}
	}

	data.ToolDescriptions = g.buildToolDescriptions(config.ToolsAllowed)

	return data
}

// buildProjectContext builds a project context description
func (g *PromptGenerator) buildProjectContext() string {
	if g.project == nil || g.project.Config == nil {
		return ""
	}

	cfg := g.project.Config
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Project: %s\n", cfg.Name))
	if cfg.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", cfg.Description))
	}

	return b.String()
}

// buildTechStackDescription builds a tech stack description
func (g *PromptGenerator) buildTechStackDescription() string {
	if g.project == nil || g.project.Config == nil {
		return ""
	}

	stack := g.project.Config.TechStack
	var b strings.Builder

	if len(stack.Languages) > 0 {
		b.WriteString("Languages:\n")
		for _, lang := range stack.Languages {
			b.WriteString(fmt.Sprintf("- %s", lang.Name))
			if lang.Version != "" {
				b.WriteString(fmt.Sprintf(" (%s)", lang.Version))
			}
			if len(lang.Frameworks) > 0 {
				b.WriteString(fmt.Sprintf(": %s", strings.Join(lang.Frameworks, ", ")))
			}
			b.WriteString("\n")
		}
	}

	if len(stack.Databases) > 0 {
		b.WriteString(fmt.Sprintf("Databases: %s\n", strings.Join(stack.Databases, ", ")))
	}

	if len(stack.Auth) > 0 {
		b.WriteString(fmt.Sprintf("Auth: %s\n", strings.Join(stack.Auth, ", ")))
	}

	if len(stack.Infrastructure) > 0 {
		b.WriteString(fmt.Sprintf("Infrastructure: %s\n", strings.Join(stack.Infrastructure, ", ")))
	}

	return b.String()
}

// buildSensitiveAreasDescription builds a description of sensitive areas
func (g *PromptGenerator) buildSensitiveAreasDescription() string {
	if g.project == nil || g.project.Config == nil {
		return ""
	}

	areas := g.project.Config.SecurityScope.SensitiveAreas
	if len(areas) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("Sensitive Areas:\n")
	for _, area := range areas {
		b.WriteString(fmt.Sprintf("- %s: %s\n", area.Path, area.Reason))
	}

	return b.String()
}

// buildToolDescriptions builds descriptions of available tools
func (g *PromptGenerator) buildToolDescriptions(tools []string) string {
	toolDocs := map[string]string{
		"read": `**read** - Read file contents
  Usage: zrok read <file> [--lines N:M]
  Read source files to analyze code. Use --lines to read specific line ranges.`,

		"list": `**list** - List directory contents
  Usage: zrok list <dir> [--recursive] [--depth N]
  Explore project structure and find relevant files.`,

		"find": `**find** - Find files by pattern
  Usage: zrok find <pattern> [--type file|dir]
  Search for files matching a pattern (supports wildcards).`,

		"search": `**search** - Search file contents
  Usage: zrok search <pattern> [--regex]
  Search for patterns in file contents (grep-like functionality).`,

		"symbols": `**symbols** - Extract code symbols
  Usage: zrok symbols <file>
  Usage: zrok symbols find <name>
  Extract functions, classes, and other symbols from source files.`,

		"memory": `**memory** - Manage analysis memories
  Usage: zrok memory list [--type context|pattern|stack]
  Usage: zrok memory read <name>
  Usage: zrok memory write <name> --content "..."
  Store and retrieve information during analysis.`,

		"finding": `**finding** - Manage security findings
  Usage: zrok finding create --file <finding.yaml>
  Usage: zrok finding list [--severity high]
  Usage: zrok finding show <id>
  Create and manage security vulnerability findings.`,

		"think": `**think** - Structured thinking tools
  Usage: zrok think collected
  Usage: zrok think adherence
  Usage: zrok think done
  Usage: zrok think next
  Usage: zrok think hypothesis <context>
  Self-reflection tools for maintaining analysis quality.`,
	}

	var b strings.Builder
	b.WriteString("Available Tools:\n\n")

	for _, tool := range tools {
		if doc, ok := toolDocs[tool]; ok {
			b.WriteString(doc)
			b.WriteString("\n\n")
		}
	}

	return b.String()
}

// DefaultPromptTemplate returns a default prompt template
func DefaultPromptTemplate() string {
	return `You are {{.AgentName}}, a security analysis agent.

## Project Context
{{.ProjectContext}}

## Tech Stack
{{.TechStack}}

{{if .SensitiveAreas}}
## Sensitive Areas
{{.SensitiveAreas}}
{{end}}

## Available Tools
{{.ToolDescriptions}}

## Analysis Guidelines

1. **Be Systematic**: Work through the codebase methodically
2. **Document Everything**: Create memories for important discoveries
3. **Validate Findings**: Ensure findings are accurate before reporting
4. **Think Critically**: Use thinking tools to maintain quality

## Workflow

1. Start by understanding the codebase structure (list, find)
2. Identify potential vulnerability areas
3. Analyze suspicious code (read, search, symbols)
4. Document findings with evidence
5. Validate findings before finalizing
`
}
