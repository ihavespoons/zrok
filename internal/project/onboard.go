package project

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// OnboardingResult contains the results of the onboarding process
type OnboardingResult struct {
	Config   *ProjectConfig
	Memories []MemoryToCreate
	Agents   []string
	Warnings []string
}

// AgentOnboardingResult contains results for agent-assisted onboarding
// The AgentPrompt field will be populated by the caller (cmd/project.go)
// since generating it requires the agent package, which would create a cycle
type AgentOnboardingResult struct {
	Config      *ProjectConfig
	Memories    []MemoryToCreate
	AgentPrompt string
}

// MemoryToCreate represents a memory that should be created during onboarding
type MemoryToCreate struct {
	Name    string
	Type    string
	Content string
}

// Onboarder handles the project onboarding workflow
type Onboarder struct {
	project  *Project
	detector *Detector
	reader   *bufio.Reader
}

// NewOnboarder creates a new onboarder for a project
func NewOnboarder(project *Project) *Onboarder {
	return &Onboarder{
		project:  project,
		detector: NewDetector(project.RootPath),
		reader:   bufio.NewReader(os.Stdin),
	}
}

// RunAgent performs agent-assisted onboarding
// It does quick static detection, saves config, and prepares for recon-agent execution.
// The AgentPrompt field must be populated by the caller (to avoid import cycles).
func (o *Onboarder) RunAgent() (*AgentOnboardingResult, error) {
	result := &AgentOnboardingResult{
		Config: o.project.Config,
	}

	// Step 1: Quick static detection for baseline
	stack, err := o.detector.DetectAll()
	if err != nil {
		// Non-fatal, continue with empty stack
		stack = &TechStack{}
	}
	result.Config.TechStack = *stack

	// Step 2: Detect sensitive areas
	areas, err := o.detector.DetectSensitiveAreas()
	if err != nil {
		// Non-fatal, continue with empty areas
		areas = []SensitiveArea{}
	}
	result.Config.SecurityScope.SensitiveAreas = areas

	// Step 3: Save initial config
	if err := o.project.Save(); err != nil {
		return nil, fmt.Errorf("failed to save project config: %w", err)
	}

	// Step 4: Generate basic initial memories
	result.Memories = o.generateInitialMemories(result.Config)

	// Note: AgentPrompt must be populated by the caller using the agent package
	// This avoids import cycles between project -> agent -> memory -> project

	return result, nil
}

// RunAuto performs automatic onboarding without user interaction
func (o *Onboarder) RunAuto() (*OnboardingResult, error) {
	result := &OnboardingResult{
		Config: o.project.Config,
	}

	// Detect tech stack
	stack, err := o.detector.DetectAll()
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Warning during detection: %v", err))
	}
	result.Config.TechStack = *stack

	// Detect sensitive areas
	areas, err := o.detector.DetectSensitiveAreas()
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Warning during sensitive area detection: %v", err))
	}
	result.Config.SecurityScope.SensitiveAreas = areas

	// Generate initial memories
	result.Memories = o.generateInitialMemories(result.Config)

	// Suggest agents based on tech stack
	result.Agents = o.suggestAgents(result.Config)

	// Save updated config
	if err := o.project.Save(); err != nil {
		return nil, fmt.Errorf("failed to save project config: %w", err)
	}

	return result, nil
}

// RunWizard performs interactive onboarding with user prompts
func (o *Onboarder) RunWizard() (*OnboardingResult, error) {
	result := &OnboardingResult{
		Config: o.project.Config,
	}

	// Step 1: Project description
	fmt.Println("\n=== Project Onboarding Wizard ===")

	fmt.Print("Project description (brief): ")
	desc, _ := o.reader.ReadString('\n')
	result.Config.Description = strings.TrimSpace(desc)

	// Step 2: Auto-detect and confirm tech stack
	fmt.Println("\nDetecting tech stack...")
	stack, _ := o.detector.DetectAll()
	result.Config.TechStack = *stack

	fmt.Println("\nDetected technologies:")
	o.printTechStack(stack)

	fmt.Print("\nIs this correct? [Y/n]: ")
	confirm, _ := o.reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(confirm)) == "n" {
		// Allow manual modification
		result.Config.TechStack = o.editTechStack(stack)
	}

	// Step 3: Security scope
	fmt.Println("\nConfiguring security scope...")

	fmt.Print("Paths to include (comma-separated, empty for all): ")
	include, _ := o.reader.ReadString('\n')
	if strings.TrimSpace(include) != "" {
		result.Config.SecurityScope.IncludePaths = splitAndTrim(include)
	}

	fmt.Print("Paths to exclude (comma-separated): ")
	exclude, _ := o.reader.ReadString('\n')
	if strings.TrimSpace(exclude) != "" {
		result.Config.SecurityScope.ExcludePaths = append(
			result.Config.SecurityScope.ExcludePaths,
			splitAndTrim(exclude)...,
		)
	}

	// Step 4: Sensitive areas
	fmt.Println("\nDetecting sensitive areas...")
	areas, _ := o.detector.DetectSensitiveAreas()

	if len(areas) > 0 {
		fmt.Println("Detected sensitive areas:")
		for _, area := range areas {
			fmt.Printf("  - %s (%s)\n", area.Path, area.Reason)
		}
	}

	fmt.Print("\nAdd additional sensitive areas? [y/N]: ")
	addMore, _ := o.reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(addMore)) == "y" {
		areas = append(areas, o.addSensitiveAreas()...)
	}
	result.Config.SecurityScope.SensitiveAreas = areas

	// Step 5: Security concerns
	fmt.Println("\nAny specific security concerns or known vulnerabilities?")
	fmt.Print("(Enter to skip, or describe concerns): ")
	concerns, _ := o.reader.ReadString('\n')
	if concerns := strings.TrimSpace(concerns); concerns != "" {
		result.Memories = append(result.Memories, MemoryToCreate{
			Name:    "security_concerns",
			Type:    "context",
			Content: concerns,
		})
	}

	// Step 6: Compliance requirements
	fmt.Println("\nCompliance requirements:")
	fmt.Println("  1. None")
	fmt.Println("  2. PCI-DSS")
	fmt.Println("  3. HIPAA")
	fmt.Println("  4. SOC2")
	fmt.Println("  5. GDPR")
	fmt.Println("  6. Other")
	fmt.Print("Select (comma-separated numbers): ")
	compliance, _ := o.reader.ReadString('\n')
	if comp := parseCompliance(compliance); len(comp) > 0 {
		result.Memories = append(result.Memories, MemoryToCreate{
			Name:    "compliance_requirements",
			Type:    "context",
			Content: strings.Join(comp, ", "),
		})
	}

	// Generate initial memories
	result.Memories = append(result.Memories, o.generateInitialMemories(result.Config)...)

	// Suggest agents
	result.Agents = o.suggestAgents(result.Config)

	// Save config
	if err := o.project.Save(); err != nil {
		return nil, fmt.Errorf("failed to save project config: %w", err)
	}

	return result, nil
}

func (o *Onboarder) printTechStack(stack *TechStack) {
	if len(stack.Languages) > 0 {
		fmt.Println("  Languages:")
		for _, lang := range stack.Languages {
			if lang.Version != "" {
				fmt.Printf("    - %s (%s)\n", lang.Name, lang.Version)
			} else {
				fmt.Printf("    - %s\n", lang.Name)
			}
			if len(lang.Frameworks) > 0 {
				fmt.Printf("      Frameworks: %s\n", strings.Join(lang.Frameworks, ", "))
			}
		}
	}
	if len(stack.Databases) > 0 {
		fmt.Printf("  Databases: %s\n", strings.Join(stack.Databases, ", "))
	}
	if len(stack.Infrastructure) > 0 {
		fmt.Printf("  Infrastructure: %s\n", strings.Join(stack.Infrastructure, ", "))
	}
	if len(stack.Auth) > 0 {
		fmt.Printf("  Auth: %s\n", strings.Join(stack.Auth, ", "))
	}
}

func (o *Onboarder) editTechStack(stack *TechStack) TechStack {
	// Simplified editor - in a real implementation this would be more interactive
	fmt.Println("\nManual tech stack editing:")
	fmt.Println("(Enter values as comma-separated lists)")

	fmt.Printf("Languages [%s]: ", formatLanguages(stack.Languages))
	input, _ := o.reader.ReadString('\n')
	if strings.TrimSpace(input) != "" {
		stack.Languages = parseLanguages(input)
	}

	fmt.Printf("Databases [%s]: ", strings.Join(stack.Databases, ", "))
	input, _ = o.reader.ReadString('\n')
	if strings.TrimSpace(input) != "" {
		stack.Databases = splitAndTrim(input)
	}

	fmt.Printf("Infrastructure [%s]: ", strings.Join(stack.Infrastructure, ", "))
	input, _ = o.reader.ReadString('\n')
	if strings.TrimSpace(input) != "" {
		stack.Infrastructure = splitAndTrim(input)
	}

	fmt.Printf("Auth mechanisms [%s]: ", strings.Join(stack.Auth, ", "))
	input, _ = o.reader.ReadString('\n')
	if strings.TrimSpace(input) != "" {
		stack.Auth = splitAndTrim(input)
	}

	return *stack
}

func (o *Onboarder) addSensitiveAreas() []SensitiveArea {
	var areas []SensitiveArea
	fmt.Println("Enter sensitive areas (empty line to finish):")
	for {
		fmt.Print("Path: ")
		path, _ := o.reader.ReadString('\n')
		path = strings.TrimSpace(path)
		if path == "" {
			break
		}
		fmt.Print("Reason: ")
		reason, _ := o.reader.ReadString('\n')
		areas = append(areas, SensitiveArea{
			Path:   path,
			Reason: strings.TrimSpace(reason),
		})
	}
	return areas
}

func (o *Onboarder) generateInitialMemories(config *ProjectConfig) []MemoryToCreate {
	var memories []MemoryToCreate

	// Project overview memory
	var overview strings.Builder
	fmt.Fprintf(&overview, "# Project: %s\n\n", config.Name)
	if config.Description != "" {
		fmt.Fprintf(&overview, "## Description\n%s\n\n", config.Description)
	}
	overview.WriteString("## Tech Stack\n")
	for _, lang := range config.TechStack.Languages {
		fmt.Fprintf(&overview, "- %s", lang.Name)
		if lang.Version != "" {
			fmt.Fprintf(&overview, " (%s)", lang.Version)
		}
		if len(lang.Frameworks) > 0 {
			fmt.Fprintf(&overview, ": %s", strings.Join(lang.Frameworks, ", "))
		}
		overview.WriteString("\n")
	}

	memories = append(memories, MemoryToCreate{
		Name:    "project_overview",
		Type:    "context",
		Content: overview.String(),
	})

	// Tech stack specific memories
	for _, lang := range config.TechStack.Languages {
		for _, framework := range lang.Frameworks {
			memories = append(memories, MemoryToCreate{
				Name:    fmt.Sprintf("%s_%s_patterns", lang.Name, framework),
				Type:    "stack",
				Content: fmt.Sprintf("# %s %s Security Patterns\n\n(To be populated during analysis)", lang.Name, framework),
			})
		}
	}

	return memories
}

func (o *Onboarder) suggestAgents(config *ProjectConfig) []string {
	// Core agents always suggested
	agents := []string{
		"recon-agent",      // Always run reconnaissance first
		"architecture-agent", // Code structure and patterns
		"guards-agent",     // Validation and defensive coding
		"validation-agent", // Validate and prioritize findings
	}

	// Content handling if web frameworks detected
	hasWebFramework := false
	for _, lang := range config.TechStack.Languages {
		for _, fw := range lang.Frameworks {
			fwLower := strings.ToLower(fw)
			if strings.Contains(fwLower, "rails") ||
				strings.Contains(fwLower, "django") ||
				strings.Contains(fwLower, "express") ||
				strings.Contains(fwLower, "gin") ||
				strings.Contains(fwLower, "spring") ||
				strings.Contains(fwLower, "react") ||
				strings.Contains(fwLower, "vue") {
				hasWebFramework = true
				break
			}
		}
	}
	if hasWebFramework {
		agents = append(agents, "content-agent")
	}

	// Dependencies agent for projects with package managers
	if len(config.TechStack.Languages) > 0 {
		agents = append(agents, "dependencies-agent")
	}

	// Logging agent for production systems
	if len(config.TechStack.Infrastructure) > 0 {
		agents = append(agents, "logging-agent")
	}

	// References agent for external integrations
	if len(config.TechStack.Databases) > 0 || len(config.TechStack.Infrastructure) > 0 {
		agents = append(agents, "references-agent")
	}

	// Security agent for auth/authz/crypto concerns
	if len(config.TechStack.Auth) > 0 || len(config.TechStack.Databases) > 0 {
		agents = append(agents, "security-agent")
	}

	return agents
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func formatLanguages(langs []Language) string {
	var names []string
	for _, l := range langs {
		names = append(names, l.Name)
	}
	return strings.Join(names, ", ")
}

func parseLanguages(input string) []Language {
	var langs []Language
	for _, name := range splitAndTrim(input) {
		langs = append(langs, Language{Name: name})
	}
	return langs
}

func parseCompliance(input string) []string {
	complianceMap := map[string]string{
		"1": "",
		"2": "PCI-DSS",
		"3": "HIPAA",
		"4": "SOC2",
		"5": "GDPR",
		"6": "Other",
	}

	var result []string
	for _, num := range splitAndTrim(input) {
		if comp, ok := complianceMap[num]; ok && comp != "" {
			result = append(result, comp)
		}
	}
	return result
}
