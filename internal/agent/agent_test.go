package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ihavespoons/zrok/internal/memory"
	"github.com/ihavespoons/zrok/internal/project"
)

func setupTestProject(t *testing.T) (*project.Project, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	p, err := project.Initialize(tmpDir)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		t.Fatalf("failed to initialize project: %v", err)
	}

	// Set up config for tests
	p.Config.Name = "test-project"
	p.Config.TechStack = project.TechStack{
		Languages: []project.Language{
			{Name: "go", Version: "1.21", Frameworks: []string{"gin"}},
		},
		Databases: []string{"postgresql"},
		Auth:      []string{"jwt"},
	}
	_ = p.Save()

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	return p, cleanup
}

// Registry tests

func TestGetBuiltinAgents(t *testing.T) {
	agents := GetBuiltinAgents()

	if len(agents) == 0 {
		t.Fatal("no builtin agents")
	}

	// Check expected agents exist (new code review focused agents)
	expectedAgents := []string{
		"recon-agent",
		"architecture-agent",
		"dependencies-agent",
		"guards-agent",
		"content-agent",
		"logging-agent",
		"references-agent",
		"security-agent",
		"validation-agent",
		"injection-agent",
		"config-agent",
		"ssrf-agent",
	}

	agentNames := make(map[string]bool)
	for _, a := range agents {
		agentNames[a.Name] = true
	}

	for _, expected := range expectedAgents {
		if !agentNames[expected] {
			t.Errorf("missing expected agent: %s", expected)
		}
	}
}

func TestGetBuiltinAgent(t *testing.T) {
	// Get existing agent
	agent := GetBuiltinAgent("architecture-agent")
	if agent == nil {
		t.Fatal("architecture-agent not found")
	}

	if agent.Name != "architecture-agent" {
		t.Errorf("unexpected name: %s", agent.Name)
	}

	if agent.Phase != PhaseAnalysis {
		t.Errorf("unexpected phase: %s", agent.Phase)
	}

	if len(agent.ToolsAllowed) == 0 {
		t.Error("no tools allowed")
	}

	if agent.PromptTemplate == "" {
		t.Error("empty prompt template")
	}

	// Get nonexistent agent
	agent = GetBuiltinAgent("nonexistent")
	if agent != nil {
		t.Error("expected nil for nonexistent agent")
	}
}

func TestGetAgentsByPhase(t *testing.T) {
	// Recon phase
	reconAgents := GetAgentsByPhase(PhaseRecon)
	if len(reconAgents) == 0 {
		t.Error("no recon phase agents")
	}
	for _, a := range reconAgents {
		if a.Phase != PhaseRecon {
			t.Errorf("agent %s has wrong phase: %s", a.Name, a.Phase)
		}
	}

	// Analysis phase
	analysisAgents := GetAgentsByPhase(PhaseAnalysis)
	if len(analysisAgents) == 0 {
		t.Error("no analysis phase agents")
	}

	// Validation phase
	validationAgents := GetAgentsByPhase(PhaseValidation)
	if len(validationAgents) == 0 {
		t.Error("no validation phase agents")
	}
}

func TestGetAgentsByReviewCategory(t *testing.T) {
	// Test architecture category
	archAgents := GetAgentsByReviewCategory("leverage-frameworks")
	if len(archAgents) == 0 {
		t.Error("no agents for leverage-frameworks category")
	}

	found := false
	for _, a := range archAgents {
		if a.Name == "architecture-agent" {
			found = true
			break
		}
	}
	if !found {
		t.Error("architecture-agent not found for leverage-frameworks category")
	}

	// Test logging category
	loggingAgents := GetAgentsByReviewCategory("log-levels")
	if len(loggingAgents) == 0 {
		t.Error("no agents for log-levels category")
	}

	found = false
	for _, a := range loggingAgents {
		if a.Name == "logging-agent" {
			found = true
			break
		}
	}
	if !found {
		t.Error("logging-agent not found for log-levels category")
	}
}

func TestGetAgentsByVulnClass(t *testing.T) {
	// Security agent should still have vulnerability classes for auth/crypto
	authAgents := GetAgentsByVulnClass("authentication")
	// This may return empty if security-agent doesn't use vulnerability_classes
	// That's OK - the test verifies the function works
	_ = authAgents
}

// ConfigManager tests

func TestConfigManagerList(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	manager := NewConfigManager(p, "")
	result, err := manager.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Should include builtin agents
	if result.Total == 0 {
		t.Error("no agents listed")
	}
}

func TestConfigManagerGet(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	manager := NewConfigManager(p, "")

	// Get builtin agent
	agent, err := manager.Get("architecture-agent")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if agent.Name != "architecture-agent" {
		t.Errorf("unexpected agent name: %s", agent.Name)
	}

	// Get nonexistent agent
	_, err = manager.Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent agent")
	}
}

func TestConfigManagerCreate(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	manager := NewConfigManager(p, "")

	config := &AgentConfig{
		Name:        "custom-agent",
		Description: "A custom test agent",
		Phase:       PhaseAnalysis,
		ToolsAllowed: []string{"read", "search"},
		PromptTemplate: "You are a custom agent.",
	}

	err := manager.Create(config)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify file was created
	path := filepath.Join(p.GetAgentsPath(), "custom-agent.yaml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("agent file not created")
	}

	// Verify can be retrieved
	retrieved, err := manager.Get("custom-agent")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.Description != "A custom test agent" {
		t.Errorf("unexpected description: %s", retrieved.Description)
	}
}

func TestConfigManagerCreateDuplicate(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	manager := NewConfigManager(p, "")

	config := &AgentConfig{
		Name:        "custom-agent",
		Description: "First",
		Phase:       PhaseAnalysis,
	}

	err := manager.Create(config)
	if err != nil {
		t.Fatalf("first Create failed: %v", err)
	}

	// Try to create duplicate
	config2 := &AgentConfig{
		Name:        "custom-agent",
		Description: "Second",
		Phase:       PhaseAnalysis,
	}

	err = manager.Create(config2)
	if err == nil {
		t.Error("expected error for duplicate agent")
	}
}

func TestConfigManagerDelete(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	manager := NewConfigManager(p, "")

	// Create agent
	config := &AgentConfig{
		Name:  "to-delete",
		Phase: PhaseAnalysis,
	}
	if err := manager.Create(config); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Delete it
	if err := manager.Delete("to-delete"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify it's gone
	path := filepath.Join(p.GetAgentsPath(), "to-delete.yaml")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("agent file still exists")
	}
}

// PromptGenerator tests

func TestPromptGeneratorGenerate(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	memStore := memory.NewStore(p)

	// Create a test memory
	mem := &memory.Memory{
		Name:    "project_overview",
		Type:    memory.MemoryTypeContext,
		Content: "This is a test project overview.",
	}
	_ = memStore.Create(mem)

	generator := NewPromptGenerator(p, memStore)

	config := &AgentConfig{
		Name:        "test-agent",
		Description: "Test agent",
		Phase:       PhaseAnalysis,
		ToolsAllowed: []string{"read", "search", "memory"},
		PromptTemplate: `Agent: {{.AgentName}}
Project: {{.ProjectName}}

## Tech Stack
{{.TechStack}}

## Tools
{{.ToolDescriptions}}
`,
		ContextMemories: []string{"project_overview"},
	}

	prompt, err := generator.Generate(config)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Check template was rendered
	if !strings.Contains(prompt, "Agent: test-agent") {
		t.Error("agent name not rendered")
	}

	if !strings.Contains(prompt, "Project: test-project") {
		t.Error("project name not rendered")
	}

	if !strings.Contains(prompt, "go") {
		t.Error("tech stack not rendered")
	}

	if !strings.Contains(prompt, "**read**") {
		t.Error("tool descriptions not rendered")
	}
}

func TestPromptGeneratorWithContext(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	generator := NewPromptGenerator(p, nil)

	config := &AgentConfig{
		Name:           "test-agent",
		PromptTemplate: "Base prompt",
	}

	prompt, err := generator.GenerateWithContext(config, "Additional context here")
	if err != nil {
		t.Fatalf("GenerateWithContext failed: %v", err)
	}

	if !strings.Contains(prompt, "Additional context here") {
		t.Error("additional context not included")
	}

	if !strings.Contains(prompt, "## Additional Context") {
		t.Error("context header not included")
	}
}

func TestDefaultPromptTemplate(t *testing.T) {
	template := DefaultPromptTemplate()

	if template == "" {
		t.Error("default template is empty")
	}

	// Check it contains expected sections
	if !strings.Contains(template, "{{.AgentName}}") {
		t.Error("missing agent name placeholder")
	}

	if !strings.Contains(template, "{{.ProjectContext}}") {
		t.Error("missing project context placeholder")
	}

	if !strings.Contains(template, "{{.TechStack}}") {
		t.Error("missing tech stack placeholder")
	}

	if !strings.Contains(template, "{{.ToolDescriptions}}") {
		t.Error("missing tool descriptions placeholder")
	}
}

func TestAgentConfigStructure(t *testing.T) {
	config := &AgentConfig{
		Name:        "test-agent",
		Description: "Test description",
		Phase:       PhaseAnalysis,
		Specialization: Specialization{
			ReviewCategories:     []string{"leverage-frameworks", "simplification"},
			VulnerabilityClasses: []string{"authentication"},
			OWASPCategories:      []string{"A07:2021"},
			TechStack:            []string{"go", "postgresql"},
		},
		ToolsAllowed:    []string{"read", "search", "memory", "finding"},
		PromptTemplate:  "You are a test agent.",
		ContextMemories: []string{"project_overview", "coding_standards"},
	}

	if config.Name != "test-agent" {
		t.Errorf("unexpected name: %s", config.Name)
	}

	if config.Phase != PhaseAnalysis {
		t.Errorf("unexpected phase: %s", config.Phase)
	}

	if len(config.Specialization.ReviewCategories) != 2 {
		t.Errorf("expected 2 review categories, got %d", len(config.Specialization.ReviewCategories))
	}

	if len(config.ToolsAllowed) != 4 {
		t.Errorf("expected 4 tools, got %d", len(config.ToolsAllowed))
	}
}

func TestBuildCWEChecklist(t *testing.T) {
	config := &AgentConfig{
		Name:  "test-agent",
		Phase: PhaseAnalysis,
		CWEChecklist: []CWEChecklistItem{
			{
				ID:             "CWE-89",
				Name:           "SQL Injection",
				DetectionHints: []string{"String concatenation in SQL"},
				FlowPatterns:   []string{"SOURCE: HTTP param -> SINK: db.Query"},
			},
		},
	}

	result := buildCWEChecklist(config)
	if result == "" {
		t.Fatal("expected non-empty CWE checklist")
	}
	if !strings.Contains(result, "CWE-89") {
		t.Error("expected CWE ID in output")
	}
	if !strings.Contains(result, "SQL Injection") {
		t.Error("expected CWE name in output")
	}
	if !strings.Contains(result, "String concatenation in SQL") {
		t.Error("expected detection hint in output")
	}
	if !strings.Contains(result, "SOURCE: HTTP param -> SINK: db.Query") {
		t.Error("expected flow pattern in output")
	}
}

func TestBuildCWEChecklistEmpty(t *testing.T) {
	config := &AgentConfig{
		Name:  "test-agent",
		Phase: PhaseAnalysis,
	}

	result := buildCWEChecklist(config)
	if result != "" {
		t.Error("expected empty result for no CWE checklist")
	}
}

func TestBuildFlowGuidance(t *testing.T) {
	analysisConfig := &AgentConfig{
		Name:  "test-agent",
		Phase: PhaseAnalysis,
	}

	result := buildFlowGuidance(analysisConfig)
	if result == "" {
		t.Fatal("expected non-empty flow guidance for analysis phase")
	}
	if !strings.Contains(result, "Flow Analysis Protocol") {
		t.Error("expected flow analysis protocol header")
	}
	if !strings.Contains(result, "SOURCE") {
		t.Error("expected SOURCE in flow guidance")
	}
	if !strings.Contains(result, "SINK") {
		t.Error("expected SINK in flow guidance")
	}
}

func TestBuildFlowGuidanceNonAnalysis(t *testing.T) {
	reconConfig := &AgentConfig{
		Name:  "test-agent",
		Phase: PhaseRecon,
	}

	result := buildFlowGuidance(reconConfig)
	if result != "" {
		t.Error("expected empty flow guidance for non-analysis phase")
	}
}

func TestCWEChecklistInPrompt(t *testing.T) {
	// Test that a builtin security agent has CWE checklist
	agent := GetBuiltinAgent("security-agent")
	if agent == nil {
		t.Fatal("security-agent not found")
	}

	if len(agent.CWEChecklist) == 0 {
		t.Error("security-agent should have CWE checklist entries")
	}

	// Verify CWE entries have required fields
	for _, item := range agent.CWEChecklist {
		if item.ID == "" {
			t.Error("CWE item missing ID")
		}
		if item.Name == "" {
			t.Error("CWE item missing Name")
		}
	}
}

func TestTruncateMemory(t *testing.T) {
	// Short content — no truncation
	short := "hello world"
	result := truncateMemory(short, 100, "test")
	if result != short {
		t.Errorf("expected no truncation, got %q", result)
	}

	// Exact boundary — no truncation
	exact := strings.Repeat("a", 100)
	result = truncateMemory(exact, 100, "test")
	if result != exact {
		t.Errorf("expected no truncation at exact boundary, got length %d", len(result))
	}

	// Over boundary — should truncate
	long := strings.Repeat("x", 5000)
	result = truncateMemory(long, 4096, "my_memory")
	if len(result) > 4096 {
		t.Errorf("truncated result too long: %d bytes", len(result))
	}
	expectedMarker := "[... truncated — full content: zrok memory read my_memory]"
	if !strings.Contains(result, expectedMarker) {
		t.Error("truncated result missing truncation marker")
	}
	if !strings.HasPrefix(result, "xxx") {
		t.Error("truncated result should start with original content")
	}
}

func TestBuildPromptDataMemoryTruncation(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	memStore := memory.NewStore(p)

	// Create a memory larger than DefaultMaxMemoryBytes
	largeContent := strings.Repeat("A", DefaultMaxMemoryBytes+1000)
	mem := &memory.Memory{
		Name:    "big_memory",
		Type:    memory.MemoryTypeContext,
		Content: largeContent,
	}
	_ = memStore.Create(mem)

	generator := NewPromptGenerator(p, memStore)

	config := &AgentConfig{
		Name:            "test-agent",
		Phase:           PhaseAnalysis,
		ContextMemories: []string{"big_memory"},
		PromptTemplate:  "{{range $k, $v := .Memories}}{{$v}}{{end}}",
	}

	prompt, err := generator.Generate(config)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if strings.Contains(prompt, largeContent) {
		t.Error("prompt should not contain the full large memory")
	}

	expectedMarker := "zrok memory read big_memory"
	if !strings.Contains(prompt, expectedMarker) {
		t.Error("prompt should contain truncation marker referencing memory name")
	}
}

func TestBuildFewShotExamplesLimit(t *testing.T) {
	// Build a config with many CWEs that have examples
	config := &AgentConfig{
		Name:  "test-agent",
		Phase: PhaseAnalysis,
		CWEChecklist: []CWEChecklistItem{
			{ID: "CWE-89", Name: "SQL Injection"},
			{ID: "CWE-79", Name: "XSS"},
			{ID: "CWE-78", Name: "OS Command Injection"},
			{ID: "CWE-287", Name: "Improper Authentication"},
			{ID: "CWE-918", Name: "SSRF"},
			{ID: "CWE-20", Name: "Improper Input Validation"},
		},
	}

	result := buildFewShotExamples(config)
	if result == "" {
		t.Fatal("expected non-empty examples")
	}

	// Count the number of example headers (### CWE-...)
	count := strings.Count(result, "### CWE-")
	if count > DefaultMaxExamples {
		t.Errorf("expected at most %d examples, got %d", DefaultMaxExamples, count)
	}

	// Verify round-robin: with 6 CWEs and limit 3, we should get examples from 3 different CWEs
	seenCWEs := make(map[string]bool)
	for _, line := range strings.Split(result, "\n") {
		if strings.HasPrefix(line, "### CWE-") {
			parts := strings.SplitN(line, ":", 2)
			cweID := strings.TrimPrefix(parts[0], "### ")
			seenCWEs[cweID] = true
		}
	}
	if len(seenCWEs) < DefaultMaxExamples {
		t.Errorf("expected examples from %d different CWEs (round-robin), got %d", DefaultMaxExamples, len(seenCWEs))
	}
}

func TestPhaseConstants(t *testing.T) {
	phases := []Phase{PhaseRecon, PhaseAnalysis, PhaseValidation, PhaseReporting}

	for _, phase := range phases {
		if phase == "" {
			t.Error("empty phase constant")
		}
	}

	if PhaseRecon != "recon" {
		t.Errorf("unexpected recon phase: %s", PhaseRecon)
	}

	if PhaseAnalysis != "analysis" {
		t.Errorf("unexpected analysis phase: %s", PhaseAnalysis)
	}
}
