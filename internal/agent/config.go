package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ihavespoons/zrok/internal/project"
	"gopkg.in/yaml.v3"
)

// Phase represents an analysis phase
type Phase string

const (
	PhaseRecon      Phase = "recon"
	PhaseAnalysis   Phase = "analysis"
	PhaseValidation Phase = "validation"
	PhaseReporting  Phase = "reporting"
)

// Specialization defines what the agent specializes in
type Specialization struct {
	ReviewCategories     []string `yaml:"review_categories,omitempty" json:"review_categories,omitempty"`
	VulnerabilityClasses []string `yaml:"vulnerability_classes,omitempty" json:"vulnerability_classes,omitempty"`
	OWASPCategories      []string `yaml:"owasp_categories,omitempty" json:"owasp_categories,omitempty"`
	TechStack            []string `yaml:"tech_stack,omitempty" json:"tech_stack,omitempty"`
}

// CWEChecklistItem represents a CWE entry with detection guidance
type CWEChecklistItem struct {
	ID             string   `yaml:"id" json:"id"`
	Name           string   `yaml:"name" json:"name"`
	DetectionHints []string `yaml:"detection_hints,omitempty" json:"detection_hints,omitempty"`
	FlowPatterns   []string `yaml:"flow_patterns,omitempty" json:"flow_patterns,omitempty"`
}

// AgentConfig represents an agent configuration
type AgentConfig struct {
	Name            string             `yaml:"name" json:"name"`
	Description     string             `yaml:"description" json:"description"`
	Phase           Phase              `yaml:"phase" json:"phase"`
	Specialization  Specialization     `yaml:"specialization,omitempty" json:"specialization,omitempty"`
	CWEChecklist    []CWEChecklistItem `yaml:"cwe_checklist,omitempty" json:"cwe_checklist,omitempty"`
	ToolsAllowed    []string           `yaml:"tools_allowed" json:"tools_allowed"`
	PromptTemplate  string             `yaml:"prompt_template" json:"prompt_template"`
	ContextMemories []string           `yaml:"context_memories,omitempty" json:"context_memories,omitempty"`
}

// AgentList contains a list of agents
type AgentList struct {
	Agents []AgentConfig `json:"agents"`
	Total  int           `json:"total"`
}

// ConfigManager manages agent configurations
type ConfigManager struct {
	project     *project.Project
	builtinPath string
	projectPath string
}

// NewConfigManager creates a new agent config manager
func NewConfigManager(p *project.Project, builtinPath string) *ConfigManager {
	return &ConfigManager{
		project:     p,
		builtinPath: builtinPath,
		projectPath: p.GetAgentsPath(),
	}
}

// List lists all available agents (built-in + project-specific)
func (m *ConfigManager) List() (*AgentList, error) {
	var agents []AgentConfig

	// Load built-in agents
	builtins, err := m.loadFromDir(m.builtinPath)
	if err == nil {
		agents = append(agents, builtins...)
	}

	// Load project-specific agents
	projectAgents, err := m.loadFromDir(m.projectPath)
	if err == nil {
		agents = append(agents, projectAgents...)
	}

	// Add registry agents if no files found
	if len(agents) == 0 {
		agents = GetBuiltinAgents()
	}

	return &AgentList{
		Agents: agents,
		Total:  len(agents),
	}, nil
}

// Get gets an agent configuration by name
func (m *ConfigManager) Get(name string) (*AgentConfig, error) {
	// Check project-specific first
	path := filepath.Join(m.projectPath, name+".yaml")
	if agent, err := m.loadFromFile(path); err == nil {
		return agent, nil
	}

	// Check built-in
	path = filepath.Join(m.builtinPath, name+".yaml")
	if agent, err := m.loadFromFile(path); err == nil {
		return agent, nil
	}

	// Check registry
	if agent := GetBuiltinAgent(name); agent != nil {
		return agent, nil
	}

	return nil, fmt.Errorf("agent '%s' not found", name)
}

// Create creates a new project-specific agent
func (m *ConfigManager) Create(config *AgentConfig) error {
	if config.Name == "" {
		return fmt.Errorf("agent name is required")
	}

	// Check if already exists
	path := filepath.Join(m.projectPath, config.Name+".yaml")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("agent '%s' already exists", config.Name)
	}

	// Ensure directory exists
	if err := os.MkdirAll(m.projectPath, 0755); err != nil {
		return fmt.Errorf("failed to create agents directory: %w", err)
	}

	return m.saveToFile(path, config)
}

// Update updates an existing agent configuration
func (m *ConfigManager) Update(config *AgentConfig) error {
	path := filepath.Join(m.projectPath, config.Name+".yaml")
	return m.saveToFile(path, config)
}

// Delete deletes a project-specific agent
func (m *ConfigManager) Delete(name string) error {
	path := filepath.Join(m.projectPath, name+".yaml")
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("agent '%s' not found (only project-specific agents can be deleted)", name)
		}
		return fmt.Errorf("failed to delete agent: %w", err)
	}
	return nil
}

// loadFromDir loads all agent configs from a directory
func (m *ConfigManager) loadFromDir(dir string) ([]AgentConfig, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var agents []AgentConfig
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		agent, err := m.loadFromFile(path)
		if err != nil {
			continue
		}
		agents = append(agents, *agent)
	}

	return agents, nil
}

// loadFromFile loads an agent config from a file
func (m *ConfigManager) loadFromFile(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config AgentConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// saveToFile saves an agent config to a file
func (m *ConfigManager) saveToFile(path string, config *AgentConfig) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal agent config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write agent config: %w", err)
	}

	return nil
}
