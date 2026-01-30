package project

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ZrokDir       = ".zrok"
	ProjectFile   = "project.yaml"
	MemoriesDir   = "memories"
	FindingsDir   = "findings"
	AgentsDir     = "agents"
	RawDir        = "raw"
	ExportsDir    = "exports"
	ContextDir    = "context"
	PatternsDir   = "patterns"
	StackDir      = "stack"
)

// Language represents a detected programming language
type Language struct {
	Name       string   `yaml:"name" json:"name"`
	Version    string   `yaml:"version,omitempty" json:"version,omitempty"`
	Frameworks []string `yaml:"frameworks,omitempty" json:"frameworks,omitempty"`
}

// SensitiveArea represents an area of code that needs extra attention
type SensitiveArea struct {
	Path   string `yaml:"path" json:"path"`
	Reason string `yaml:"reason" json:"reason"`
}

// SecurityScope defines what to analyze
type SecurityScope struct {
	IncludePaths   []string        `yaml:"include_paths,omitempty" json:"include_paths,omitempty"`
	ExcludePaths   []string        `yaml:"exclude_paths,omitempty" json:"exclude_paths,omitempty"`
	SensitiveAreas []SensitiveArea `yaml:"sensitive_areas,omitempty" json:"sensitive_areas,omitempty"`
}

// TechStack represents the detected technology stack
type TechStack struct {
	Languages      []Language `yaml:"languages,omitempty" json:"languages,omitempty"`
	Databases      []string   `yaml:"databases,omitempty" json:"databases,omitempty"`
	Infrastructure []string   `yaml:"infrastructure,omitempty" json:"infrastructure,omitempty"`
	Auth           []string   `yaml:"auth,omitempty" json:"auth,omitempty"`
}

// ProjectConfig represents the .zrok/project.yaml configuration
type ProjectConfig struct {
	Name          string        `yaml:"name" json:"name"`
	Version       string        `yaml:"version" json:"version"`
	Description   string        `yaml:"description,omitempty" json:"description,omitempty"`
	DetectedAt    time.Time     `yaml:"detected_at" json:"detected_at"`
	TechStack     TechStack     `yaml:"tech_stack" json:"tech_stack"`
	SecurityScope SecurityScope `yaml:"security_scope,omitempty" json:"security_scope,omitempty"`
}

// Project represents an active zrok project
type Project struct {
	RootPath string
	Config   *ProjectConfig
}

// Active holds the currently active project
var Active *Project

// FindProjectRoot looks for .zrok directory starting from path and going up
func FindProjectRoot(startPath string) (string, error) {
	path := startPath
	for {
		zrokPath := filepath.Join(path, ZrokDir)
		if info, err := os.Stat(zrokPath); err == nil && info.IsDir() {
			return path, nil
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", fmt.Errorf("no .zrok directory found (searched from %s to root)", startPath)
		}
		path = parent
	}
}

// GetZrokPath returns the path to the .zrok directory
func (p *Project) GetZrokPath() string {
	return filepath.Join(p.RootPath, ZrokDir)
}

// GetConfigPath returns the path to project.yaml
func (p *Project) GetConfigPath() string {
	return filepath.Join(p.GetZrokPath(), ProjectFile)
}

// GetMemoriesPath returns the path to the memories directory
func (p *Project) GetMemoriesPath() string {
	return filepath.Join(p.GetZrokPath(), MemoriesDir)
}

// GetFindingsPath returns the path to the findings directory
func (p *Project) GetFindingsPath() string {
	return filepath.Join(p.GetZrokPath(), FindingsDir)
}

// GetAgentsPath returns the path to the agents directory
func (p *Project) GetAgentsPath() string {
	return filepath.Join(p.GetZrokPath(), AgentsDir)
}

// Load loads the project configuration from disk
func (p *Project) Load() error {
	data, err := os.ReadFile(p.GetConfigPath())
	if err != nil {
		return fmt.Errorf("failed to read project config: %w", err)
	}

	var config ProjectConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse project config: %w", err)
	}

	p.Config = &config
	return nil
}

// Save saves the project configuration to disk
func (p *Project) Save() error {
	data, err := yaml.Marshal(p.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal project config: %w", err)
	}

	if err := os.WriteFile(p.GetConfigPath(), data, 0644); err != nil {
		return fmt.Errorf("failed to write project config: %w", err)
	}

	return nil
}

// Initialize creates a new .zrok project structure
func Initialize(rootPath string) (*Project, error) {
	zrokPath := filepath.Join(rootPath, ZrokDir)

	// Check if already initialized
	if _, err := os.Stat(zrokPath); err == nil {
		return nil, fmt.Errorf("project already initialized at %s", zrokPath)
	}

	// Create directory structure
	dirs := []string{
		zrokPath,
		filepath.Join(zrokPath, MemoriesDir, ContextDir),
		filepath.Join(zrokPath, MemoriesDir, PatternsDir),
		filepath.Join(zrokPath, MemoriesDir, StackDir),
		filepath.Join(zrokPath, FindingsDir, RawDir),
		filepath.Join(zrokPath, FindingsDir, ExportsDir),
		filepath.Join(zrokPath, AgentsDir),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Create default project config
	projectName := filepath.Base(rootPath)
	config := &ProjectConfig{
		Name:       projectName,
		Version:    "1.0",
		DetectedAt: time.Now(),
		TechStack:  TechStack{},
		SecurityScope: SecurityScope{
			ExcludePaths: []string{"vendor/", "node_modules/", ".git/"},
		},
	}

	project := &Project{
		RootPath: rootPath,
		Config:   config,
	}

	if err := project.Save(); err != nil {
		return nil, err
	}

	return project, nil
}

// Activate loads and activates a project
func Activate(path string) (*Project, error) {
	rootPath, err := FindProjectRoot(path)
	if err != nil {
		return nil, err
	}

	project := &Project{
		RootPath: rootPath,
	}

	if err := project.Load(); err != nil {
		return nil, err
	}

	Active = project
	return project, nil
}

// EnsureActive returns the active project or activates from current directory
func EnsureActive() (*Project, error) {
	if Active != nil {
		return Active, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current directory: %w", err)
	}

	return Activate(cwd)
}
