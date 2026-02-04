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
	IndexDir      = "index"
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

// EmbeddingConfig contains configuration for the embedding provider
type EmbeddingConfig struct {
	// Provider is the embedding provider: "ollama", "openai", "huggingface"
	Provider string `yaml:"provider" json:"provider"`
	// Model is the model name (provider-specific)
	Model string `yaml:"model,omitempty" json:"model,omitempty"`
	// Endpoint is the API endpoint (required for ollama)
	Endpoint string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	// APIKeyEnv is the environment variable name for the API key
	APIKeyEnv string `yaml:"api_key_env,omitempty" json:"api_key_env,omitempty"`
	// Dimension is the embedding dimension
	Dimension int `yaml:"dimension,omitempty" json:"dimension,omitempty"`
}

// IndexConfig contains configuration for semantic indexing
type IndexConfig struct {
	// Enabled indicates if semantic indexing is enabled
	Enabled bool `yaml:"enabled" json:"enabled"`
	// ChunkStrategy is the chunking strategy: "lsp" (default), "regex"
	ChunkStrategy string `yaml:"chunk_strategy,omitempty" json:"chunk_strategy,omitempty"`
	// MaxChunkLines is the maximum lines per chunk (default: 100)
	MaxChunkLines int `yaml:"max_chunk_lines,omitempty" json:"max_chunk_lines,omitempty"`
	// Embedding contains the embedding provider configuration
	Embedding EmbeddingConfig `yaml:"embedding" json:"embedding"`
	// ExcludePatterns are file patterns to exclude from indexing
	ExcludePatterns []string `yaml:"exclude_patterns,omitempty" json:"exclude_patterns,omitempty"`
}

// DefaultIndexConfig returns the default index configuration
func DefaultIndexConfig() IndexConfig {
	return IndexConfig{
		Enabled:       false,
		ChunkStrategy: "lsp",
		MaxChunkLines: 100,
		Embedding: EmbeddingConfig{
			Provider:  "ollama",
			Model:     "nomic-embed-text",
			Endpoint:  "http://localhost:11434",
			Dimension: 768,
		},
		ExcludePatterns: []string{
			"*_test.go",
			"*.min.js",
			"vendor/",
			"node_modules/",
		},
	}
}

// ProjectConfig represents the .zrok/project.yaml configuration
type ProjectConfig struct {
	Name          string        `yaml:"name" json:"name"`
	Version       string        `yaml:"version" json:"version"`
	Description   string        `yaml:"description,omitempty" json:"description,omitempty"`
	DetectedAt    time.Time     `yaml:"detected_at" json:"detected_at"`
	TechStack     TechStack     `yaml:"tech_stack" json:"tech_stack"`
	SecurityScope SecurityScope `yaml:"security_scope,omitempty" json:"security_scope,omitempty"`
	Index         IndexConfig   `yaml:"index,omitempty" json:"index,omitempty"`
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

// GetIndexPath returns the path to the index directory
func (p *Project) GetIndexPath() string {
	return filepath.Join(p.GetZrokPath(), IndexDir)
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
		filepath.Join(zrokPath, IndexDir),
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
