package project

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInitialize(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Initialize project
	p, err := Initialize(tmpDir)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Verify project was created
	if p.RootPath != tmpDir {
		t.Errorf("expected RootPath %s, got %s", tmpDir, p.RootPath)
	}

	if p.Config == nil {
		t.Fatal("Config is nil")
	}

	if p.Config.Name != filepath.Base(tmpDir) {
		t.Errorf("expected Name %s, got %s", filepath.Base(tmpDir), p.Config.Name)
	}

	if p.Config.Version != "1.0" {
		t.Errorf("expected Version 1.0, got %s", p.Config.Version)
	}

	// Verify directories were created
	dirs := []string{
		filepath.Join(tmpDir, ZrokDir),
		filepath.Join(tmpDir, ZrokDir, MemoriesDir, ContextDir),
		filepath.Join(tmpDir, ZrokDir, MemoriesDir, PatternsDir),
		filepath.Join(tmpDir, ZrokDir, MemoriesDir, StackDir),
		filepath.Join(tmpDir, ZrokDir, FindingsDir, RawDir),
		filepath.Join(tmpDir, ZrokDir, FindingsDir, ExportsDir),
		filepath.Join(tmpDir, ZrokDir, AgentsDir),
	}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("directory not created: %s", dir)
		}
	}

	// Verify project.yaml was created
	configPath := filepath.Join(tmpDir, ZrokDir, ProjectFile)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("project.yaml not created")
	}
}

func TestInitializeAlreadyExists(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Initialize once
	_, err = Initialize(tmpDir)
	if err != nil {
		t.Fatalf("first Initialize failed: %v", err)
	}

	// Try to initialize again - should fail
	_, err = Initialize(tmpDir)
	if err == nil {
		t.Error("expected error when initializing already initialized project")
	}
}

func TestProjectLoadSave(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Initialize
	p, err := Initialize(tmpDir)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Modify config
	p.Config.Name = "test-project"
	p.Config.Description = "A test project"
	p.Config.TechStack.Languages = []Language{
		{Name: "go", Version: "1.21", Frameworks: []string{"gin", "gorm"}},
	}
	p.Config.TechStack.Databases = []string{"postgresql"}

	// Save
	if err := p.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Create new project instance and load
	p2 := &Project{RootPath: tmpDir}
	if err := p2.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify loaded data
	if p2.Config.Name != "test-project" {
		t.Errorf("expected Name 'test-project', got '%s'", p2.Config.Name)
	}

	if p2.Config.Description != "A test project" {
		t.Errorf("expected Description 'A test project', got '%s'", p2.Config.Description)
	}

	if len(p2.Config.TechStack.Languages) != 1 {
		t.Fatalf("expected 1 language, got %d", len(p2.Config.TechStack.Languages))
	}

	if p2.Config.TechStack.Languages[0].Name != "go" {
		t.Errorf("expected language 'go', got '%s'", p2.Config.TechStack.Languages[0].Name)
	}

	if len(p2.Config.TechStack.Databases) != 1 || p2.Config.TechStack.Databases[0] != "postgresql" {
		t.Errorf("expected databases [postgresql], got %v", p2.Config.TechStack.Databases)
	}
}

func TestFindProjectRoot(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Initialize project
	_, err = Initialize(tmpDir)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Create nested directory
	nestedDir := filepath.Join(tmpDir, "src", "pkg", "handlers")
	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		t.Fatalf("failed to create nested dir: %v", err)
	}

	// Find project root from nested directory
	root, err := FindProjectRoot(nestedDir)
	if err != nil {
		t.Fatalf("FindProjectRoot failed: %v", err)
	}

	if root != tmpDir {
		t.Errorf("expected root %s, got %s", tmpDir, root)
	}
}

func TestFindProjectRootNotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Don't initialize - should fail to find
	_, err = FindProjectRoot(tmpDir)
	if err == nil {
		t.Error("expected error when no .zrok directory exists")
	}
}

func TestActivate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Initialize
	_, err = Initialize(tmpDir)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Reset Active
	Active = nil

	// Activate
	p, err := Activate(tmpDir)
	if err != nil {
		t.Fatalf("Activate failed: %v", err)
	}

	if p != Active {
		t.Error("Activate did not set Active project")
	}

	if p.Config == nil {
		t.Error("Activate did not load config")
	}
}

func TestProjectPaths(t *testing.T) {
	p := &Project{
		RootPath: "/test/project",
		Config:   &ProjectConfig{},
	}

	if p.GetZrokPath() != "/test/project/.zrok" {
		t.Errorf("unexpected zrok path: %s", p.GetZrokPath())
	}

	if p.GetConfigPath() != "/test/project/.zrok/project.yaml" {
		t.Errorf("unexpected config path: %s", p.GetConfigPath())
	}

	if p.GetMemoriesPath() != "/test/project/.zrok/memories" {
		t.Errorf("unexpected memories path: %s", p.GetMemoriesPath())
	}

	if p.GetFindingsPath() != "/test/project/.zrok/findings" {
		t.Errorf("unexpected findings path: %s", p.GetFindingsPath())
	}

	if p.GetAgentsPath() != "/test/project/.zrok/agents" {
		t.Errorf("unexpected agents path: %s", p.GetAgentsPath())
	}
}

func TestProjectConfigTypes(t *testing.T) {
	config := &ProjectConfig{
		Name:       "test",
		Version:    "1.0",
		DetectedAt: time.Now(),
		TechStack: TechStack{
			Languages: []Language{
				{Name: "go", Version: "1.21", Frameworks: []string{"gin"}},
			},
			Databases:      []string{"postgresql", "redis"},
			Infrastructure: []string{"docker", "kubernetes"},
			Auth:           []string{"jwt", "oauth2"},
		},
		SecurityScope: SecurityScope{
			IncludePaths: []string{"src/", "api/"},
			ExcludePaths: []string{"vendor/", "node_modules/"},
			SensitiveAreas: []SensitiveArea{
				{Path: "src/auth/", Reason: "Authentication logic"},
			},
		},
	}

	if len(config.TechStack.Languages) != 1 {
		t.Errorf("expected 1 language, got %d", len(config.TechStack.Languages))
	}

	if len(config.TechStack.Databases) != 2 {
		t.Errorf("expected 2 databases, got %d", len(config.TechStack.Databases))
	}

	if len(config.SecurityScope.SensitiveAreas) != 1 {
		t.Errorf("expected 1 sensitive area, got %d", len(config.SecurityScope.SensitiveAreas))
	}
}
