package project

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectorDetectGo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create go.mod
	goMod := `module example.com/test

go 1.21

require (
	github.com/gin-gonic/gin v1.9.0
	gorm.io/gorm v1.25.0
)
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatalf("failed to write go.mod: %v", err)
	}

	detector := NewDetector(tmpDir)
	stack, err := detector.DetectAll()
	if err != nil {
		t.Fatalf("DetectAll failed: %v", err)
	}

	// Check Go was detected
	var goLang *Language
	for i := range stack.Languages {
		if stack.Languages[i].Name == "go" {
			goLang = &stack.Languages[i]
			break
		}
	}

	if goLang == nil {
		t.Fatal("Go language not detected")
	}

	if goLang.Version != "1.21" {
		t.Errorf("expected Go version 1.21, got %s", goLang.Version)
	}

	// Check frameworks
	hasGin := false
	hasGorm := false
	for _, fw := range goLang.Frameworks {
		if fw == "gin" {
			hasGin = true
		}
		if fw == "gorm" {
			hasGorm = true
		}
	}

	if !hasGin {
		t.Error("gin framework not detected")
	}
	if !hasGorm {
		t.Error("gorm framework not detected")
	}
}

func TestDetectorDetectNode(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create package.json
	packageJSON := `{
  "name": "test-app",
  "dependencies": {
    "react": "^18.0.0",
    "express": "^4.18.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	detector := NewDetector(tmpDir)
	stack, err := detector.DetectAll()
	if err != nil {
		t.Fatalf("DetectAll failed: %v", err)
	}

	// Check TypeScript was detected (because of devDependencies)
	var tsLang *Language
	for i := range stack.Languages {
		if stack.Languages[i].Name == "typescript" {
			tsLang = &stack.Languages[i]
			break
		}
	}

	if tsLang == nil {
		t.Fatal("TypeScript not detected")
	}

	// Check frameworks
	hasReact := false
	hasExpress := false
	for _, fw := range tsLang.Frameworks {
		if fw == "react" {
			hasReact = true
		}
		if fw == "express" {
			hasExpress = true
		}
	}

	if !hasReact {
		t.Error("react framework not detected")
	}
	if !hasExpress {
		t.Error("express framework not detected")
	}
}

func TestDetectorDetectPython(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create requirements.txt
	requirements := `django==4.2.0
flask==2.3.0
sqlalchemy==2.0.0
`
	if err := os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte(requirements), 0644); err != nil {
		t.Fatalf("failed to write requirements.txt: %v", err)
	}

	detector := NewDetector(tmpDir)
	stack, err := detector.DetectAll()
	if err != nil {
		t.Fatalf("DetectAll failed: %v", err)
	}

	var pyLang *Language
	for i := range stack.Languages {
		if stack.Languages[i].Name == "python" {
			pyLang = &stack.Languages[i]
			break
		}
	}

	if pyLang == nil {
		t.Fatal("Python not detected")
	}

	// Check frameworks
	hasDjango := false
	hasFlask := false
	for _, fw := range pyLang.Frameworks {
		if fw == "django" {
			hasDjango = true
		}
		if fw == "flask" {
			hasFlask = true
		}
	}

	if !hasDjango {
		t.Error("django framework not detected")
	}
	if !hasFlask {
		t.Error("flask framework not detected")
	}
}

func TestDetectorDetectDatabases(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create docker-compose.yml with database services
	dockerCompose := `version: '3'
services:
  db:
    image: postgres:15
  cache:
    image: redis:7
  search:
    image: elasticsearch:8
`
	if err := os.WriteFile(filepath.Join(tmpDir, "docker-compose.yml"), []byte(dockerCompose), 0644); err != nil {
		t.Fatalf("failed to write docker-compose.yml: %v", err)
	}

	detector := NewDetector(tmpDir)
	stack, err := detector.DetectAll()
	if err != nil {
		t.Fatalf("DetectAll failed: %v", err)
	}

	hasPostgres := false
	hasRedis := false
	hasElastic := false
	for _, db := range stack.Databases {
		switch db {
		case "postgresql":
			hasPostgres = true
		case "redis":
			hasRedis = true
		case "elasticsearch":
			hasElastic = true
		}
	}

	if !hasPostgres {
		t.Error("postgresql not detected")
	}
	if !hasRedis {
		t.Error("redis not detected")
	}
	if !hasElastic {
		t.Error("elasticsearch not detected")
	}
}

func TestDetectorDetectInfrastructure(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create Dockerfile
	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte("FROM golang:1.21"), 0644); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	// Create docker-compose.yml
	if err := os.WriteFile(filepath.Join(tmpDir, "docker-compose.yml"), []byte("version: '3'"), 0644); err != nil {
		t.Fatalf("failed to write docker-compose.yml: %v", err)
	}

	// Create .github/workflows directory
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		t.Fatalf("failed to create workflows dir: %v", err)
	}

	// Create k8s directory
	if err := os.MkdirAll(filepath.Join(tmpDir, "k8s"), 0755); err != nil {
		t.Fatalf("failed to create k8s dir: %v", err)
	}

	detector := NewDetector(tmpDir)
	stack, err := detector.DetectAll()
	if err != nil {
		t.Fatalf("DetectAll failed: %v", err)
	}

	hasDocker := false
	hasCompose := false
	hasK8s := false
	hasGHA := false
	for _, infra := range stack.Infrastructure {
		switch infra {
		case "docker":
			hasDocker = true
		case "docker-compose":
			hasCompose = true
		case "kubernetes":
			hasK8s = true
		case "github-actions":
			hasGHA = true
		}
	}

	if !hasDocker {
		t.Error("docker not detected")
	}
	if !hasCompose {
		t.Error("docker-compose not detected")
	}
	if !hasK8s {
		t.Error("kubernetes not detected")
	}
	if !hasGHA {
		t.Error("github-actions not detected")
	}
}

func TestDetectorDetectSensitiveAreas(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create sensitive directories
	sensitiveDirs := []string{
		"src/auth",
		"src/admin",
		"api/payment",
		"internal/crypto",
	}

	for _, dir := range sensitiveDirs {
		if err := os.MkdirAll(filepath.Join(tmpDir, dir), 0755); err != nil {
			t.Fatalf("failed to create dir %s: %v", dir, err)
		}
	}

	detector := NewDetector(tmpDir)
	areas, err := detector.DetectSensitiveAreas()
	if err != nil {
		t.Fatalf("DetectSensitiveAreas failed: %v", err)
	}

	if len(areas) < 3 {
		t.Errorf("expected at least 3 sensitive areas, got %d", len(areas))
	}

	// Check that auth was detected
	hasAuth := false
	hasAdmin := false
	hasPayment := false
	for _, area := range areas {
		if area.Path == "src/auth/" {
			hasAuth = true
		}
		if area.Path == "src/admin/" {
			hasAdmin = true
		}
		if area.Path == "api/payment/" {
			hasPayment = true
		}
	}

	if !hasAuth {
		t.Error("auth directory not detected as sensitive")
	}
	if !hasAdmin {
		t.Error("admin directory not detected as sensitive")
	}
	if !hasPayment {
		t.Error("payment directory not detected as sensitive")
	}
}

func TestDetectorEmptyProject(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	detector := NewDetector(tmpDir)
	stack, err := detector.DetectAll()
	if err != nil {
		t.Fatalf("DetectAll failed: %v", err)
	}

	// Should return empty but not nil
	if stack == nil {
		t.Fatal("stack is nil")
	}

	if len(stack.Languages) != 0 {
		t.Errorf("expected 0 languages, got %d", len(stack.Languages))
	}
}
