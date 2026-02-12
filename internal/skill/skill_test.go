package skill

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedContent(t *testing.T) {
	if len(skillContent) == 0 {
		t.Fatal("embedded skill content is empty")
	}

	if !strings.HasPrefix(string(skillContent), "# Code Review Skill") {
		t.Errorf("embedded content does not start with expected header, got: %s", string(skillContent[:50]))
	}
}

func TestInstall(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	result, err := Install()
	if err != nil {
		t.Fatalf("Install() failed: %v", err)
	}

	if !result.Installed {
		t.Error("expected Installed to be true")
	}

	expectedPath := filepath.Join(tmpHome, ".claude", "skills", "zrok-code-review", "SKILL.md")
	if result.Path != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, result.Path)
	}

	content, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed to read installed file: %v", err)
	}

	if string(content) != string(skillContent) {
		t.Error("installed content does not match embedded content")
	}
}

func TestInstallOverwrite(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	skillPath := filepath.Join(tmpHome, ".claude", "skills", "zrok-code-review", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(skillPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(skillPath, []byte("old content"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Install()
	if err != nil {
		t.Fatalf("Install() failed on overwrite: %v", err)
	}

	if !result.Installed {
		t.Error("expected Installed to be true")
	}

	content, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatalf("failed to read installed file: %v", err)
	}

	if string(content) == "old content" {
		t.Error("file was not overwritten")
	}

	if string(content) != string(skillContent) {
		t.Error("overwritten content does not match embedded content")
	}
}
