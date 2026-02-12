package skill

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:generate cp ../../skills/code-review/SKILL.md configs/SKILL.md

//go:embed configs/SKILL.md
var skillContent []byte

// InstallResult contains the result of a skill installation.
type InstallResult struct {
	Path      string `json:"path"`
	Installed bool   `json:"installed"`
	Message   string `json:"message"`
}

// Install writes the embedded code-review skill to ~/.claude/skills/zrok-code-review/SKILL.md.
func Install() (*InstallResult, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	skillDir := filepath.Join(homeDir, ".claude", "skills", "zrok-code-review")
	skillPath := filepath.Join(skillDir, "SKILL.md")

	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create skill directory: %w", err)
	}

	if err := os.WriteFile(skillPath, skillContent, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write skill file: %w", err)
	}

	return &InstallResult{
		Path:      skillPath,
		Installed: true,
		Message:   fmt.Sprintf("Installed code-review skill to %s", skillPath),
	}, nil
}
