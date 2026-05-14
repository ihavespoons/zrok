package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ihavespoons/quokka/internal/navigate"
)

// TestNormalizeListPathsRelativeInput verifies that when the user passes a
// relative dir inside the project, output paths are normalized to be
// relative to the project root.
func TestNormalizeListPathsRelativeInput(t *testing.T) {
	tmp, err := os.MkdirTemp("", "quokka-listpaths-*")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	// Simulate lister output for a relative input dir "src".
	result := &navigate.ListResult{
		Path: "src",
		Entries: []navigate.FileInfo{
			{Name: "app.go", Path: filepath.Join("src", "app.go"), IsDir: false},
			{Name: "pkg", Path: filepath.Join("src", "pkg"), IsDir: true},
		},
	}

	normalizeListPaths(result, tmp, "src")

	if result.Path != "src" {
		t.Errorf("expected result.Path 'src', got %q", result.Path)
	}
	for _, e := range result.Entries {
		if filepath.IsAbs(e.Path) {
			t.Errorf("entry path should not be absolute: %q", e.Path)
		}
		if !strings.HasPrefix(e.Path, "src"+string(filepath.Separator)) {
			t.Errorf("entry path should be project-root-relative under 'src/', got %q", e.Path)
		}
	}
}

// TestNormalizeListPathsAbsoluteInputInsideProject verifies that when an
// absolute path inside the project is passed, output paths become
// project-root-relative (not absolute).
func TestNormalizeListPathsAbsoluteInputInsideProject(t *testing.T) {
	tmp, err := os.MkdirTemp("", "quokka-listpaths-*")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	srcAbs := filepath.Join(tmp, "src")
	if err := os.MkdirAll(srcAbs, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Simulate lister output where inputDir was absolute. The lister builds
	// entry paths by joining inputDir with the entry name; so entry paths
	// will be absolute too.
	result := &navigate.ListResult{
		Path: srcAbs,
		Entries: []navigate.FileInfo{
			{Name: "app.go", Path: filepath.Join(srcAbs, "app.go"), IsDir: false},
			{Name: "pkg", Path: filepath.Join(srcAbs, "pkg"), IsDir: true},
		},
	}

	normalizeListPaths(result, tmp, srcAbs)

	if filepath.IsAbs(result.Path) {
		t.Errorf("result.Path should not be absolute after normalization: %q", result.Path)
	}
	if result.Path != "src" {
		t.Errorf("expected result.Path 'src', got %q", result.Path)
	}
	for _, e := range result.Entries {
		if filepath.IsAbs(e.Path) {
			t.Errorf("entry path should not be absolute after normalization: %q", e.Path)
		}
		if !strings.HasPrefix(e.Path, "src"+string(filepath.Separator)) {
			t.Errorf("entry path should be project-root-relative under 'src/', got %q", e.Path)
		}
	}
}

// TestNormalizeListPathsOutsideProject verifies that when the listed dir is
// outside the project root, paths are kept relative to the input dir.
func TestNormalizeListPathsOutsideProject(t *testing.T) {
	projRoot, err := os.MkdirTemp("", "quokka-listpaths-proj-*")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer func() { _ = os.RemoveAll(projRoot) }()

	outsideDir, err := os.MkdirTemp("", "quokka-listpaths-outside-*")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer func() { _ = os.RemoveAll(outsideDir) }()

	// Simulate lister output for an absolute outside-of-project path.
	result := &navigate.ListResult{
		Path: outsideDir,
		Entries: []navigate.FileInfo{
			{Name: "data.txt", Path: filepath.Join(outsideDir, "data.txt"), IsDir: false},
		},
	}

	normalizeListPaths(result, projRoot, outsideDir)

	// Outside-of-project: paths should be relative to inputDir.
	if result.Path != outsideDir {
		t.Errorf("expected result.Path to be inputDir for outside-of-project, got %q", result.Path)
	}
	for _, e := range result.Entries {
		if e.Path != "data.txt" {
			t.Errorf("expected entry path relative to input dir ('data.txt'), got %q", e.Path)
		}
	}
}
