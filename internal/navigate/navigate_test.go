package navigate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to initialize project: %v", err)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return p, cleanup
}

// Reader tests

func TestReaderRead(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	// Create test file
	content := "line 1\nline 2\nline 3\nline 4\nline 5\n"
	testFile := filepath.Join(p.RootPath, "test.txt")
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	reader := NewReader(p)

	result, err := reader.Read("test.txt")
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if result.Content != content {
		t.Errorf("unexpected content: %s", result.Content)
	}

	if result.TotalLines != 6 { // 5 lines + empty line at end
		t.Errorf("expected 6 lines, got %d", result.TotalLines)
	}
}

func TestReaderReadLines(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	// Create test file
	var lines []string
	for i := 1; i <= 10; i++ {
		lines = append(lines, "line "+string('0'+rune(i)))
	}
	content := strings.Join(lines, "\n") + "\n"
	testFile := filepath.Join(p.RootPath, "test.txt")
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	reader := NewReader(p)

	result, err := reader.ReadLines("test.txt", 3, 5)
	if err != nil {
		t.Fatalf("ReadLines failed: %v", err)
	}

	if len(result.Lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(result.Lines))
	}

	if result.StartLine != 3 {
		t.Errorf("expected start line 3, got %d", result.StartLine)
	}

	if result.EndLine != 5 {
		t.Errorf("expected end line 5, got %d", result.EndLine)
	}
}

func TestReaderExists(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	reader := NewReader(p)

	// File doesn't exist
	if reader.Exists("nonexistent.txt") {
		t.Error("expected false for nonexistent file")
	}

	// Create file
	testFile := filepath.Join(p.RootPath, "exists.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	if !reader.Exists("exists.txt") {
		t.Error("expected true for existing file")
	}
}

func TestReaderGetInfo(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	// Create test file
	content := "test content"
	testFile := filepath.Join(p.RootPath, "info.txt")
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	reader := NewReader(p)
	info, err := reader.GetInfo("info.txt")
	if err != nil {
		t.Fatalf("GetInfo failed: %v", err)
	}

	if info.Name != "info.txt" {
		t.Errorf("unexpected name: %s", info.Name)
	}

	if info.Size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), info.Size)
	}

	if info.IsDir {
		t.Error("expected IsDir false")
	}
}

// Lister tests

func TestListerList(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	// Create directory structure
	dirs := []string{"src", "pkg", "internal"}
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(p.RootPath, dir), 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
	}

	files := []string{"main.go", "go.mod", "README.md"}
	for _, file := range files {
		if err := os.WriteFile(filepath.Join(p.RootPath, file), []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
	}

	lister := NewLister(p)
	result, err := lister.List(".", nil)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Should have dirs + files (minus .zrok which is ignored)
	if result.Total < 5 {
		t.Errorf("expected at least 5 entries, got %d", result.Total)
	}

	// Verify dirs come first
	if !result.Entries[0].IsDir {
		t.Error("directories should come first")
	}
}

func TestListerListRecursive(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	// Create nested structure
	nested := filepath.Join(p.RootPath, "src", "pkg", "handlers")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatalf("failed to create nested dirs: %v", err)
	}

	// Create files at various levels
	files := []string{
		filepath.Join(p.RootPath, "main.go"),
		filepath.Join(p.RootPath, "src", "app.go"),
		filepath.Join(p.RootPath, "src", "pkg", "util.go"),
		filepath.Join(p.RootPath, "src", "pkg", "handlers", "handler.go"),
	}
	for _, file := range files {
		if err := os.WriteFile(file, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
	}

	lister := NewLister(p)
	result, err := lister.List(".", &ListOptions{Recursive: true})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Should find all files and directories
	if result.Total < 7 { // 3 dirs + 4 files
		t.Errorf("expected at least 7 entries, got %d", result.Total)
	}
}

func TestListerTree(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	// Create structure
	os.MkdirAll(filepath.Join(p.RootPath, "src"), 0755)
	os.WriteFile(filepath.Join(p.RootPath, "src", "main.go"), []byte("test"), 0644)
	os.WriteFile(filepath.Join(p.RootPath, "README.md"), []byte("test"), 0644)

	lister := NewLister(p)
	tree, err := lister.Tree(".", 2)
	if err != nil {
		t.Fatalf("Tree failed: %v", err)
	}

	// Check tree contains expected elements
	if !strings.Contains(tree, "src/") {
		t.Error("tree missing src/")
	}
	if !strings.Contains(tree, "├──") || !strings.Contains(tree, "└──") {
		t.Error("tree missing tree characters")
	}
}

// Finder tests

func TestFinderFind(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	// Create files
	files := []string{
		filepath.Join(p.RootPath, "main.go"),
		filepath.Join(p.RootPath, "util.go"),
		filepath.Join(p.RootPath, "readme.md"),
	}
	for _, file := range files {
		if err := os.WriteFile(file, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
	}

	finder := NewFinder(p)

	// Find by extension
	result, err := finder.Find("*.go", nil)
	if err != nil {
		t.Fatalf("Find failed: %v", err)
	}

	if result.Total != 2 {
		t.Errorf("expected 2 .go files, got %d", result.Total)
	}

	// Find by name
	result, err = finder.Find("main*", nil)
	if err != nil {
		t.Fatalf("Find failed: %v", err)
	}

	if result.Total != 1 {
		t.Errorf("expected 1 main* file, got %d", result.Total)
	}
}

func TestFinderSearch(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	// Create files with content
	files := map[string]string{
		"main.go":    "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}",
		"util.go":    "package main\n\nfunc helper() {\n\treturn nil\n}",
		"handler.go": "package main\n\nfunc handleRequest() {\n\t// handle request\n}",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(p.RootPath, name), []byte(content), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
	}

	finder := NewFinder(p)

	// Search for pattern
	result, err := finder.Search("func", nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if result.Total < 3 {
		t.Errorf("expected at least 3 matches for 'func', got %d", result.Total)
	}

	// Search with regex
	result, err = finder.Search("func.*Request", &SearchOptions{Regex: true})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if result.Total != 1 {
		t.Errorf("expected 1 match for 'func.*Request', got %d", result.Total)
	}

	// Search with file pattern
	result, err = finder.Search("func", &SearchOptions{FilePattern: "main.go"})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if result.Total != 1 {
		t.Errorf("expected 1 match in main.go, got %d", result.Total)
	}
}

func TestFinderSearchContext(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	content := "line 1\nline 2\nTARGET\nline 4\nline 5\n"
	if err := os.WriteFile(filepath.Join(p.RootPath, "test.txt"), []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	finder := NewFinder(p)
	result, err := finder.Search("TARGET", &SearchOptions{Context: 1})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if result.Total != 1 {
		t.Fatalf("expected 1 match, got %d", result.Total)
	}

	if result.Matches[0].Context == "" {
		t.Error("expected context in match")
	}

	if !strings.Contains(result.Matches[0].Context, "line 2") {
		t.Error("context missing previous line")
	}
	if !strings.Contains(result.Matches[0].Context, "line 4") {
		t.Error("context missing next line")
	}
}

// Symbol tests

func TestSymbolExtractGo(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	goCode := `package main

type User struct {
	ID   int
	Name string
}

type Repository interface {
	Find(id int) (*User, error)
}

func main() {
	println("hello")
}

func (u *User) String() string {
	return u.Name
}

var globalVar = "test"

const MaxSize = 100
`
	if err := os.WriteFile(filepath.Join(p.RootPath, "main.go"), []byte(goCode), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	extractor := NewSymbolExtractor(p)
	result, err := extractor.Extract("main.go")
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Check various symbol types
	hasStruct := false
	hasInterface := false
	hasFunction := false
	hasMethod := false
	hasVar := false
	hasConst := false

	for _, sym := range result.Symbols {
		switch sym.Kind {
		case SymbolStruct:
			hasStruct = true
			if sym.Name != "User" {
				t.Errorf("unexpected struct name: %s", sym.Name)
			}
		case SymbolInterface:
			hasInterface = true
		case SymbolFunction:
			hasFunction = true
		case SymbolMethod:
			hasMethod = true
			if sym.Parent != "User" {
				t.Errorf("expected method parent 'User', got '%s'", sym.Parent)
			}
		case SymbolVariable:
			hasVar = true
		case SymbolConstant:
			hasConst = true
		}
	}

	if !hasStruct {
		t.Error("struct not detected")
	}
	if !hasInterface {
		t.Error("interface not detected")
	}
	if !hasFunction {
		t.Error("function not detected")
	}
	if !hasMethod {
		t.Error("method not detected")
	}
	if !hasVar {
		t.Error("variable not detected")
	}
	if !hasConst {
		t.Error("constant not detected")
	}
}

func TestSymbolExtractPython(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	pyCode := `class User:
    def __init__(self, name):
        self.name = name

    def greet(self):
        return f"Hello, {self.name}"

def helper_function():
    pass

CONSTANT = 42
`
	if err := os.WriteFile(filepath.Join(p.RootPath, "app.py"), []byte(pyCode), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	extractor := NewSymbolExtractor(p)
	result, err := extractor.Extract("app.py")
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	hasClass := false
	hasMethod := false
	hasFunction := false

	for _, sym := range result.Symbols {
		switch sym.Kind {
		case SymbolClass:
			hasClass = true
		case SymbolMethod:
			hasMethod = true
		case SymbolFunction:
			hasFunction = true
		}
	}

	if !hasClass {
		t.Error("class not detected")
	}
	if !hasMethod {
		t.Error("method not detected")
	}
	if !hasFunction {
		t.Error("function not detected")
	}
}

func TestSymbolFind(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	// Create files with functions
	os.WriteFile(filepath.Join(p.RootPath, "a.go"), []byte("package main\nfunc HandleUser() {}"), 0644)
	os.WriteFile(filepath.Join(p.RootPath, "b.go"), []byte("package main\nfunc HandleOrder() {}"), 0644)

	extractor := NewSymbolExtractor(p)
	result, err := extractor.Find("Handle")
	if err != nil {
		t.Fatalf("Find failed: %v", err)
	}

	if result.Total != 2 {
		t.Errorf("expected 2 symbols with 'Handle', got %d", result.Total)
	}
}
