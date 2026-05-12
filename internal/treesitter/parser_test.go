package treesitter

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanHandle(t *testing.T) {
	p := NewParser()

	if !p.CanHandle("test.go") {
		t.Error("expected CanHandle to return true for .go files")
	}
	if !p.CanHandle("test.py") {
		t.Error("expected CanHandle to return true for .py files")
	}
	if p.CanHandle("test.xyz") {
		t.Error("expected CanHandle to return false for .xyz files")
	}
}

func TestExtractGoSymbols(t *testing.T) {
	source := []byte(`package main

import "fmt"

type MyStruct struct {
	Name string
}

func (m *MyStruct) Hello() string {
	return "hello " + m.Name
}

func main() {
	fmt.Println("hello")
}

var globalVar = "test"

const myConst = 42
`)

	p := NewParser()
	symbols, err := p.ExtractSymbolsFromSource(source, "test.go")
	if err != nil {
		t.Fatalf("failed to extract symbols: %v", err)
	}

	if len(symbols) == 0 {
		t.Fatal("expected at least some symbols, got 0")
	}

	// Check we got expected symbols
	found := make(map[string]bool)
	for _, s := range symbols {
		found[string(s.Kind)+":"+s.Name] = true
		t.Logf("Symbol: %s %s (line %d, parent=%s)", s.Kind, s.Name, s.Line, s.Parent)
	}

	expected := []string{"struct:MyStruct", "method:Hello", "function:main"}
	for _, e := range expected {
		if !found[e] {
			t.Errorf("expected to find symbol %s", e)
		}
	}
}

func TestExtractPythonSymbols(t *testing.T) {
	source := []byte(`class Calculator:
    def add(self, a, b):
        return a + b

    def subtract(self, a, b):
        return a - b

def main():
    calc = Calculator()
    print(calc.add(1, 2))
`)

	p := NewParser()
	symbols, err := p.ExtractSymbolsFromSource(source, "test.py")
	if err != nil {
		t.Fatalf("failed to extract symbols: %v", err)
	}

	if len(symbols) == 0 {
		t.Fatal("expected at least some symbols, got 0")
	}

	found := make(map[string]bool)
	for _, s := range symbols {
		found[string(s.Kind)+":"+s.Name] = true
		t.Logf("Symbol: %s %s (line %d, parent=%s)", s.Kind, s.Name, s.Line, s.Parent)
	}

	if !found["class:Calculator"] {
		t.Error("expected to find class Calculator")
	}
	if !found["function:main"] {
		t.Error("expected to find function main")
	}
}

func TestCanHandleInferredLanguage(t *testing.T) {
	p := NewParser()

	// C# has no custom query but the library can infer one
	if !p.CanHandle("test.cs") {
		t.Error("expected CanHandle to return true for .cs files via inferred query")
	}
	// Swift should also be inferred
	if !p.CanHandle("test.swift") {
		t.Error("expected CanHandle to return true for .swift files via inferred query")
	}
}

func TestExtractRustSymbols(t *testing.T) {
	source := []byte(`fn main() {
    println!("hello");
}

struct Point {
    x: f64,
    y: f64,
}

impl Point {
    fn distance(&self) -> f64 {
        (self.x * self.x + self.y * self.y).sqrt()
    }
}

trait Shape {
    fn area(&self) -> f64;
}

const MAX_SIZE: usize = 100;
`)

	p := NewParser()
	symbols, err := p.ExtractSymbolsFromSource(source, "test.rs")
	if err != nil {
		t.Fatalf("failed to extract symbols: %v", err)
	}

	found := make(map[string]bool)
	for _, s := range symbols {
		found[string(s.Kind)+":"+s.Name] = true
		t.Logf("Symbol: %s %s (line %d, parent=%s)", s.Kind, s.Name, s.Line, s.Parent)
	}

	expected := []string{"function:main", "struct:Point", "interface:Shape", "constant:MAX_SIZE"}
	for _, e := range expected {
		if !found[e] {
			t.Errorf("expected to find symbol %s", e)
		}
	}
}

func TestExtractJavaScriptSymbols(t *testing.T) {
	source := []byte(`class UserService {
  constructor(db) {
    this.db = db;
  }

  getUser(id) {
    return this.db.find(id);
  }
}

function main() {
  const svc = new UserService(null);
}

const helper = () => {
  return 42;
};
`)

	p := NewParser()
	symbols, err := p.ExtractSymbolsFromSource(source, "test.js")
	if err != nil {
		t.Fatalf("failed to extract symbols: %v", err)
	}

	if len(symbols) == 0 {
		t.Fatal("expected at least some symbols, got 0")
	}

	found := make(map[string]bool)
	for _, s := range symbols {
		found[string(s.Kind)+":"+s.Name] = true
		t.Logf("Symbol: %s %s (line %d)", s.Kind, s.Name, s.Line)
	}

	if !found["class:UserService"] {
		t.Error("expected to find class UserService")
	}
	if !found["function:main"] {
		t.Error("expected to find function main")
	}
}

// TestExtractSymbolsRespectsMaxFileSize: oversized file is skipped with
// SkippedFileError. The parser must NOT load the file into memory beyond
// the os.Stat() probe.
func TestExtractSymbolsRespectsMaxFileSize(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "big.go")
	body := "package x\n" + strings.Repeat("// pad\n", 300) // ~2 KB
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	parser := NewParser()
	parser.SetMaxFileSize(1024) // 1 KB cap, file is ~2 KB

	_, err := parser.ExtractSymbols(p, "big.go")
	if err == nil {
		t.Fatal("expected SkippedFileError for oversized file, got nil")
	}
	var skipped *SkippedFileError
	if !errors.As(err, &skipped) {
		t.Fatalf("expected *SkippedFileError, got %T: %v", err, err)
	}
	if skipped.Size <= 1024 {
		t.Errorf("SkippedFileError.Size=%d should exceed cap 1024", skipped.Size)
	}
}

// TestExtractSymbolsBelowCapProceeds: small file under the cap parses
// without a skip error.
func TestExtractSymbolsBelowCapProceeds(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "small.go")
	body := `package x

func Hello() string { return "hi" }
`
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	parser := NewParser()
	parser.SetMaxFileSize(10 * 1024)

	_, err := parser.ExtractSymbols(p, "small.go")
	if err != nil {
		var skipped *SkippedFileError
		if errors.As(err, &skipped) {
			t.Errorf("did not expect skip for small file under cap, got: %v", err)
		}
	}
}

// TestExtractSymbolsDisabledCap: SetMaxFileSize(0) means no cap.
func TestExtractSymbolsDisabledCap(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "huge.go")
	body := "package x\n" + strings.Repeat("// pad\n", 5000)
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	parser := NewParser()
	parser.SetMaxFileSize(0) // disabled

	_, err := parser.ExtractSymbols(p, "huge.go")
	if err != nil {
		var skipped *SkippedFileError
		if errors.As(err, &skipped) {
			t.Errorf("did not expect skip with disabled cap, got: %v", err)
		}
	}
}

// TestDefaultMaxFileSize sanity-checks the default value picks up a
// reasonable bound (avoids accidentally clamping to a tiny value).
func TestDefaultMaxFileSize(t *testing.T) {
	if DefaultMaxFileSize < 1024*1024 {
		t.Errorf("DefaultMaxFileSize=%d is suspiciously small; should be at least 1 MB", DefaultMaxFileSize)
	}
}
