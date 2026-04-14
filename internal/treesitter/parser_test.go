package treesitter

import (
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
