package agent

import (
	"testing"
)

func TestGetExamplesForCWEs(t *testing.T) {
	examples := GetExamplesForCWEs([]string{"CWE-89"})
	if len(examples) == 0 {
		t.Fatal("expected examples for CWE-89, got none")
	}

	for _, ex := range examples {
		if ex.CWE != "CWE-89" {
			t.Errorf("expected CWE-89, got %s", ex.CWE)
		}
		if ex.Name == "" {
			t.Error("expected non-empty name")
		}
		if ex.Language == "" {
			t.Error("expected non-empty language")
		}
		if ex.Vulnerable == "" {
			t.Error("expected non-empty vulnerable code")
		}
		if ex.Patched == "" {
			t.Error("expected non-empty patched code")
		}
		if ex.Explanation == "" {
			t.Error("expected non-empty explanation")
		}
	}
}

func TestGetExamplesForMultipleCWEs(t *testing.T) {
	examples := GetExamplesForCWEs([]string{"CWE-89", "CWE-79"})
	if len(examples) < 2 {
		t.Fatalf("expected at least 2 examples for CWE-89+CWE-79, got %d", len(examples))
	}

	hasSQLi := false
	hasXSS := false
	for _, ex := range examples {
		if ex.CWE == "CWE-89" {
			hasSQLi = true
		}
		if ex.CWE == "CWE-79" {
			hasXSS = true
		}
	}
	if !hasSQLi {
		t.Error("expected SQL injection examples")
	}
	if !hasXSS {
		t.Error("expected XSS examples")
	}
}

func TestGetExamplesForUnknownCWE(t *testing.T) {
	examples := GetExamplesForCWEs([]string{"CWE-99999"})
	if len(examples) != 0 {
		t.Errorf("expected no examples for unknown CWE, got %d", len(examples))
	}
}

func TestGetExamplesForCWEAndLanguage(t *testing.T) {
	examples := GetExamplesForCWEAndLanguage("CWE-89", "go")
	if len(examples) == 0 {
		t.Fatal("expected Go examples for CWE-89, got none")
	}
	for _, ex := range examples {
		if ex.Language != "go" {
			t.Errorf("expected language 'go', got '%s'", ex.Language)
		}
	}

	// Test filtering excludes other languages
	jsExamples := GetExamplesForCWEAndLanguage("CWE-89", "javascript")
	if len(jsExamples) == 0 {
		t.Fatal("expected JavaScript examples for CWE-89, got none")
	}
	for _, ex := range jsExamples {
		if ex.Language != "javascript" {
			t.Errorf("expected language 'javascript', got '%s'", ex.Language)
		}
	}
}
