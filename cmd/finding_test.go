package cmd

import (
	"os"
	"testing"
	"time"

	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/project"
)

func setupFindingTestProject(t *testing.T) (*project.Project, func()) {
	t.Helper()
	tmp, err := os.MkdirTemp("", "zrok-cmd-finding-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	p, err := project.Initialize(tmp)
	if err != nil {
		_ = os.RemoveAll(tmp)
		t.Fatalf("init: %v", err)
	}
	return p, func() { _ = os.RemoveAll(tmp) }
}

// TestValidateOwnsCWEsInScope: an in-scope CWE for a known agent passes silently.
func TestValidateOwnsCWEsInScope(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	f := &finding.Finding{
		Title:     "InScope",
		CWE:       "CWE-89", // owned by injection-agent
		CreatedBy: "injection-agent",
	}
	if err := validateOwnsCWEs(p, f, false); err != nil {
		t.Errorf("expected no error for in-scope CWE, got: %v", err)
	}
	if err := validateOwnsCWEs(p, f, true); err != nil {
		t.Errorf("expected no error under --strict for in-scope CWE, got: %v", err)
	}
}

// TestValidateOwnsCWEsOutOfScopeWarn: out-of-scope CWE warns but returns nil
// (no error) in non-strict mode.
func TestValidateOwnsCWEsOutOfScopeWarn(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	f := &finding.Finding{
		Title:     "OutOfScope",
		CWE:       "CWE-79", // NOT owned by injection-agent
		CreatedBy: "injection-agent",
	}
	if err := validateOwnsCWEs(p, f, false); err != nil {
		t.Errorf("expected nil err in warn mode, got: %v", err)
	}
}

// TestValidateOwnsCWEsOutOfScopeStrict: --strict rejects out-of-scope CWE with error.
func TestValidateOwnsCWEsOutOfScopeStrict(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	f := &finding.Finding{
		Title:     "OutOfScopeStrict",
		CWE:       "CWE-79",
		CreatedBy: "injection-agent",
	}
	err := validateOwnsCWEs(p, f, true)
	if err == nil {
		t.Fatal("expected error under --strict for out-of-scope CWE")
	}
}

// TestValidateOwnsCWEsUnknownAgent: agent not in registry => no validation.
func TestValidateOwnsCWEsUnknownAgent(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	f := &finding.Finding{
		Title:     "UnknownAgent",
		CWE:       "CWE-79",
		CreatedBy: "no-such-agent-xyz",
	}
	if err := validateOwnsCWEs(p, f, true); err != nil {
		t.Errorf("expected nil err for unknown agent (skip validation), got: %v", err)
	}
}

// TestValidateOwnsCWEsNoCreatedBy: empty created_by => no validation.
func TestValidateOwnsCWEsNoCreatedBy(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	f := &finding.Finding{
		Title: "NoCreator",
		CWE:   "CWE-79",
	}
	if err := validateOwnsCWEs(p, f, true); err != nil {
		t.Errorf("expected nil err with no created_by, got: %v", err)
	}
}

// TestValidateOwnsCWEsCaseInsensitive: CWE compare is case-insensitive.
func TestValidateOwnsCWEsCaseInsensitive(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	f := &finding.Finding{
		Title:     "LowerCase",
		CWE:       "cwe-89",
		CreatedBy: "injection-agent",
	}
	if err := validateOwnsCWEs(p, f, true); err != nil {
		t.Errorf("expected case-insensitive CWE match, got: %v", err)
	}
}

// TestFindingNotesRoundTrip: notes appended via repeated updates are preserved
// in order through save/read cycles.
func TestFindingNotesRoundTrip(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	store := finding.NewStore(p)
	f := &finding.Finding{
		Title:      "with notes",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceHigh,
		Location: finding.Location{
			File:      "app.py",
			LineStart: 1,
		},
		Description: "test",
	}
	if err := store.Create(f); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Append first note
	loaded, err := store.Read(f.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	loaded.Notes = append(loaded.Notes, finding.FindingNote{
		Timestamp: time.Now(),
		Author:    "tester",
		Text:      "first note",
	})
	if err := store.Update(loaded); err != nil {
		t.Fatalf("update 1: %v", err)
	}

	// Append second note
	loaded, err = store.Read(f.ID)
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}
	loaded.Notes = append(loaded.Notes, finding.FindingNote{
		Timestamp: time.Now(),
		Author:    "tester",
		Text:      "second note",
	})
	if err := store.Update(loaded); err != nil {
		t.Fatalf("update 2: %v", err)
	}

	final, err := store.Read(f.ID)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if len(final.Notes) != 2 {
		t.Fatalf("expected 2 notes, got %d", len(final.Notes))
	}
	if final.Notes[0].Text != "first note" {
		t.Errorf("expected first note 'first note', got %q", final.Notes[0].Text)
	}
	if final.Notes[1].Text != "second note" {
		t.Errorf("expected second note 'second note', got %q", final.Notes[1].Text)
	}
	if final.Notes[0].Author != "tester" {
		t.Errorf("expected author 'tester', got %q", final.Notes[0].Author)
	}
}

// TestFindingDuplicateOfAndNotesPersist: confirms duplicate_of and notes
// survive a YAML save/load round-trip (so JSON output via --json works for free).
func TestFindingDuplicateOfAndNotesPersist(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	store := finding.NewStore(p)
	f := &finding.Finding{
		Title:      "duplicate marker",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceHigh,
		Location: finding.Location{
			File:      "app.py",
			LineStart: 1,
		},
		Description: "test",
		DuplicateOf: "FIND-999",
		Notes: []finding.FindingNote{
			{Timestamp: time.Now(), Author: "alice", Text: "looks like a dup"},
		},
	}
	if err := store.Create(f); err != nil {
		t.Fatalf("create: %v", err)
	}
	loaded, err := store.Read(f.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if loaded.DuplicateOf != "FIND-999" {
		t.Errorf("DuplicateOf not preserved: %q", loaded.DuplicateOf)
	}
	if len(loaded.Notes) != 1 || loaded.Notes[0].Text != "looks like a dup" {
		t.Errorf("Notes not preserved: %+v", loaded.Notes)
	}
}
