package think

import (
	"testing"

	"github.com/diffsec/quokka/internal/finding"
)

func TestAnalyzeAdherence_InAndOutOfScope(t *testing.T) {
	p, _ := writeTempProject(t)
	store := finding.NewStore(p)

	// in-scope: injection-agent owns CWE-89
	if err := store.Create(&finding.Finding{
		Title:    "in-scope",
		Severity: finding.SeverityHigh,
		Status:   finding.StatusOpen,
		CWE:      "CWE-89",
		Location: finding.Location{File: "a.py", LineStart: 1},
		CreatedBy: "injection-agent",
	}); err != nil {
		t.Fatalf("create in: %v", err)
	}
	// out-of-scope: injection-agent does not own CWE-79
	if err := store.Create(&finding.Finding{
		Title:    "out-of-scope",
		Severity: finding.SeverityMedium,
		Status:   finding.StatusOpen,
		CWE:      "CWE-79",
		Location: finding.Location{File: "b.py", LineStart: 1},
		CreatedBy: "injection-agent",
	}); err != nil {
		t.Fatalf("create out: %v", err)
	}

	r, err := AnalyzeAdherence(p, AdherenceOptions{Agent: "injection-agent"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.InScope) != 1 {
		t.Errorf("want 1 in-scope, got %d", len(r.InScope))
	}
	if len(r.OutOfScope) != 1 {
		t.Errorf("want 1 out-of-scope, got %d", len(r.OutOfScope))
	}
}

func TestAnalyzeAdherence_UnknownAgent(t *testing.T) {
	p, _ := writeTempProject(t)
	_, err := AnalyzeAdherence(p, AdherenceOptions{Agent: "nonexistent-agent"})
	if err == nil {
		t.Errorf("want error for unknown agent")
	}
}
