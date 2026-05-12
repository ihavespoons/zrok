package think

import (
	"testing"

	"github.com/ihavespoons/zrok/internal/finding"
)

func TestAnalyzeDone_RequiresAgent(t *testing.T) {
	p, _ := writeTempProject(t)
	_, err := AnalyzeDone(p, DoneOptions{})
	if err == nil {
		t.Errorf("want error when agent missing")
	}
}

func TestAnalyzeDone_UnknownAgent(t *testing.T) {
	p, _ := writeTempProject(t)
	_, err := AnalyzeDone(p, DoneOptions{Agent: "doesnt-exist"})
	if err == nil {
		t.Errorf("want error for unknown agent")
	}
}

func TestAnalyzeDone_ScoresFindings(t *testing.T) {
	p, _ := writeTempProject(t)
	store := finding.NewStore(p)
	// One finding for each injection-agent owned CWE (CWE-89, 78, 94, 643, 917).
	for _, cwe := range []string{"CWE-89", "CWE-78", "CWE-94", "CWE-643", "CWE-917"} {
		if err := store.Create(&finding.Finding{
			Title:    "x",
			Severity: finding.SeverityMedium,
			Status:   finding.StatusConfirmed,
			CWE:      cwe,
			Location: finding.Location{File: "a.py", LineStart: 1},
			CreatedBy: "injection-agent",
		}); err != nil {
			t.Fatalf("create %s: %v", cwe, err)
		}
	}

	r, err := AnalyzeDone(p, DoneOptions{Agent: "injection-agent"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	// All CWEs covered, but memories missing -> partial.
	if r.CompletenessPct == 0 {
		t.Errorf("want non-zero completeness")
	}
	// CWE coverage should report 5/5 finding counts > 0.
	for _, c := range r.CWECoverage {
		if c.FindingCount == 0 && !c.HasNullResult {
			t.Errorf("CWE %s not covered", c.CWE)
		}
	}
}
