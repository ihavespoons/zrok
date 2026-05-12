package think

import (
	"strings"
	"testing"

	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/project"
)

func TestAnalyzeNext_RanksOpenHighSeverityFirst(t *testing.T) {
	p, _ := writeTempProject(t)
	p.Config.Classification = project.ProjectClassification{
		Types:  []project.ProjectType{project.TypeWebApp},
		Traits: []project.ProjectTrait{project.TraitHasDatastore},
	}
	if err := p.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	store := finding.NewStore(p)
	if err := store.Create(&finding.Finding{
		Title:    "x",
		Severity: finding.SeverityHigh,
		Status:   finding.StatusOpen,
		CWE:      "CWE-89",
		Location: finding.Location{File: "a.py", LineStart: 1},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	r, err := AnalyzeNext(p, NextOptions{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if r.OpenHighSev != 1 {
		t.Errorf("want 1 open high-sev, got %d", r.OpenHighSev)
	}
	if len(r.Steps) == 0 {
		t.Fatalf("want at least 1 step")
	}
	if r.Steps[0].Priority != "high" {
		t.Errorf("want first step priority=high, got %s", r.Steps[0].Priority)
	}
	if !strings.Contains(r.Steps[0].Action, "Validate") {
		t.Errorf("want validation suggested first, got: %s", r.Steps[0].Action)
	}
}

func TestAnalyzeNext_EmptyProjectSuggestsRecon(t *testing.T) {
	p, _ := writeTempProject(t)
	r, err := AnalyzeNext(p, NextOptions{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.Steps) == 0 {
		t.Fatalf("want at least 1 step")
	}
}
