package think

import (
	"testing"

	"github.com/ihavespoons/quokka/internal/memory"
	"github.com/ihavespoons/quokka/internal/project"
)

func TestAnalyzeCollected_ReportsMissingAndCrossRefs(t *testing.T) {
	p, _ := writeTempProject(t)
	p.Config.Classification = project.ProjectClassification{
		Types:  []project.ProjectType{project.TypeWebApp},
		Traits: []project.ProjectTrait{project.TraitHasDatastore},
	}
	if err := p.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	mStore := memory.NewStore(p)
	if err := mStore.Create(&memory.Memory{
		Name:    "project_overview",
		Type:    memory.MemoryTypeContext,
		Content: "A web app. See api_endpoints for routes.",
	}); err != nil {
		_ = mStore.Close()
		t.Fatalf("create overview: %v", err)
	}
	// Close before analyzer creates its own store (bolt holds an flock).
	if err := mStore.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	r, err := AnalyzeCollected(p, CollectedOptions{})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	if len(r.PresentMemories) != 1 || r.PresentMemories[0] != "project_overview" {
		t.Errorf("present = %v", r.PresentMemories)
	}
	// api_endpoints is expected by multiple agents but missing.
	var sawApiMissing bool
	for _, m := range r.MissingExpected {
		if m.Name == "api_endpoints" {
			sawApiMissing = true
			if len(m.ExpectedByAgents) == 0 {
				t.Errorf("missing memory should record expecting agents")
			}
		}
	}
	if !sawApiMissing {
		t.Errorf("expected api_endpoints to be missing, got %v", r.MissingExpected)
	}
}
