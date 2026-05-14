package think

import (
	"testing"

	"github.com/diffsec/quokka/internal/memory"
	"github.com/diffsec/quokka/internal/project"
)

func TestAnalyzeHypothesis_TechHintsProduceRankedCWEs(t *testing.T) {
	p, _ := writeTempProject(t)
	// Set classification so applicable agents include injection-agent.
	p.Config.Classification = project.ProjectClassification{
		Types:  []project.ProjectType{project.TypeWebApp},
		Traits: []project.ProjectTrait{project.TraitHasDatastore},
	}
	if err := p.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	r, err := AnalyzeHypothesis(p, HypothesisOptions{Tech: []string{"sqlite", "sqlalchemy"}})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.Hypotheses) == 0 {
		t.Fatalf("want hypotheses, got 0")
	}
	if r.Hypotheses[0].CWE != "CWE-89" {
		t.Errorf("want top hypothesis CWE-89, got %s", r.Hypotheses[0].CWE)
	}
	if r.Hypotheses[0].Score < 1 {
		t.Errorf("want positive score, got %d", r.Hypotheses[0].Score)
	}
	if r.Hypotheses[0].Test == "" {
		t.Errorf("want a test command on hypothesis")
	}
}

func TestAnalyzeHypothesis_MemoryEvidence(t *testing.T) {
	p, _ := writeTempProject(t)
	p.Config.Classification = project.ProjectClassification{
		Types:  []project.ProjectType{project.TypeWebApp},
		Traits: []project.ProjectTrait{project.TraitHasDatastore},
	}
	if err := p.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Add a memory mentioning eval/exec keywords for CWE-94.
	mStore := memory.NewStore(p)
	if err := mStore.Create(&memory.Memory{
		Name:    "codeinj_notes",
		Type:    memory.MemoryTypeContext,
		Content: "Several endpoints call eval() directly on user input via exec()",
	}); err != nil {
		_ = mStore.Close()
		t.Fatalf("create memory: %v", err)
	}
	// Close before analyzer opens its own bolt-backed index.
	if err := mStore.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	r, err := AnalyzeHypothesis(p, HypothesisOptions{Memories: []string{"codeinj_notes"}})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	var seen bool
	for _, h := range r.Hypotheses {
		if h.CWE == "CWE-94" {
			seen = true
			break
		}
	}
	if !seen {
		t.Errorf("want CWE-94 hypothesis from memory evidence")
	}
}
