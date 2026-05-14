package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ihavespoons/quokka/internal/project"
)

func contains(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}

func TestSuggestAgents_NoProjectFallsBackToBuiltins(t *testing.T) {
	suggested := SuggestAgents(nil, project.ProjectClassification{
		Types: []project.ProjectType{project.TypeWebApp},
	})
	if len(suggested) == 0 {
		t.Fatal("expected at least one built-in to match for web-app")
	}
}

func TestSuggestAgents_ProjectOverrideShadowsBuiltin(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	// Built-in security-agent applies to web-app + has-auth. Override it to
	// apply ONLY to worker projects, then verify it disappears from web-app
	// suggestions and appears in worker suggestions.
	overridePath := filepath.Join(p.GetAgentsPath(), "security-agent.yaml")
	if err := os.MkdirAll(filepath.Dir(overridePath), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	overrideYAML := `name: security-agent
description: Overridden security agent for worker projects only
phase: analysis
applicability:
  project_types: [worker]
prompt_template: "overridden"
`
	if err := os.WriteFile(overridePath, []byte(overrideYAML), 0644); err != nil {
		t.Fatalf("write override: %v", err)
	}

	webSuggested := SuggestAgents(p, project.ProjectClassification{
		Types:  []project.ProjectType{project.TypeWebApp},
		Traits: []project.ProjectTrait{project.TraitHasAuth},
	})
	if contains(webSuggested, "security-agent") {
		t.Errorf("override should have removed security-agent from web-app suggestions, got: %v", webSuggested)
	}

	workerSuggested := SuggestAgents(p, project.ProjectClassification{
		Types: []project.ProjectType{project.TypeWorker},
	})
	if !contains(workerSuggested, "security-agent") {
		t.Errorf("override should make security-agent apply to worker, got: %v", workerSuggested)
	}
}

func TestSuggestAgents_ProjectAddsNewAgent(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	// A wholly-new agent not in the registry should also be suggested when
	// applicability matches.
	path := filepath.Join(p.GetAgentsPath(), "custom-pii-agent.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	yaml := `name: custom-pii-agent
description: Org-specific PII handling rules
phase: analysis
applicability:
  project_traits: [has-datastore]
prompt_template: "check PII handling"
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	suggested := SuggestAgents(p, project.ProjectClassification{
		Traits: []project.ProjectTrait{project.TraitHasDatastore},
	})
	if !contains(suggested, "custom-pii-agent") {
		t.Errorf("expected custom-pii-agent in suggestions, got: %v", suggested)
	}
}

func TestSuggestAgents_NilProjectIgnoresLocalOverrides(t *testing.T) {
	// When the caller has no project context (e.g. a library use), built-in
	// behavior is preserved — no surprises from the working directory.
	p, cleanup := setupTestProject(t)
	defer cleanup()

	overridePath := filepath.Join(p.GetAgentsPath(), "security-agent.yaml")
	_ = os.MkdirAll(filepath.Dir(overridePath), 0755)
	override := `name: security-agent
description: Worker-only override
applicability:
  project_types: [worker]
`
	_ = os.WriteFile(overridePath, []byte(override), 0644)

	// Passing nil — override should be ignored.
	suggested := SuggestAgents(nil, project.ProjectClassification{
		Types:  []project.ProjectType{project.TypeWebApp},
		Traits: []project.ProjectTrait{project.TraitHasAuth},
	})
	if !contains(suggested, "security-agent") {
		t.Errorf("nil project should ignore local override; expected security-agent in web-app suggestions, got: %v", suggested)
	}
}
