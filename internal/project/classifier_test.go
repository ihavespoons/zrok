package project

import (
	"slices"
	"testing"
)

func TestClassifyWebApp(t *testing.T) {
	c := NewClassifier()
	config := &ProjectConfig{
		TechStack: TechStack{
			Languages: []Language{
				{Name: "python", Frameworks: []string{"flask", "sqlalchemy"}},
			},
			Databases: []string{"sqlite"},
			Auth:      []string{"ldap"},
		},
		SecurityScope: SecurityScope{
			SensitiveAreas: []SensitiveArea{{Path: "auth/", Reason: "Authentication logic"}},
		},
	}

	result := c.Classify(config)

	if !slices.Contains(result.Types, TypeWebApp) {
		t.Errorf("expected web-app type, got %v", result.Types)
	}
	if !slices.Contains(result.Traits, TraitHasDatastore) {
		t.Errorf("expected has-datastore trait, got %v", result.Traits)
	}
	if !slices.Contains(result.Traits, TraitHasAuth) {
		t.Errorf("expected has-auth trait, got %v", result.Traits)
	}
	if !slices.Contains(result.Traits, TraitHasSensitiveData) {
		t.Errorf("expected has-sensitive-data trait, got %v", result.Traits)
	}
}

func TestClassifyCLITool(t *testing.T) {
	c := NewClassifier()
	config := &ProjectConfig{
		TechStack: TechStack{
			Languages: []Language{
				{Name: "go", Frameworks: []string{"cobra"}},
			},
		},
	}

	result := c.Classify(config)

	if !slices.Contains(result.Types, TypeCLITool) {
		t.Errorf("expected cli-tool type, got %v", result.Types)
	}
	if len(result.Traits) != 0 {
		t.Errorf("expected no traits, got %v", result.Traits)
	}
}

func TestClassifyMultiType(t *testing.T) {
	c := NewClassifier()
	config := &ProjectConfig{
		TechStack: TechStack{
			Languages: []Language{
				{Name: "javascript", Frameworks: []string{"express"}},
			},
			Databases: []string{"mongodb"},
			Auth:      []string{"jwt"},
		},
	}

	result := c.Classify(config)

	// express should match both web-app and api-service
	if !slices.Contains(result.Types, TypeWebApp) {
		t.Errorf("expected web-app type, got %v", result.Types)
	}
	if !slices.Contains(result.Types, TypeAPIService) {
		t.Errorf("expected api-service type, got %v", result.Types)
	}
	if !slices.Contains(result.Traits, TraitHasDatastore) {
		t.Errorf("expected has-datastore trait, got %v", result.Traits)
	}
	if !slices.Contains(result.Traits, TraitHasAuth) {
		t.Errorf("expected has-auth trait, got %v", result.Traits)
	}
}

func TestClassifyLibraryFallback(t *testing.T) {
	c := NewClassifier()
	config := &ProjectConfig{
		TechStack: TechStack{
			Languages: []Language{
				{Name: "go", Frameworks: []string{}},
			},
		},
	}

	result := c.Classify(config)

	if !slices.Contains(result.Types, TypeLibrary) {
		t.Errorf("expected library type as fallback, got %v", result.Types)
	}
}

func TestClassifyEmptyProject(t *testing.T) {
	c := NewClassifier()
	config := &ProjectConfig{}

	result := c.Classify(config)

	if len(result.Types) != 0 {
		t.Errorf("expected no types for empty project, got %v", result.Types)
	}
	if len(result.Traits) != 0 {
		t.Errorf("expected no traits for empty project, got %v", result.Traits)
	}
}

func TestClassifyWorker(t *testing.T) {
	c := NewClassifier()
	config := &ProjectConfig{
		TechStack: TechStack{
			Languages: []Language{
				{Name: "python", Frameworks: []string{"celery"}},
			},
			Databases:      []string{"redis"},
			Infrastructure: []string{"docker"},
		},
	}

	result := c.Classify(config)

	if !slices.Contains(result.Types, TypeWorker) {
		t.Errorf("expected worker type, got %v", result.Types)
	}
	if !slices.Contains(result.Traits, TraitHasDatastore) {
		t.Errorf("expected has-datastore trait, got %v", result.Traits)
	}
	if !slices.Contains(result.Traits, TraitHasInfrastructure) {
		t.Errorf("expected has-infrastructure trait, got %v", result.Traits)
	}
}

func TestApplicabilityMatches(t *testing.T) {
	classification := ProjectClassification{
		Types:  []ProjectType{TypeWebApp, TypeAPIService},
		Traits: []ProjectTrait{TraitHasDatastore, TraitHasAuth},
	}

	// always_include
	if !ApplicabilityMatches(ApplicabilityRule{AlwaysInclude: true}, classification) {
		t.Error("always_include should match")
	}

	// type match
	if !ApplicabilityMatches(ApplicabilityRule{ProjectTypes: []string{"web-app"}}, classification) {
		t.Error("web-app type should match")
	}

	// trait match
	if !ApplicabilityMatches(ApplicabilityRule{ProjectTraits: []string{"has-datastore"}}, classification) {
		t.Error("has-datastore trait should match")
	}

	// no match
	if ApplicabilityMatches(ApplicabilityRule{ProjectTypes: []string{"cli-tool"}}, classification) {
		t.Error("cli-tool type should not match")
	}

	// empty rule should not match
	if ApplicabilityMatches(ApplicabilityRule{}, classification) {
		t.Error("empty rule should not match")
	}
}
