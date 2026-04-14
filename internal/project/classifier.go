package project

import (
	"embed"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed configs/classification_rules.yaml
var embeddedRules embed.FS

// classificationRules is the parsed rules from embedded YAML
type classificationRules struct {
	Types  map[string]typeRule  `yaml:"types"`
	Traits map[string]traitRule `yaml:"traits"`
}

type typeRule struct {
	FrameworkKeywords []string `yaml:"framework_keywords"`
}

type traitRule struct {
	Condition string `yaml:"condition"`
}

// Classifier infers project classification from detected tech stack.
type Classifier struct {
	rules classificationRules
}

// NewClassifier creates a classifier with embedded rules.
func NewClassifier() *Classifier {
	c := &Classifier{}
	data, err := embeddedRules.ReadFile("configs/classification_rules.yaml")
	if err != nil {
		return c
	}
	_ = yaml.Unmarshal(data, &c.rules)
	return c
}

// Classify infers project types and traits from the project config.
func (c *Classifier) Classify(config *ProjectConfig) ProjectClassification {
	var classification ProjectClassification

	// Collect all framework names into a lowercase set
	frameworks := make(map[string]bool)
	for _, lang := range config.TechStack.Languages {
		for _, fw := range lang.Frameworks {
			frameworks[strings.ToLower(fw)] = true
		}
	}

	// Match framework keywords against type rules
	for typeName, rule := range c.rules.Types {
		for _, keyword := range rule.FrameworkKeywords {
			if frameworks[strings.ToLower(keyword)] {
				classification.Types = append(classification.Types, ProjectType(typeName))
				break
			}
		}
	}

	// Evaluate trait conditions against TechStack
	for traitName, rule := range c.rules.Traits {
		if c.evaluateCondition(rule.Condition, config) {
			classification.Traits = append(classification.Traits, ProjectTrait(traitName))
		}
	}

	// Fallback: if no types matched but we have languages, classify as library
	if len(classification.Types) == 0 && len(config.TechStack.Languages) > 0 {
		classification.Types = append(classification.Types, TypeLibrary)
	}

	return classification
}

// evaluateCondition maps condition strings to TechStack checks.
func (c *Classifier) evaluateCondition(condition string, config *ProjectConfig) bool {
	switch condition {
	case "databases_detected":
		return len(config.TechStack.Databases) > 0
	case "auth_detected":
		return len(config.TechStack.Auth) > 0
	case "infrastructure_detected":
		return len(config.TechStack.Infrastructure) > 0
	case "sensitive_areas_detected":
		return len(config.SecurityScope.SensitiveAreas) > 0
	default:
		return false
	}
}
