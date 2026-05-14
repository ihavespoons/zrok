package agent

import (
	"embed"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ihavespoons/quokka/internal/project"
	"gopkg.in/yaml.v3"
)

//go:embed configs/agents/*.yaml
var embeddedAgents embed.FS

// builtinAgents contains all built-in agent definitions loaded from embedded YAML
var (
	builtinAgents     map[string]*AgentConfig
	builtinAgentsOnce sync.Once
)

// loadBuiltinAgents loads all built-in agents from embedded YAML files
func loadBuiltinAgents() {
	builtinAgentsOnce.Do(func() {
		builtinAgents = make(map[string]*AgentConfig)

		entries, err := embeddedAgents.ReadDir("configs/agents")
		if err != nil {
			return
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
				continue
			}

			path := filepath.Join("configs/agents", entry.Name())
			data, err := embeddedAgents.ReadFile(path)
			if err != nil {
				continue
			}

			var config AgentConfig
			if err := yaml.Unmarshal(data, &config); err != nil {
				continue
			}

			builtinAgents[config.Name] = &config
		}
	})
}

// GetBuiltinAgents returns all built-in agents
func GetBuiltinAgents() []AgentConfig {
	loadBuiltinAgents()

	agents := make([]AgentConfig, 0, len(builtinAgents))
	for _, agent := range builtinAgents {
		agents = append(agents, *agent)
	}
	return agents
}

// GetBuiltinAgent returns a specific built-in agent by name
func GetBuiltinAgent(name string) *AgentConfig {
	loadBuiltinAgents()

	if agent, ok := builtinAgents[name]; ok {
		return agent
	}
	return nil
}

// GetAgentsByPhase returns agents for a specific phase
func GetAgentsByPhase(phase Phase) []AgentConfig {
	loadBuiltinAgents()

	var agents []AgentConfig
	for _, agent := range builtinAgents {
		if agent.Phase == phase {
			agents = append(agents, *agent)
		}
	}
	return agents
}

// GetAgentsByVulnClass returns agents that specialize in a vulnerability class
func GetAgentsByVulnClass(vulnClass string) []AgentConfig {
	loadBuiltinAgents()

	var agents []AgentConfig
	for _, agent := range builtinAgents {
		for _, vc := range agent.Specialization.VulnerabilityClasses {
			if vc == vulnClass {
				agents = append(agents, *agent)
				break
			}
		}
	}
	return agents
}

// SuggestAgents returns agent names that are applicable to the given project
// classification. When p is non-nil, project-local agent YAMLs in
// .quokka/agents/ shadow built-ins of the same name — so an override's
// applicability rules (and any other field) win over the built-in. This is
// what makes the override pattern coherent end-to-end: editing a local
// security-agent.yaml to change applicability changes which PRs it runs on.
func SuggestAgents(p *project.Project, classification project.ProjectClassification) []string {
	loadBuiltinAgents()

	merged := make(map[string]*AgentConfig, len(builtinAgents))
	for name, cfg := range builtinAgents {
		merged[name] = cfg
	}
	if p != nil {
		for name, cfg := range loadProjectAgents(p.GetAgentsPath()) {
			merged[name] = cfg
		}
	}

	var names []string
	for _, agent := range merged {
		if project.ApplicabilityMatches(agent.Applicability, classification) {
			names = append(names, agent.Name)
		}
	}
	return names
}

// loadProjectAgents reads .yaml agent definitions from a project's agents
// directory. Returns an empty map (not an error) when the directory is
// missing, since most projects won't have any local overrides.
func loadProjectAgents(dir string) map[string]*AgentConfig {
	out := map[string]*AgentConfig{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var cfg AgentConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			continue
		}
		if cfg.Name == "" {
			continue
		}
		out[cfg.Name] = &cfg
	}
	return out
}

// GetAgentsByReviewCategory returns agents that cover a specific review category
func GetAgentsByReviewCategory(category string) []AgentConfig {
	loadBuiltinAgents()

	var agents []AgentConfig
	for _, agent := range builtinAgents {
		for _, rc := range agent.Specialization.ReviewCategories {
			if rc == category {
				agents = append(agents, *agent)
				break
			}
		}
	}
	return agents
}
