package agent

import (
	"embed"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed configs/agents/*.yaml
var embeddedAgents embed.FS

// builtinAgents contains all built-in agent definitions loaded from embedded YAML
var (
	builtinAgents     map[string]*AgentConfig
	builtinAgentsOnce sync.Once
	builtinAgentsErr  error
)

// loadBuiltinAgents loads all built-in agents from embedded YAML files
func loadBuiltinAgents() {
	builtinAgentsOnce.Do(func() {
		builtinAgents = make(map[string]*AgentConfig)

		entries, err := embeddedAgents.ReadDir("configs/agents")
		if err != nil {
			builtinAgentsErr = fmt.Errorf("failed to read embedded agents directory: %w", err)
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
