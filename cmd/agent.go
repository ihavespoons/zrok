package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/ihavespoons/zrok/internal/agent"
	"github.com/ihavespoons/zrok/internal/memory"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// agentCmd represents the agent command
var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage agent configurations",
	Long: `Manage security analysis agents and their configurations.

Agents are specialized analyzers with specific focus areas and prompt templates.
Built-in agents include reconnaissance, injection analysis, authentication,
cryptography, configuration, and business logic specialists.`,
}

// agentListCmd represents the agent list command
var agentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available agents",
	Long:  `List all available agents (both built-in and project-specific).`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		// Get built-in config path (may not exist)
		builtinPath := ""
		if exe, err := os.Executable(); err == nil {
			builtinPath = exe + "/../configs/agents"
		}

		manager := agent.NewConfigManager(p, builtinPath)
		result, err := manager.List()
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(result)
		} else {
			// Group by phase
			phases := map[agent.Phase][]agent.AgentConfig{
				agent.PhaseRecon:      {},
				agent.PhaseAnalysis:   {},
				agent.PhaseValidation: {},
				agent.PhaseReporting:  {},
			}

			for _, a := range result.Agents {
				phases[a.Phase] = append(phases[a.Phase], a)
			}

			phaseOrder := []agent.Phase{agent.PhaseRecon, agent.PhaseAnalysis, agent.PhaseValidation, agent.PhaseReporting}
			phaseNames := map[agent.Phase]string{
				agent.PhaseRecon:      "Reconnaissance",
				agent.PhaseAnalysis:   "Analysis",
				agent.PhaseValidation: "Validation",
				agent.PhaseReporting:  "Reporting",
			}

			for _, phase := range phaseOrder {
				agents := phases[phase]
				if len(agents) == 0 {
					continue
				}
				fmt.Printf("=== %s Phase ===\n", phaseNames[phase])
				for _, a := range agents {
					fmt.Printf("  %s\n", a.Name)
					fmt.Printf("    %s\n", a.Description)
				}
				fmt.Println()
			}

			fmt.Printf("Total: %d agents\n", result.Total)
		}
	},
}

// agentShowCmd represents the agent show command
var agentShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show agent configuration",
	Long:  `Show detailed configuration for a specific agent.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		builtinPath := ""
		manager := agent.NewConfigManager(p, builtinPath)
		config, err := manager.Get(args[0])
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(config)
		} else {
			fmt.Printf("Name: %s\n", config.Name)
			fmt.Printf("Description: %s\n", config.Description)
			fmt.Printf("Phase: %s\n", config.Phase)

			if len(config.Specialization.VulnerabilityClasses) > 0 {
				fmt.Printf("Vulnerability Classes: %s\n", strings.Join(config.Specialization.VulnerabilityClasses, ", "))
			}
			if len(config.Specialization.OWASPCategories) > 0 {
				fmt.Printf("OWASP Categories: %s\n", strings.Join(config.Specialization.OWASPCategories, ", "))
			}
			if len(config.ToolsAllowed) > 0 {
				fmt.Printf("Tools Allowed: %s\n", strings.Join(config.ToolsAllowed, ", "))
			}
			if len(config.ContextMemories) > 0 {
				fmt.Printf("Context Memories: %s\n", strings.Join(config.ContextMemories, ", "))
			}
		}
	},
}

// agentCreateCmd represents the agent create command
var agentCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a custom agent",
	Long:  `Create a new project-specific agent configuration from a YAML file.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		file, _ := cmd.Flags().GetString("file")
		if file == "" {
			exitError("provide agent configuration via --file flag")
		}

		data, err := os.ReadFile(file)
		if err != nil {
			exitError("failed to read file: %v", err)
		}

		var config agent.AgentConfig
		if err := yaml.Unmarshal(data, &config); err != nil {
			exitError("failed to parse agent config: %v", err)
		}

		config.Name = args[0]
		builtinPath := ""
		manager := agent.NewConfigManager(p, builtinPath)

		if err := manager.Create(&config); err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(map[string]interface{}{
				"success": true,
				"name":    config.Name,
			})
		} else {
			fmt.Printf("Created agent: %s\n", config.Name)
		}
	},
}

// agentPromptCmd represents the agent prompt command
var agentPromptCmd = &cobra.Command{
	Use:   "prompt <name>",
	Short: "Generate agent prompt",
	Long:  `Generate the complete prompt for an agent, including project context and memories.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		builtinPath := ""
		manager := agent.NewConfigManager(p, builtinPath)
		config, err := manager.Get(args[0])
		if err != nil {
			exitError("%v", err)
		}

		memStore := memory.NewStore(p)
		generator := agent.NewPromptGenerator(p, memStore)

		context, _ := cmd.Flags().GetString("context")
		var prompt string
		if context != "" {
			prompt, err = generator.GenerateWithContext(config, context)
		} else {
			prompt, err = generator.Generate(config)
		}

		if err != nil {
			exitError("failed to generate prompt: %v", err)
		}

		if jsonOutput {
			outputJSON(map[string]interface{}{
				"agent":  config.Name,
				"prompt": prompt,
			})
		} else {
			fmt.Println(prompt)
		}
	},
}

// agentGenerateCmd represents the agent generate command
var agentGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate agents from onboarding",
	Long:  `Generate recommended agent configurations based on the project's tech stack.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		if p.Config == nil {
			exitError("project not onboarded, run 'zrok onboard' first")
		}

		// Get recommended agents based on tech stack
		var recommended []string

		// Always recommend base agents
		recommended = append(recommended, "recon-agent", "static-agent", "dataflow-agent", "validation-agent")

		stack := p.Config.TechStack

		// Add agents based on databases
		if len(stack.Databases) > 0 {
			recommended = append(recommended, "injection-agent")
		}

		// Add agents based on auth
		if len(stack.Auth) > 0 {
			recommended = append(recommended, "auth-agent")
		}

		// Always add crypto and config agents
		recommended = append(recommended, "crypto-agent", "config-agent", "logic-agent")

		if jsonOutput {
			outputJSON(map[string]interface{}{
				"recommended_agents": recommended,
				"tech_stack":         stack,
			})
		} else {
			fmt.Println("Recommended agents based on tech stack:")
			fmt.Println()
			for _, name := range recommended {
				builtinAgent := agent.GetBuiltinAgent(name)
				if builtinAgent != nil {
					fmt.Printf("  %s\n", name)
					fmt.Printf("    %s\n", builtinAgent.Description)
				} else {
					fmt.Printf("  %s\n", name)
				}
			}
			fmt.Println()
			fmt.Println("Generate prompts with: zrok agent prompt <name>")
		}
	},
}

func init() {
	rootCmd.AddCommand(agentCmd)
	agentCmd.AddCommand(agentListCmd)
	agentCmd.AddCommand(agentShowCmd)
	agentCmd.AddCommand(agentCreateCmd)
	agentCmd.AddCommand(agentPromptCmd)
	agentCmd.AddCommand(agentGenerateCmd)

	agentCreateCmd.Flags().StringP("file", "f", "", "YAML file containing agent configuration")

	agentPromptCmd.Flags().StringP("context", "c", "", "Additional context to include in prompt")
}
