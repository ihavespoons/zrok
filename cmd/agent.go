package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/ihavespoons/quokka/internal/agent"
	"github.com/ihavespoons/quokka/internal/finding"
	"github.com/ihavespoons/quokka/internal/memory"
	"github.com/ihavespoons/quokka/internal/project"
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
			if err := outputJSON(result); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
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
			if err := outputJSON(config); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
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
			if err := outputJSON(map[string]interface{}{
				"success": true,
				"name":    config.Name,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
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
		findingID, _ := cmd.Flags().GetString("finding")

		// If --finding is supplied, load it and prepend its YAML to the context.
		if findingID != "" {
			findingStore := finding.NewStore(p)
			f, err := findingStore.Read(findingID)
			if err != nil {
				exitError("failed to load finding %s: %v", findingID, err)
			}
			data, err := yaml.Marshal(f)
			if err != nil {
				exitError("failed to marshal finding: %v", err)
			}
			findingSection := fmt.Sprintf("## Finding to Investigate\n\nThe following finding (%s) requires deep review:\n\n```yaml\n%s```\n",
				f.ID, string(data))
			if context != "" {
				context = findingSection + "\n" + context
			} else {
				context = findingSection
			}
		}

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
			if err := outputJSON(map[string]interface{}{
				"agent":  config.Name,
				"prompt": prompt,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
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
			exitError("project not onboarded, run 'quokka onboard' first")
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
			if err := outputJSON(map[string]interface{}{
				"recommended_agents": recommended,
				"tech_stack":         stack,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
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
			fmt.Println("Generate prompts with: quokka agent prompt <name>")
		}
	},
}

// agentVerifyMemoriesCmd checks that all memories referenced by an agent's
// context_memories list are present in the project's memory store.
var agentVerifyMemoriesCmd = &cobra.Command{
	Use:   "verify-memories [agent-name]",
	Short: "Verify that an agent's expected context memories exist",
	Long: `Verify that all memories listed in an agent's context_memories field
have been created in the project's .quokka/memories/ directory.

Use --all to verify every analysis-phase agent at once.

Exit code is 0 if all expected memories are present, 1 otherwise.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		all, _ := cmd.Flags().GetBool("all")
		if !all && len(args) == 0 {
			exitError("provide an agent name or use --all")
		}
		if all && len(args) > 0 {
			exitError("--all cannot be combined with an agent name")
		}

		memStore := memory.NewStore(p)
		manager := agent.NewConfigManager(p, "")

		if all {
			result, err := agent.VerifyAnalysisAgents(manager, memStore)
			if err != nil {
				exitError("%v", err)
			}
			if jsonOutput {
				if err := outputJSON(result); err != nil {
					exitError("failed to encode JSON: %v", err)
				}
			} else {
				printAggregateVerification(result)
			}
			if !result.Pass {
				os.Exit(1)
			}
			return
		}

		name := args[0]
		cfg, err := manager.Get(name)
		if err != nil {
			exitError("%v", err)
		}

		rpt := agent.VerifyAgentMemories(cfg, memStore)
		if jsonOutput {
			if err := outputJSON(rpt); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			printAgentVerification(rpt)
		}
		if !rpt.Pass {
			os.Exit(1)
		}
	},
}

// agentRecordTimingCmd is a lightweight hook the orchestrating skill can call
// to record per-agent execution timings. The data is written to
// .quokka/run-state.json and later merged into the eval run manifest.
var agentRecordTimingCmd = &cobra.Command{
	Use:   "record-timing <agent-name>",
	Short: "Record start or end timing for an agent invocation",
	Long: `Record per-agent execution timing into .quokka/run-state.json.

Call with --start before spawning an agent, and --end after it completes.
The eval scorer merges this data into the run manifest as best-effort timing.
This command is intended to be invoked by an orchestrating skill or script.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		name := args[0]
		phase, _ := cmd.Flags().GetString("phase")
		start, _ := cmd.Flags().GetBool("start")
		end, _ := cmd.Flags().GetBool("end")
		findingsCreated, _ := cmd.Flags().GetInt("findings-created")
		memoriesCreated, _ := cmd.Flags().GetInt("memories-created")

		if start == end {
			exitError("provide exactly one of --start or --end")
		}

		if start {
			if err := agent.RecordStart(p, name, phase); err != nil {
				exitError("%v", err)
			}
			if !jsonOutput {
				fmt.Printf("Recorded start for %s\n", name)
			}
		} else {
			if err := agent.RecordEnd(p, name, phase, findingsCreated, memoriesCreated); err != nil {
				exitError("%v", err)
			}
			if !jsonOutput {
				fmt.Printf("Recorded end for %s\n", name)
			}
		}

		if jsonOutput {
			_ = outputJSON(map[string]interface{}{"success": true, "name": name})
		}
	},
}

func printAgentVerification(rpt *agent.AgentVerification) {
	fmt.Printf("%s expects %d memories:\n", rpt.Agent, rpt.Expected)
	maxName := 0
	for _, m := range rpt.Memories {
		if len(m.Name) > maxName {
			maxName = len(m.Name)
		}
	}
	for _, m := range rpt.Memories {
		mark := "✗" // ✗
		if m.Present {
			mark = "✓" // ✓
		}
		pad := strings.Repeat(" ", maxName-len(m.Name)+2)
		if m.Present {
			fmt.Printf("  %s %s%s(last updated %s)\n", mark, m.Name, pad, m.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"))
		} else {
			fmt.Printf("  %s %s%sMISSING\n", mark, m.Name, pad)
		}
	}
	if rpt.Pass {
		fmt.Printf("Result: PASS (%d/%d present)\n", rpt.Present, rpt.Expected)
	} else {
		fmt.Printf("Result: FAIL (%d missing)\n", rpt.Missing)
	}
}

func printAggregateVerification(agg *agent.AggregateVerification) {
	fmt.Printf("Verifying %d analysis-phase agents...\n\n", agg.TotalAgents)
	for i := range agg.Agents {
		printAgentVerification(&agg.Agents[i])
		fmt.Println()
	}
	fmt.Printf("=== Summary ===\n")
	fmt.Printf("Agents passing: %d/%d\n", agg.PassingCount, agg.TotalAgents)
	if agg.Pass {
		fmt.Println("Overall: PASS")
	} else {
		fmt.Printf("Overall: FAIL (%d agents missing memories)\n", agg.FailingCount)
	}
}

func init() {
	rootCmd.AddCommand(agentCmd)
	agentCmd.AddCommand(agentListCmd)
	agentCmd.AddCommand(agentShowCmd)
	agentCmd.AddCommand(agentCreateCmd)
	agentCmd.AddCommand(agentPromptCmd)
	agentCmd.AddCommand(agentGenerateCmd)
	agentCmd.AddCommand(agentVerifyMemoriesCmd)
	agentCmd.AddCommand(agentRecordTimingCmd)

	agentCreateCmd.Flags().StringP("file", "f", "", "YAML file containing agent configuration")

	agentPromptCmd.Flags().StringP("context", "c", "", "Additional context to include in prompt")
	agentPromptCmd.Flags().String("finding", "", "Inject a finding (by ID) into the prompt context (used by review-agent)")

	agentVerifyMemoriesCmd.Flags().Bool("all", false, "Verify all analysis-phase agents")

	agentRecordTimingCmd.Flags().String("phase", "", "Phase name (recon, analysis, validation, reporting)")
	agentRecordTimingCmd.Flags().Bool("start", false, "Record the start time for this agent invocation")
	agentRecordTimingCmd.Flags().Bool("end", false, "Record the end time for this agent invocation")
	agentRecordTimingCmd.Flags().Int("findings-created", 0, "Number of findings created by this agent (optional)")
	agentRecordTimingCmd.Flags().Int("memories-created", 0, "Number of memories created by this agent (optional)")
}
