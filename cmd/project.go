package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ihavespoons/zrok/internal/agent"
	"github.com/ihavespoons/zrok/internal/memory"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/spf13/cobra"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new zrok project",
	Long: `Initialize a new .zrok directory in the current project.

This creates the directory structure for storing project configuration,
memories, findings, and agent configurations.`,
	Run: func(cmd *cobra.Command, args []string) {
		cwd, err := os.Getwd()
		if err != nil {
			exitError("failed to get current directory: %v", err)
		}

		p, err := project.Initialize(cwd)
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			if err := outputJSON(map[string]interface{}{
				"success": true,
				"path":    p.GetZrokPath(),
				"message": "Project initialized successfully",
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Printf("Initialized zrok project at %s\n", p.GetZrokPath())
			fmt.Println("\nNext steps:")
			fmt.Println("  zrok onboard           # Agent-assisted onboarding (recommended)")
			fmt.Println("  zrok onboard --static  # Static detection only (fast)")
			fmt.Println("  zrok onboard --wizard  # Interactive setup")
		}
	},
}

// activateCmd represents the activate command
var activateCmd = &cobra.Command{
	Use:   "activate [path]",
	Short: "Activate a zrok project",
	Long:  `Activate a zrok project at the specified path (or current directory).`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := "."
		if len(args) > 0 {
			path = args[0]
		}

		p, err := project.Activate(path)
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			if err := outputJSON(map[string]interface{}{
				"success": true,
				"path":    p.RootPath,
				"project": p.Config,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Printf("Activated project: %s\n", p.Config.Name)
			fmt.Printf("Root path: %s\n", p.RootPath)
		}
	},
}

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show project status",
	Long:  `Display the current project status, configuration, and statistics.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		// Count memories
		memStore := memory.NewStore(p)
		memList, _ := memStore.List("")
		memCount := 0
		if memList != nil {
			memCount = memList.Total
		}

		// Count findings
		findingCount := 0
		findingsDir := p.GetFindingsPath() + "/raw"
		if entries, err := os.ReadDir(findingsDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
					findingCount++
				}
			}
		}

		status := map[string]interface{}{
			"project":       p.Config.Name,
			"path":          p.RootPath,
			"detected_at":   p.Config.DetectedAt,
			"tech_stack":    p.Config.TechStack,
			"memory_count":  memCount,
			"finding_count": findingCount,
		}

		if jsonOutput {
			if err := outputJSON(status); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Printf("Project: %s\n", p.Config.Name)
			fmt.Printf("Path: %s\n", p.RootPath)
			fmt.Printf("Detected: %s\n", p.Config.DetectedAt.Format(time.RFC3339))
			fmt.Println()

			stack := p.Config.TechStack
			if len(stack.Languages) > 0 {
				fmt.Println("Tech Stack:")
				for _, lang := range stack.Languages {
					fmt.Printf("  - %s", lang.Name)
					if lang.Version != "" {
						fmt.Printf(" (%s)", lang.Version)
					}
					if len(lang.Frameworks) > 0 {
						fmt.Printf(": %s", strings.Join(lang.Frameworks, ", "))
					}
					fmt.Println()
				}
				if len(stack.Databases) > 0 {
					fmt.Printf("  Databases: %s\n", strings.Join(stack.Databases, ", "))
				}
				if len(stack.Auth) > 0 {
					fmt.Printf("  Auth: %s\n", strings.Join(stack.Auth, ", "))
				}
				fmt.Println()
			}

			fmt.Printf("Memories: %d\n", memCount)
			fmt.Printf("Findings: %d\n", findingCount)
		}
	},
}

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config [get|set] [key] [value]",
	Short: "View or modify project configuration",
	Long: `View or modify the project configuration.

Examples:
  zrok config                    # Show all config
  zrok config get name           # Get a specific value
  zrok config set name myproject # Set a value`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		if len(args) == 0 {
			// Show all config
			if jsonOutput {
				if err := outputJSON(p.Config); err != nil {
					exitError("failed to encode JSON: %v", err)
				}
			} else {
				fmt.Printf("name: %s\n", p.Config.Name)
				fmt.Printf("version: %s\n", p.Config.Version)
				if p.Config.Description != "" {
					fmt.Printf("description: %s\n", p.Config.Description)
				}
				fmt.Printf("detected_at: %s\n", p.Config.DetectedAt.Format(time.RFC3339))
			}
			return
		}

		action := args[0]
		switch action {
		case "get":
			if len(args) < 2 {
				exitError("usage: zrok config get <key>")
			}
			key := args[1]
			var value interface{}
			switch key {
			case "name":
				value = p.Config.Name
			case "version":
				value = p.Config.Version
			case "description":
				value = p.Config.Description
			default:
				exitError("unknown config key: %s", key)
			}
			if jsonOutput {
				if err := outputJSON(map[string]interface{}{key: value}); err != nil {
					exitError("failed to encode JSON: %v", err)
				}
			} else {
				fmt.Println(value)
			}

		case "set":
			if len(args) < 3 {
				exitError("usage: zrok config set <key> <value>")
			}
			key := args[1]
			value := args[2]
			switch key {
			case "name":
				p.Config.Name = value
			case "version":
				p.Config.Version = value
			case "description":
				p.Config.Description = value
			default:
				exitError("unknown config key: %s", key)
			}

			if err := p.Save(); err != nil {
				exitError("failed to save config: %v", err)
			}

			if jsonOutput {
				if err := outputJSON(map[string]interface{}{"success": true, key: value}); err != nil {
					exitError("failed to encode JSON: %v", err)
				}
			} else {
				fmt.Printf("Set %s = %s\n", key, value)
			}

		default:
			exitError("unknown action: %s (use 'get' or 'set')", action)
		}
	},
}

// onboardCmd represents the onboard command
var onboardCmd = &cobra.Command{
	Use:   "onboard",
	Short: "Run project onboarding workflow",
	Long: `Run the project onboarding workflow to detect tech stack and configure analysis.

Modes:
  (default)      Agent-assisted onboarding - outputs recon-agent prompt for LLM execution
  --static       Static detection only (fast, no LLM required)
  --wizard       Interactive wizard mode for human setup`,
	Run: func(cmd *cobra.Command, args []string) {
		staticMode, _ := cmd.Flags().GetBool("static")
		wizardMode, _ := cmd.Flags().GetBool("wizard")
		// --auto is deprecated, treat as --static
		autoMode, _ := cmd.Flags().GetBool("auto")
		if autoMode {
			staticMode = true
		}

		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		onboarder := project.NewOnboarder(p)

		// Default to agent mode unless --static or --wizard specified
		if !staticMode && !wizardMode {
			// Agent mode (default)
			agentResult, err := onboarder.RunAgent()
			if err != nil {
				exitError("agent onboarding failed: %v", err)
			}

			// Create initial memories
			memStore := memory.NewStore(p)
			for _, mem := range agentResult.Memories {
				memType, _ := memory.ParseMemoryType(mem.Type)
				m := &memory.Memory{
					Name:    mem.Name,
					Type:    memType,
					Content: mem.Content,
				}
				_ = memStore.Create(m) // Ignore errors for existing memories
			}

			// Generate recon-agent prompt
			reconAgent := agent.GetBuiltinAgent("recon-agent")
			if reconAgent == nil {
				exitError("recon-agent not found in built-in agents")
			}

			promptGen := agent.NewPromptGenerator(p, memStore)
			agentPrompt, err := promptGen.Generate(reconAgent)
			if err != nil {
				exitError("failed to generate recon-agent prompt: %v", err)
			}

			if jsonOutput {
				if err := outputJSON(map[string]interface{}{
					"status":           "ready_for_recon",
					"tech_stack":       agentResult.Config.TechStack,
					"sensitive_areas":  agentResult.Config.SecurityScope.SensitiveAreas,
					"agent_prompt":     agentPrompt,
					"memories_created": len(agentResult.Memories),
					"next_step":        "Run the recon-agent prompt with your LLM",
				}); err != nil {
					exitError("failed to encode JSON: %v", err)
				}
			} else {
				fmt.Println("=== Agent Onboarding ===")
				fmt.Println()

				stack := agentResult.Config.TechStack
				if len(stack.Languages) > 0 {
					fmt.Println("Static Detection Results:")
					for _, lang := range stack.Languages {
						fmt.Printf("  - %s", lang.Name)
						if lang.Version != "" {
							fmt.Printf(" (%s)", lang.Version)
						}
						if len(lang.Frameworks) > 0 {
							fmt.Printf(": %s", strings.Join(lang.Frameworks, ", "))
						}
						fmt.Println()
					}
					fmt.Println()
				}

				if len(agentResult.Config.SecurityScope.SensitiveAreas) > 0 {
					fmt.Println("Detected Sensitive Areas:")
					for _, area := range agentResult.Config.SecurityScope.SensitiveAreas {
						fmt.Printf("  - %s: %s\n", area.Path, area.Reason)
					}
					fmt.Println()
				}

				fmt.Printf("Created %d initial memories\n\n", len(agentResult.Memories))
				fmt.Println("--- BEGIN RECON AGENT PROMPT ---")
				fmt.Println(agentPrompt)
				fmt.Println("--- END RECON AGENT PROMPT ---")
			}
			return
		}

		var result *project.OnboardingResult
		if staticMode {
			result, err = onboarder.RunAuto()
		} else {
			result, err = onboarder.RunWizard()
		}

		if err != nil {
			exitError("onboarding failed: %v", err)
		}

		// Create initial memories
		memStore := memory.NewStore(p)
		for _, mem := range result.Memories {
			memType, _ := memory.ParseMemoryType(mem.Type)
			m := &memory.Memory{
				Name:    mem.Name,
				Type:    memType,
				Content: mem.Content,
			}
			_ = memStore.Create(m) // Ignore errors for existing memories
		}

		if jsonOutput {
			if err := outputJSON(map[string]interface{}{
				"success":          true,
				"config":           result.Config,
				"memories_created": len(result.Memories),
				"suggested_agents": result.Agents,
				"warnings":         result.Warnings,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Println("Onboarding complete!")
			fmt.Println()

			stack := result.Config.TechStack
			if len(stack.Languages) > 0 {
				fmt.Println("Detected Tech Stack:")
				for _, lang := range stack.Languages {
					fmt.Printf("  - %s", lang.Name)
					if lang.Version != "" {
						fmt.Printf(" (%s)", lang.Version)
					}
					if len(lang.Frameworks) > 0 {
						fmt.Printf(": %s", strings.Join(lang.Frameworks, ", "))
					}
					fmt.Println()
				}
				if len(stack.Databases) > 0 {
					fmt.Printf("  Databases: %s\n", strings.Join(stack.Databases, ", "))
				}
				if len(stack.Auth) > 0 {
					fmt.Printf("  Auth: %s\n", strings.Join(stack.Auth, ", "))
				}
				fmt.Println()
			}

			if len(result.Config.SecurityScope.SensitiveAreas) > 0 {
				fmt.Println("Sensitive Areas:")
				for _, area := range result.Config.SecurityScope.SensitiveAreas {
					fmt.Printf("  - %s: %s\n", area.Path, area.Reason)
				}
				fmt.Println()
			}

			fmt.Printf("Created %d memories\n", len(result.Memories))

			if len(result.Agents) > 0 {
				fmt.Println("\nSuggested agents for analysis:")
				for _, agent := range result.Agents {
					fmt.Printf("  - %s\n", agent)
				}
			}

			if len(result.Warnings) > 0 {
				fmt.Println("\nWarnings:")
				for _, w := range result.Warnings {
					fmt.Printf("  - %s\n", w)
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(activateCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(onboardCmd)

	onboardCmd.Flags().Bool("static", false, "Static detection only (fast, no LLM)")
	onboardCmd.Flags().Bool("wizard", false, "Interactive wizard mode")
	onboardCmd.Flags().Bool("auto", false, "Deprecated: use --static instead")
	_ = onboardCmd.Flags().MarkDeprecated("auto", "use --static instead")
}
