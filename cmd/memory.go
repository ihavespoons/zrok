package cmd

import (
	"fmt"
	"os"

	"github.com/ihavespoons/zrok/internal/memory"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/spf13/cobra"
)

// memoryCmd represents the memory command
var memoryCmd = &cobra.Command{
	Use:   "memory",
	Short: "Manage analysis memories",
	Long: `Manage persistent memories for security analysis.

Memories store context, patterns, and tech stack specific information
that persists across analysis sessions.

Memory types:
  - context: Project context and overview information
  - pattern: Vulnerability patterns and anti-patterns
  - stack: Tech stack specific security patterns`,
}

// memoryListCmd represents the memory list command
var memoryListCmd = &cobra.Command{
	Use:   "list",
	Short: "List memories",
	Long:  `List all memories or filter by type.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		store := memory.NewStore(p)
		typeFilter, _ := cmd.Flags().GetString("type")

		var memType memory.MemoryType
		if typeFilter != "" {
			var ok bool
			memType, ok = memory.ParseMemoryType(typeFilter)
			if !ok {
				exitError("invalid memory type: %s (valid: context, pattern, stack)", typeFilter)
			}
		}

		result, err := store.List(memType)
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(result)
		} else {
			if result.Total == 0 {
				fmt.Println("No memories found")
				return
			}

			for _, mem := range result.Memories {
				fmt.Printf("[%s] %s", mem.Type, mem.Name)
				if mem.Description != "" {
					fmt.Printf(" - %s", mem.Description)
				}
				fmt.Println()
			}
			fmt.Printf("\nTotal: %d memories\n", result.Total)
		}
	},
}

// memoryReadCmd represents the memory read command
var memoryReadCmd = &cobra.Command{
	Use:   "read <name>",
	Short: "Read a memory",
	Long:  `Read the contents of a memory by name.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		store := memory.NewStore(p)
		mem, err := store.ReadByName(args[0])
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(mem)
		} else {
			fmt.Printf("Name: %s\n", mem.Name)
			fmt.Printf("Type: %s\n", mem.Type)
			if mem.Description != "" {
				fmt.Printf("Description: %s\n", mem.Description)
			}
			if len(mem.Tags) > 0 {
				fmt.Printf("Tags: %v\n", mem.Tags)
			}
			fmt.Printf("Created: %s\n", mem.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("Updated: %s\n", mem.UpdatedAt.Format("2006-01-02 15:04:05"))
			fmt.Println("\n--- Content ---")
			fmt.Println(mem.Content)
		}
	},
}

// memoryWriteCmd represents the memory write command
var memoryWriteCmd = &cobra.Command{
	Use:   "write <name>",
	Short: "Create or update a memory",
	Long: `Create or update a memory with content.

Provide content via --content flag or --file flag.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		name := args[0]
		content, _ := cmd.Flags().GetString("content")
		file, _ := cmd.Flags().GetString("file")
		memTypeStr, _ := cmd.Flags().GetString("type")
		description, _ := cmd.Flags().GetString("description")
		tagsStr, _ := cmd.Flags().GetStringSlice("tags")

		// Get content from file if specified
		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				exitError("failed to read file: %v", err)
			}
			content = string(data)
		}

		if content == "" {
			exitError("provide content via --content or --file")
		}

		// Parse memory type
		memType := memory.MemoryTypeContext // default
		if memTypeStr != "" {
			var ok bool
			memType, ok = memory.ParseMemoryType(memTypeStr)
			if !ok {
				exitError("invalid memory type: %s (valid: context, pattern, stack)", memTypeStr)
			}
		}

		store := memory.NewStore(p)

		// Check if exists
		existing, _ := store.ReadByName(name)
		mem := &memory.Memory{
			Name:        name,
			Type:        memType,
			Content:     content,
			Description: description,
			Tags:        tagsStr,
		}

		if existing != nil {
			// Update
			mem.Type = existing.Type // Keep original type
			err = store.Update(mem)
		} else {
			// Create
			err = store.Create(mem)
		}

		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(map[string]interface{}{
				"success": true,
				"name":    name,
				"type":    memType,
				"action":  map[bool]string{true: "updated", false: "created"}[existing != nil],
			})
		} else {
			action := "Created"
			if existing != nil {
				action = "Updated"
			}
			fmt.Printf("%s memory: %s\n", action, name)
		}
	},
}

// memoryDeleteCmd represents the memory delete command
var memoryDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a memory",
	Long:  `Delete a memory by name.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		store := memory.NewStore(p)
		err = store.DeleteByName(args[0])
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(map[string]interface{}{
				"success": true,
				"name":    args[0],
				"action":  "deleted",
			})
		} else {
			fmt.Printf("Deleted memory: %s\n", args[0])
		}
	},
}

// memorySearchCmd represents the memory search command
var memorySearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search memories",
	Long:  `Search memories by content, name, or tags.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		store := memory.NewStore(p)
		result, err := store.Search(args[0])
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(result)
		} else {
			if result.Total == 0 {
				fmt.Println("No matches found")
				return
			}

			for _, mem := range result.Memories {
				fmt.Printf("[%s] %s\n", mem.Type, mem.Name)
			}
			fmt.Printf("\nFound: %d matches\n", result.Total)
		}
	},
}

func init() {
	rootCmd.AddCommand(memoryCmd)
	memoryCmd.AddCommand(memoryListCmd)
	memoryCmd.AddCommand(memoryReadCmd)
	memoryCmd.AddCommand(memoryWriteCmd)
	memoryCmd.AddCommand(memoryDeleteCmd)
	memoryCmd.AddCommand(memorySearchCmd)

	memoryListCmd.Flags().StringP("type", "t", "", "Filter by type (context, pattern, stack)")

	memoryWriteCmd.Flags().StringP("content", "c", "", "Memory content")
	memoryWriteCmd.Flags().StringP("file", "f", "", "Read content from file")
	memoryWriteCmd.Flags().StringP("type", "t", "context", "Memory type (context, pattern, stack)")
	memoryWriteCmd.Flags().StringP("description", "d", "", "Memory description")
	memoryWriteCmd.Flags().StringSlice("tags", []string{}, "Memory tags")
}
