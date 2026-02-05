package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ihavespoons/zrok/internal/embedding"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/ihavespoons/zrok/internal/semantic"
	"github.com/spf13/cobra"
)

// indexCmd represents the index command
var indexCmd = &cobra.Command{
	Use:   "index",
	Short: "Manage semantic search index",
	Long: `Manage the semantic search index for natural language code queries.

The semantic index enables searching your codebase using natural language
queries like "authentication middleware" or "SQL injection vulnerabilities".

Index management commands:
  enable   - Enable semantic indexing and configure provider
  disable  - Disable semantic indexing
  build    - Build or rebuild the full index
  update   - Incrementally update changed files
  status   - Show index statistics
  watch    - Start file watcher for real-time updates
  clear    - Clear the index`,
}

// indexEnableCmd represents the index enable command
var indexEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable semantic indexing",
	Long: `Enable semantic indexing and configure the embedding provider.

Available providers:
  - ollama      (local, free, requires Ollama installed)
  - openai      (cloud, paid, requires OPENAI_API_KEY)
  - huggingface (cloud, free tier, requires HF_API_KEY)`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		provider, _ := cmd.Flags().GetString("provider")
		model, _ := cmd.Flags().GetString("model")
		endpoint, _ := cmd.Flags().GetString("endpoint")

		// Get default config for provider
		defaultConfig, ok := embedding.DefaultConfigs[provider]
		if !ok {
			exitError("unknown provider: %s (valid: ollama, openai, huggingface)", provider)
		}

		// Build embedding config
		embConfig := project.EmbeddingConfig{
			Provider:  provider,
			Model:     model,
			Endpoint:  endpoint,
			Dimension: defaultConfig.Dimension,
		}

		if model == "" {
			embConfig.Model = defaultConfig.Model
		}
		if endpoint == "" && defaultConfig.Endpoint != "" {
			embConfig.Endpoint = defaultConfig.Endpoint
		}
		if defaultConfig.APIKeyEnv != "" {
			embConfig.APIKeyEnv = defaultConfig.APIKeyEnv
		}

		// Update project config
		p.Config.Index = project.IndexConfig{
			Enabled:       true,
			ChunkStrategy: "lsp",
			MaxChunkLines: 100,
			Embedding:     embConfig,
			ExcludePatterns: []string{
				"*_test.go",
				"*.min.js",
				"vendor/",
				"node_modules/",
			},
		}

		if err := p.Save(); err != nil {
			exitError("failed to save config: %v", err)
		}

		if jsonOutput {
			if err := outputJSON(map[string]interface{}{
				"success":  true,
				"provider": provider,
				"model":    embConfig.Model,
				"enabled":  true,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Printf("Semantic indexing enabled\n")
			fmt.Printf("  Provider: %s\n", provider)
			fmt.Printf("  Model: %s\n", embConfig.Model)
			fmt.Println("\nRun 'zrok index build' to build the index")
		}
	},
}

// indexDisableCmd represents the index disable command
var indexDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable semantic indexing",
	Long:  `Disable semantic indexing. This does not delete the index.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		p.Config.Index.Enabled = false

		if err := p.Save(); err != nil {
			exitError("failed to save config: %v", err)
		}

		if jsonOutput {
			if err := outputJSON(map[string]interface{}{
				"success": true,
				"enabled": false,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Println("Semantic indexing disabled")
		}
	},
}

// indexBuildCmd represents the index build command
var indexBuildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build or rebuild the index",
	Long:  `Build or rebuild the semantic search index for the entire project.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		if !p.Config.Index.Enabled {
			exitError("semantic indexing is not enabled. Run 'zrok index enable' first")
		}

		force, _ := cmd.Flags().GetBool("force")

		indexer, err := createIndexer(p)
		if err != nil {
			exitError("failed to create indexer: %v", err)
		}
		defer func() { _ = indexer.Close() }()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Handle interrupt
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			fmt.Println("\nInterrupted, cleaning up...")
			cancel()
		}()

		var lastFile string
		progress := func(p *semantic.IndexProgress) {
			if jsonOutput {
				return
			}
			if p.File != "" && p.File != lastFile {
				fmt.Printf("\r\033[K  %s", p.File)
				lastFile = p.File
			}
			if p.Phase == "complete" {
				fmt.Printf("\r\033[K")
			}
		}

		if !jsonOutput {
			fmt.Println("Building semantic index...")
		}

		if err := indexer.Build(ctx, force, progress); err != nil {
			if ctx.Err() != nil {
				fmt.Println("Build cancelled")
				os.Exit(0)
			}
			exitError("build failed: %v", err)
		}

		stats, err := indexer.Stats()
		if err != nil {
			exitError("failed to get stats: %v", err)
		}

		if jsonOutput {
			if err := outputJSON(map[string]interface{}{
				"success": true,
				"chunks":  stats.TotalChunks,
				"files":   stats.TotalFiles,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Printf("Index built successfully\n")
			fmt.Printf("  Chunks: %d\n", stats.TotalChunks)
			fmt.Printf("  Files: %d\n", stats.TotalFiles)
		}
	},
}

// indexUpdateCmd represents the index update command
var indexUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Incrementally update the index",
	Long:  `Update the index with changes since the last build.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		if !p.Config.Index.Enabled {
			exitError("semantic indexing is not enabled. Run 'zrok index enable' first")
		}

		indexer, err := createIndexer(p)
		if err != nil {
			exitError("failed to create indexer: %v", err)
		}
		defer func() { _ = indexer.Close() }()

		ctx := context.Background()

		var lastFile string
		progress := func(p *semantic.IndexProgress) {
			if jsonOutput {
				return
			}
			if p.File != "" && p.File != lastFile {
				fmt.Printf("  %s\n", p.File)
				lastFile = p.File
			}
		}

		if !jsonOutput {
			fmt.Println("Updating semantic index...")
		}

		updated, err := indexer.Update(ctx, progress)
		if err != nil {
			exitError("update failed: %v", err)
		}

		if jsonOutput {
			if err := outputJSON(map[string]interface{}{
				"success": true,
				"updated": updated,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Printf("Index updated: %d files changed\n", updated)
		}
	},
}

// indexStatusCmd represents the index status command
var indexStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show index statistics",
	Long:  `Display statistics about the semantic search index.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		if !p.Config.Index.Enabled {
			if jsonOutput {
				if err := outputJSON(map[string]interface{}{
					"enabled": false,
				}); err != nil {
					exitError("failed to encode JSON: %v", err)
				}
			} else {
				fmt.Println("Semantic indexing is not enabled")
				fmt.Println("Run 'zrok index enable' to enable it")
			}
			return
		}

		indexer, err := createIndexer(p)
		if err != nil {
			exitError("failed to create indexer: %v", err)
		}
		defer func() { _ = indexer.Close() }()

		stats, err := indexer.Stats()
		if err != nil {
			exitError("failed to get stats: %v", err)
		}

		if jsonOutput {
			if err := outputJSON(map[string]interface{}{
				"enabled":         true,
				"provider":        p.Config.Index.Embedding.Provider,
				"model":           p.Config.Index.Embedding.Model,
				"total_chunks":    stats.TotalChunks,
				"total_files":     stats.TotalFiles,
				"type_counts":     stats.TypeCounts,
				"language_counts": stats.LanguageCounts,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Println("Semantic Index Status")
			fmt.Println("=====================")
			fmt.Printf("Enabled: true\n")
			fmt.Printf("Provider: %s\n", p.Config.Index.Embedding.Provider)
			fmt.Printf("Model: %s\n", p.Config.Index.Embedding.Model)
			fmt.Printf("\nIndex Statistics:\n")
			fmt.Printf("  Total Chunks: %d\n", stats.TotalChunks)
			fmt.Printf("  Total Files: %d\n", stats.TotalFiles)

			if len(stats.TypeCounts) > 0 {
				fmt.Printf("\nBy Type:\n")
				for t, count := range stats.TypeCounts {
					fmt.Printf("  %s: %d\n", t, count)
				}
			}

			if len(stats.LanguageCounts) > 0 {
				fmt.Printf("\nBy Language:\n")
				for lang, count := range stats.LanguageCounts {
					fmt.Printf("  %s: %d\n", lang, count)
				}
			}
		}
	},
}

// indexWatchCmd represents the index watch command
var indexWatchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch for file changes",
	Long:  `Start a file watcher to automatically update the index when files change.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		if !p.Config.Index.Enabled {
			exitError("semantic indexing is not enabled. Run 'zrok index enable' first")
		}

		indexer, err := createIndexer(p)
		if err != nil {
			exitError("failed to create indexer: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())

		// Handle interrupt
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			fmt.Println("\nStopping watcher...")
			cancel()
			indexer.StopWatch()
			_ = indexer.Close()
			os.Exit(0)
		}()

		if err := indexer.Watch(ctx); err != nil {
			exitError("failed to start watcher: %v", err)
		}

		fmt.Println("Watching for file changes... (Ctrl+C to stop)")

		// Block until cancelled
		<-ctx.Done()
	},
}

// indexClearCmd represents the index clear command
var indexClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear the index",
	Long:  `Remove all data from the semantic search index.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		if !p.Config.Index.Enabled {
			exitError("semantic indexing is not enabled")
		}

		indexer, err := createIndexer(p)
		if err != nil {
			exitError("failed to create indexer: %v", err)
		}
		defer func() { _ = indexer.Close() }()

		if err := indexer.Clear(); err != nil {
			exitError("failed to clear index: %v", err)
		}

		if jsonOutput {
			if err := outputJSON(map[string]interface{}{
				"success": true,
				"action":  "cleared",
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Println("Index cleared")
		}
	},
}

// createIndexer creates an indexer from project config
func createIndexer(p *project.Project) (*semantic.Indexer, error) {
	embConfig := &embedding.Config{
		Provider:  p.Config.Index.Embedding.Provider,
		Model:     p.Config.Index.Embedding.Model,
		Endpoint:  p.Config.Index.Embedding.Endpoint,
		APIKeyEnv: p.Config.Index.Embedding.APIKeyEnv,
		Dimension: p.Config.Index.Embedding.Dimension,
	}

	// Validate embedding config
	if err := embedding.ValidateConfig(embConfig); err != nil {
		return nil, err
	}

	config := &semantic.IndexerConfig{
		StorePath:       p.GetIndexPath(),
		ProviderConfig:  embConfig,
		ChunkStrategy:   p.Config.Index.ChunkStrategy,
		MaxChunkLines:   p.Config.Index.MaxChunkLines,
		ExcludePatterns: p.Config.Index.ExcludePatterns,
	}

	return semantic.NewIndexer(p, config)
}

func init() {
	rootCmd.AddCommand(indexCmd)
	indexCmd.AddCommand(indexEnableCmd)
	indexCmd.AddCommand(indexDisableCmd)
	indexCmd.AddCommand(indexBuildCmd)
	indexCmd.AddCommand(indexUpdateCmd)
	indexCmd.AddCommand(indexStatusCmd)
	indexCmd.AddCommand(indexWatchCmd)
	indexCmd.AddCommand(indexClearCmd)

	// Enable flags
	indexEnableCmd.Flags().StringP("provider", "p", "ollama", "Embedding provider (ollama, openai, huggingface)")
	indexEnableCmd.Flags().StringP("model", "m", "", "Model name (provider-specific, uses default if not set)")
	indexEnableCmd.Flags().StringP("endpoint", "e", "", "API endpoint (for ollama)")

	// Build flags
	indexBuildCmd.Flags().Bool("force", false, "Force full rebuild")
}
