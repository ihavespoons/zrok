package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ihavespoons/zrok/internal/chunk"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/ihavespoons/zrok/internal/semantic"
	"github.com/ihavespoons/zrok/internal/vectordb"
	"github.com/spf13/cobra"
)

// semanticCmd represents the semantic command
var semanticCmd = &cobra.Command{
	Use:   "semantic <query>",
	Short: "Semantic code search",
	Long: `Search the codebase using natural language queries.

Semantic search uses embeddings to find code that matches the meaning
of your query, not just exact text matches.

Examples:
  zrok semantic "authentication middleware"
  zrok semantic "SQL injection vulnerabilities" --multi-hop
  zrok semantic "error handling" --type function
  zrok semantic "database connection" --file "*.go"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		if !p.Config.Index.Enabled {
			exitError("semantic indexing is not enabled. Run 'zrok index enable' first")
		}

		query := args[0]
		limit, _ := cmd.Flags().GetInt("limit")
		multiHop, _ := cmd.Flags().GetBool("multi-hop")
		maxHops, _ := cmd.Flags().GetInt("max-hops")
		threshold, _ := cmd.Flags().GetFloat32("threshold")
		typeFilter, _ := cmd.Flags().GetString("type")
		fileFilter, _ := cmd.Flags().GetString("file")
		langFilter, _ := cmd.Flags().GetString("language")
		timeout, _ := cmd.Flags().GetInt("timeout")

		// Create indexer and searcher
		indexer, err := createIndexer(p)
		if err != nil {
			exitError("failed to create indexer: %v", err)
		}
		defer func() { _ = indexer.Close() }()

		searcher := indexer.Searcher()

		// Build filter
		var filter *vectordb.Filter
		if typeFilter != "" || fileFilter != "" || langFilter != "" || threshold > 0 {
			filter = &vectordb.Filter{
				MinScore: threshold,
			}

			if typeFilter != "" {
				filter.Types = []chunk.ChunkType{chunk.ChunkType(typeFilter)}
			}
			if fileFilter != "" {
				filter.Files = []string{fileFilter}
			}
			if langFilter != "" {
				filter.Languages = []string{langFilter}
			}
		}

		// Build search options
		opts := &semantic.SearchOptions{
			Limit:     limit,
			MultiHop:  multiHop,
			MaxHops:   maxHops,
			Threshold: threshold,
			TimeLimit: time.Duration(timeout) * time.Second,
			Filter:    filter,
		}

		ctx := context.Background()

		if !jsonOutput && verbose {
			fmt.Printf("Searching for: %s\n", query)
			if multiHop {
				fmt.Printf("  Multi-hop: enabled (max %d hops)\n", maxHops)
			}
			fmt.Println()
		}

		results, err := searcher.Search(ctx, query, opts)
		if err != nil {
			exitError("search failed: %v", err)
		}

		if jsonOutput {
			if err := outputJSON(results); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			printSearchResults(results, verbose)
		}
	},
}

// printSearchResults prints search results in human-readable format
func printSearchResults(results *semantic.SearchResults, verbose bool) {
	if len(results.Results) == 0 {
		fmt.Println("No results found")
		return
	}

	for i, r := range results.Results {
		// Header
		fmt.Printf("%d. %s", i+1, r.Chunk.File)
		if r.Chunk.StartLine > 0 {
			fmt.Printf(":%d-%d", r.Chunk.StartLine, r.Chunk.EndLine)
		}
		fmt.Printf(" (score: %.3f)\n", r.Score)

		// Symbol info
		fmt.Printf("   %s %s", r.Chunk.Type, r.Chunk.Name)
		if r.Chunk.ParentName != "" {
			fmt.Printf(" in %s", r.Chunk.ParentName)
		}
		fmt.Println()

		if verbose {
			// Signature
			if r.Chunk.Signature != "" && r.Chunk.Signature != r.Chunk.Name {
				fmt.Printf("   %s\n", r.Chunk.Signature)
			}

			// Content preview (first 3 lines)
			lines := strings.Split(r.Chunk.Content, "\n")
			maxLines := 3
			if len(lines) < maxLines {
				maxLines = len(lines)
			}
			for j := 0; j < maxLines; j++ {
				line := strings.TrimSpace(lines[j])
				if len(line) > 80 {
					line = line[:77] + "..."
				}
				fmt.Printf("   │ %s\n", line)
			}
			if len(lines) > 3 {
				fmt.Printf("   │ ... (%d more lines)\n", len(lines)-3)
			}
		}

		fmt.Println()
	}

	// Summary
	fmt.Printf("Found %d results", len(results.Results))
	if results.TotalHops > 1 {
		fmt.Printf(" in %d hops", results.TotalHops)
	}
	fmt.Printf(" (%s)\n", results.Duration.Round(time.Millisecond))
}

// semanticRelatedCmd represents the semantic related command
var semanticRelatedCmd = &cobra.Command{
	Use:   "related <file>",
	Short: "Find related code",
	Long: `Find code related to a specific file or chunk.

This command finds code that is semantically similar to the given file,
which is useful for understanding dependencies and related functionality.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		if !p.Config.Index.Enabled {
			exitError("semantic indexing is not enabled")
		}

		filePath := args[0]
		limit, _ := cmd.Flags().GetInt("limit")

		indexer, err := createIndexer(p)
		if err != nil {
			exitError("failed to create indexer: %v", err)
		}
		defer func() { _ = indexer.Close() }()

		searcher := indexer.Searcher()

		ctx := context.Background()
		opts := &semantic.SearchOptions{
			Limit: limit,
		}

		results, err := searcher.SearchByFile(ctx, filePath, opts)
		if err != nil {
			exitError("search failed: %v", err)
		}

		if jsonOutput {
			if err := outputJSON(results); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Printf("Code related to: %s\n\n", filePath)
			printSearchResults(results, verbose)
		}
	},
}

func init() {
	rootCmd.AddCommand(semanticCmd)
	semanticCmd.AddCommand(semanticRelatedCmd)

	// Search flags
	semanticCmd.Flags().IntP("limit", "l", 10, "Maximum number of results")
	semanticCmd.Flags().Bool("multi-hop", false, "Enable multi-hop exploration")
	semanticCmd.Flags().Int("max-hops", 3, "Maximum hops for multi-hop search")
	semanticCmd.Flags().Float32P("threshold", "t", 0.0, "Minimum similarity score (0-1)")
	semanticCmd.Flags().String("type", "", "Filter by chunk type (function, method, class, struct, interface)")
	semanticCmd.Flags().StringP("file", "f", "", "Filter by file pattern (glob)")
	semanticCmd.Flags().String("language", "", "Filter by language")
	semanticCmd.Flags().Int("timeout", 5, "Search timeout in seconds")

	// Related flags
	semanticRelatedCmd.Flags().IntP("limit", "l", 10, "Maximum number of results")
}
