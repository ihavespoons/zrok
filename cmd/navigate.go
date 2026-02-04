package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ihavespoons/zrok/internal/navigate"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/spf13/cobra"
)

// readCmd represents the read command
var readCmd = &cobra.Command{
	Use:   "read <file>",
	Short: "Read file contents",
	Long: `Read the contents of a file.

Use --lines to read specific line ranges (e.g., --lines 10:20).`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		reader := navigate.NewReader(p)
		filePath := args[0]
		linesFlag, _ := cmd.Flags().GetString("lines")

		var result *navigate.ReadResult
		if linesFlag != "" {
			parts := strings.Split(linesFlag, ":")
			if len(parts) != 2 {
				exitError("invalid lines format, use N:M (e.g., 10:20)")
			}
			start, err1 := strconv.Atoi(parts[0])
			end, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil {
				exitError("invalid line numbers")
			}
			result, err = reader.ReadLines(filePath, start, end)
		} else {
			result, err = reader.Read(filePath)
		}

		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			if err := outputJSON(result); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			if linesFlag != "" {
				// Show line numbers for partial reads
				for i, line := range result.Lines {
					fmt.Printf("%5d: %s\n", result.StartLine+i, line)
				}
			} else {
				fmt.Print(result.Content)
			}
		}
	},
}

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list [dir]",
	Short: "List directory contents",
	Long: `List the contents of a directory.

Use --recursive to list subdirectories, and --depth to limit depth.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		dir := "."
		if len(args) > 0 {
			dir = args[0]
		}

		recursive, _ := cmd.Flags().GetBool("recursive")
		depth, _ := cmd.Flags().GetInt("depth")
		tree, _ := cmd.Flags().GetBool("tree")

		lister := navigate.NewLister(p)

		if tree {
			result, err := lister.Tree(dir, depth)
			if err != nil {
				exitError("%v", err)
			}
			fmt.Print(result)
			return
		}

		opts := &navigate.ListOptions{
			Recursive: recursive,
			MaxDepth:  depth,
		}

		result, err := lister.List(dir, opts)
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			if err := outputJSON(result); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			for _, entry := range result.Entries {
				suffix := ""
				if entry.IsDir {
					suffix = "/"
				}
				fmt.Printf("%s%s\n", entry.Path, suffix)
			}
			fmt.Printf("\nTotal: %d entries\n", result.Total)
		}
	},
}

// findCmd represents the find command
var findCmd = &cobra.Command{
	Use:   "find <pattern>",
	Short: "Find files by pattern",
	Long: `Find files matching a pattern.

Supports glob patterns (e.g., *.go, **/*.js).
Use --type to filter by file or directory.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		pattern := args[0]
		fileType, _ := cmd.Flags().GetString("type")
		maxDepth, _ := cmd.Flags().GetInt("depth")

		finder := navigate.NewFinder(p)
		opts := &navigate.FindOptions{
			Type:     fileType,
			MaxDepth: maxDepth,
		}

		result, err := finder.Find(pattern, opts)
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			if err := outputJSON(result); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			for _, match := range result.Matches {
				suffix := ""
				if match.IsDir {
					suffix = "/"
				}
				fmt.Printf("%s%s\n", match.Path, suffix)
			}
			fmt.Printf("\nFound: %d matches\n", result.Total)
		}
	},
}

// searchCmd represents the search command
var searchCmd = &cobra.Command{
	Use:   "search <pattern>",
	Short: "Search file contents",
	Long: `Search for a pattern in file contents.

Use --regex for regular expression patterns.
Use --context N to show N lines of context around matches.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		pattern := args[0]
		regex, _ := cmd.Flags().GetBool("regex")
		ignoreCase, _ := cmd.Flags().GetBool("ignore-case")
		context, _ := cmd.Flags().GetInt("context")
		maxResults, _ := cmd.Flags().GetInt("max")
		filePattern, _ := cmd.Flags().GetString("file")

		finder := navigate.NewFinder(p)
		opts := &navigate.SearchOptions{
			Regex:       regex,
			IgnoreCase:  ignoreCase,
			Context:     context,
			MaxResults:  maxResults,
			FilePattern: filePattern,
		}

		result, err := finder.Search(pattern, opts)
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			if err := outputJSON(result); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			currentFile := ""
			for _, match := range result.Matches {
				if match.File != currentFile {
					if currentFile != "" {
						fmt.Println()
					}
					fmt.Printf("=== %s ===\n", match.File)
					currentFile = match.File
				}

				if match.Context != "" {
					fmt.Println(match.Context)
					fmt.Println("---")
				} else {
					fmt.Printf("%d: %s\n", match.Line, match.Content)
				}
			}
			fmt.Printf("\nFound: %d matches in %d files\n", result.Total, result.Files)
		}
	},
}

// symbolsCmd represents the symbols command
var symbolsCmd = &cobra.Command{
	Use:   "symbols <file>",
	Short: "Extract code symbols",
	Long: `Extract code symbols (functions, classes, etc.) from a file.

Use 'symbols find <name>' to search for symbols globally.
Use 'symbols refs <symbol>' to find references to a symbol.

Use --method to specify extraction method:
  auto  - Try LSP first, fall back to regex (default)
  lsp   - Use only LSP (requires language server installed)
  regex - Use only regex patterns`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		methodStr, _ := cmd.Flags().GetString("method")
		method := navigate.ExtractionMethod(methodStr)
		if method == "" {
			method = navigate.MethodAuto
		}

		extractor := navigate.NewUnifiedExtractor(p, method)
		defer func() { _ = extractor.Close() }()

		// Check for subcommand
		if args[0] == "find" {
			if len(args) < 2 {
				exitError("usage: zrok symbols find <name>")
			}
			result, err := extractor.Find(args[1])
			if err != nil {
				exitError("%v", err)
			}
			if jsonOutput {
				if err := outputJSON(result); err != nil {
					exitError("failed to encode JSON: %v", err)
				}
			} else {
				for _, sym := range result.Symbols {
					fmt.Printf("%s %s (%s:%d)\n", sym.Kind, sym.Name, sym.File, sym.Line)
				}
				fmt.Printf("\nFound: %d symbols\n", result.Total)
			}
			return
		}

		if args[0] == "refs" {
			if len(args) < 2 {
				exitError("usage: zrok symbols refs <symbol>")
			}
			result, err := extractor.FindReferences(args[1])
			if err != nil {
				exitError("%v", err)
			}
			if jsonOutput {
				if err := outputJSON(result); err != nil {
					exitError("failed to encode JSON: %v", err)
				}
			} else {
				for _, match := range result.Matches {
					fmt.Printf("%s:%d: %s\n", match.File, match.Line, match.Content)
				}
				fmt.Printf("\nFound: %d references\n", result.Total)
			}
			return
		}

		// Default: extract symbols from file
		result, err := extractor.Extract(args[0])
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			if err := outputJSON(result); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Printf("Symbols in %s:\n\n", result.File)
			for _, sym := range result.Symbols {
				prefix := ""
				if sym.Parent != "" {
					prefix = sym.Parent + "."
				}
				fmt.Printf("  %s %s%s (line %d)\n", sym.Kind, prefix, sym.Name, sym.Line)
			}
			fmt.Printf("\nTotal: %d symbols\n", result.Total)
		}
	},
}

func init() {
	rootCmd.AddCommand(readCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(findCmd)
	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(symbolsCmd)

	readCmd.Flags().StringP("lines", "l", "", "Line range to read (N:M)")

	listCmd.Flags().BoolP("recursive", "r", false, "List recursively")
	listCmd.Flags().IntP("depth", "d", 0, "Maximum depth (0 = unlimited)")
	listCmd.Flags().BoolP("tree", "t", false, "Display as tree")

	findCmd.Flags().StringP("type", "t", "", "Filter by type (file or dir)")
	findCmd.Flags().IntP("depth", "d", 0, "Maximum depth (0 = unlimited)")

	searchCmd.Flags().BoolP("regex", "r", false, "Use regular expressions")
	searchCmd.Flags().BoolP("ignore-case", "i", false, "Ignore case")
	searchCmd.Flags().IntP("context", "C", 0, "Lines of context")
	searchCmd.Flags().IntP("max", "m", 100, "Maximum results")
	searchCmd.Flags().StringP("file", "f", "", "File pattern to search")

	symbolsCmd.Flags().StringP("method", "m", "auto", "Extraction method: auto, lsp, regex")
}
