package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	jsonOutput bool
	verbose    bool
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "zrok",
	Short: "Security code review CLI tool for LLM-assisted analysis",
	Long: `zrok is a read-only CLI tool designed for LLM-assisted security code review.

It provides structured tooling for:
- Code navigation and analysis
- Security finding management
- Memory/context persistence
- Agent-based workflows
- Export to standard formats (SARIF, JSON, Markdown, HTML, CSV)

Use 'zrok init' to initialize a project, then 'zrok onboard --auto' to detect
the tech stack and set up for analysis.`,
	Version: "1.0.0",
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
}

// outputJSON outputs data as JSON
func outputJSON(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// output outputs data in the appropriate format
func output(data interface{}, textFormatter func(interface{}) string) {
	if jsonOutput {
		if err := outputJSON(data); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Print(textFormatter(data))
	}
}

// exitError prints an error message and exits
func exitError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}

// exitErrorJSON outputs an error in JSON format if --json flag is set
func exitErrorJSON(err error) {
	if jsonOutput {
		outputJSON(map[string]string{"error": err.Error()})
	} else {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	os.Exit(1)
}
