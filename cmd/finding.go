package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/finding/export"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// findingCmd represents the finding command
var findingCmd = &cobra.Command{
	Use:   "finding",
	Short: "Manage security findings",
	Long: `Manage security findings discovered during analysis.

Findings can be created from YAML files, filtered, and exported
to various formats including SARIF, JSON, Markdown, HTML, and CSV.`,
}

// findingCreateCmd represents the finding create command
var findingCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new finding",
	Long: `Create a new security finding from a YAML file or interactively.

Example YAML format:
  title: "SQL Injection in user search"
  severity: high
  confidence: high
  cwe: CWE-89
  location:
    file: "src/api/users.go"
    line_start: 45
  description: "User input is concatenated into SQL query"
  remediation: "Use parameterized queries"`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		file, _ := cmd.Flags().GetString("file")
		if file == "" {
			exitError("provide finding via --file flag")
		}

		data, err := os.ReadFile(file)
		if err != nil {
			exitError("failed to read file: %v", err)
		}

		var f finding.Finding
		if err := yaml.Unmarshal(data, &f); err != nil {
			exitError("failed to parse finding: %v", err)
		}

		store := finding.NewStore(p)
		if err := store.Create(&f); err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(map[string]interface{}{
				"success": true,
				"id":      f.ID,
				"finding": f,
			})
		} else {
			fmt.Printf("Created finding: %s\n", f.ID)
			fmt.Printf("Title: %s\n", f.Title)
			fmt.Printf("Severity: %s\n", f.Severity)
		}
	},
}

// findingUpdateCmd represents the finding update command
var findingUpdateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update a finding",
	Long: `Update an existing finding by ID.

You can update status, severity, or provide a new YAML file.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		id := args[0]
		store := finding.NewStore(p)

		f, err := store.Read(id)
		if err != nil {
			exitError("%v", err)
		}

		// Apply updates
		if status, _ := cmd.Flags().GetString("status"); status != "" {
			f.Status = finding.Status(status)
		}
		if severity, _ := cmd.Flags().GetString("severity"); severity != "" {
			f.Severity = finding.Severity(severity)
		}
		if confidence, _ := cmd.Flags().GetString("confidence"); confidence != "" {
			f.Confidence = finding.Confidence(confidence)
		}

		if err := store.Update(f); err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(map[string]interface{}{
				"success": true,
				"finding": f,
			})
		} else {
			fmt.Printf("Updated finding: %s\n", f.ID)
		}
	},
}

// findingListCmd represents the finding list command
var findingListCmd = &cobra.Command{
	Use:   "list",
	Short: "List findings",
	Long:  `List all findings with optional filters.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		store := finding.NewStore(p)
		opts := &finding.FilterOptions{}

		if sev, _ := cmd.Flags().GetString("severity"); sev != "" {
			opts.Severity = finding.Severity(sev)
		}
		if status, _ := cmd.Flags().GetString("status"); status != "" {
			opts.Status = finding.Status(status)
		}
		if cwe, _ := cmd.Flags().GetString("cwe"); cwe != "" {
			opts.CWE = cwe
		}

		result, err := store.List(opts)
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(result)
		} else {
			if result.Total == 0 {
				fmt.Println("No findings")
				return
			}

			for _, f := range result.Findings {
				badge := getSeverityBadge(f.Severity)
				fmt.Printf("%s [%s] %s - %s\n", badge, f.ID, f.Title, f.Status)
				fmt.Printf("   Location: %s:%d\n", f.Location.File, f.Location.LineStart)
			}
			fmt.Printf("\nTotal: %d findings\n", result.Total)
		}
	},
}

// findingShowCmd represents the finding show command
var findingShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show finding details",
	Long:  `Show detailed information about a specific finding.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		store := finding.NewStore(p)
		f, err := store.Read(args[0])
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(f)
		} else {
			fmt.Printf("%s %s\n", getSeverityBadge(f.Severity), f.Title)
			fmt.Printf("ID: %s\n", f.ID)
			fmt.Printf("Status: %s\n", f.Status)
			fmt.Printf("Confidence: %s\n", f.Confidence)
			if f.CWE != "" {
				fmt.Printf("CWE: %s\n", f.CWE)
			}
			if f.CVSS != nil {
				fmt.Printf("CVSS: %.1f (%s)\n", f.CVSS.Score, f.CVSS.Vector)
			}
			fmt.Println()
			fmt.Printf("Location: %s:%d", f.Location.File, f.Location.LineStart)
			if f.Location.LineEnd > 0 {
				fmt.Printf("-%d", f.Location.LineEnd)
			}
			fmt.Println()
			if f.Location.Function != "" {
				fmt.Printf("Function: %s\n", f.Location.Function)
			}
			fmt.Println()
			if f.Description != "" {
				fmt.Printf("Description:\n%s\n\n", f.Description)
			}
			if f.Location.Snippet != "" {
				fmt.Printf("Code:\n%s\n\n", f.Location.Snippet)
			}
			if f.Impact != "" {
				fmt.Printf("Impact:\n%s\n\n", f.Impact)
			}
			if f.Remediation != "" {
				fmt.Printf("Remediation:\n%s\n\n", f.Remediation)
			}
			if len(f.Evidence) > 0 {
				fmt.Println("Evidence:")
				for _, ev := range f.Evidence {
					fmt.Printf("  - %s: %s\n", ev.Type, ev.Description)
				}
				fmt.Println()
			}
			if len(f.Tags) > 0 {
				fmt.Printf("Tags: %s\n", strings.Join(f.Tags, ", "))
			}
			fmt.Printf("\nCreated: %s\n", f.CreatedAt.Format(time.RFC3339))
			if f.CreatedBy != "" {
				fmt.Printf("Created by: %s\n", f.CreatedBy)
			}
		}
	},
}

// findingExportCmd represents the finding export command
var findingExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export findings",
	Long: `Export findings to various formats.

Supported formats: sarif, json, md (markdown), html, csv`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		format, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")

		store := finding.NewStore(p)
		result, err := store.List(nil)
		if err != nil {
			exitError("%v", err)
		}

		data, err := export.ExportFindings(result.Findings, format, p.Config.Name)
		if err != nil {
			exitError("%v", err)
		}

		if output != "" {
			// Ensure exports directory exists
			dir := filepath.Dir(output)
			if dir == "." || dir == "" {
				dir = store.GetExportsPath()
				output = filepath.Join(dir, output)
			}
			os.MkdirAll(filepath.Dir(output), 0755)

			if err := os.WriteFile(output, data, 0644); err != nil {
				exitError("failed to write file: %v", err)
			}

			if jsonOutput {
				outputJSON(map[string]interface{}{
					"success": true,
					"format":  format,
					"file":    output,
					"count":   result.Total,
				})
			} else {
				fmt.Printf("Exported %d findings to %s\n", result.Total, output)
			}
		} else {
			// Output to stdout
			fmt.Print(string(data))
		}
	},
}

// findingImportCmd represents the finding import command
var findingImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import findings",
	Long:  `Import findings from a YAML file.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		store := finding.NewStore(p)
		f, err := store.Import(args[0])
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(map[string]interface{}{
				"success": true,
				"finding": f,
			})
		} else {
			fmt.Printf("Imported finding: %s\n", f.ID)
		}
	},
}

// findingStatsCmd represents the finding stats command
var findingStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show finding statistics",
	Long:  `Display summary statistics about findings.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		store := finding.NewStore(p)
		stats, err := store.Stats()
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(stats)
		} else {
			fmt.Printf("Total Findings: %d\n\n", stats.Total)

			fmt.Println("By Severity:")
			for _, sev := range finding.ValidSeverities {
				if count := stats.BySeverity[string(sev)]; count > 0 {
					fmt.Printf("  %s %s: %d\n", getSeverityBadge(sev), sev, count)
				}
			}
			fmt.Println()

			fmt.Println("By Status:")
			for _, status := range finding.ValidStatuses {
				if count := stats.ByStatus[string(status)]; count > 0 {
					fmt.Printf("  %s: %d\n", status, count)
				}
			}
			fmt.Println()

			if len(stats.ByCWE) > 0 {
				fmt.Println("By CWE:")
				for cwe, count := range stats.ByCWE {
					fmt.Printf("  %s: %d\n", cwe, count)
				}
				fmt.Println()
			}

			if len(stats.TopTags) > 0 {
				fmt.Println("Top Tags:")
				for _, tag := range stats.TopTags {
					fmt.Printf("  %s: %d\n", tag.Tag, tag.Count)
				}
			}
		}
	},
}

// findingDeleteCmd represents the finding delete command
var findingDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a finding",
	Long:  `Delete a finding by ID.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		store := finding.NewStore(p)
		if err := store.Delete(args[0]); err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(map[string]interface{}{
				"success": true,
				"id":      args[0],
				"action":  "deleted",
			})
		} else {
			fmt.Printf("Deleted finding: %s\n", args[0])
		}
	},
}

func getSeverityBadge(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "[CRIT]"
	case finding.SeverityHigh:
		return "[HIGH]"
	case finding.SeverityMedium:
		return "[MED]"
	case finding.SeverityLow:
		return "[LOW]"
	case finding.SeverityInfo:
		return "[INFO]"
	default:
		return "[???]"
	}
}

func init() {
	rootCmd.AddCommand(findingCmd)
	findingCmd.AddCommand(findingCreateCmd)
	findingCmd.AddCommand(findingUpdateCmd)
	findingCmd.AddCommand(findingListCmd)
	findingCmd.AddCommand(findingShowCmd)
	findingCmd.AddCommand(findingExportCmd)
	findingCmd.AddCommand(findingImportCmd)
	findingCmd.AddCommand(findingStatsCmd)
	findingCmd.AddCommand(findingDeleteCmd)

	findingCreateCmd.Flags().StringP("file", "f", "", "YAML file containing finding")

	findingUpdateCmd.Flags().String("status", "", "Update status (open, confirmed, false_positive, fixed)")
	findingUpdateCmd.Flags().String("severity", "", "Update severity")
	findingUpdateCmd.Flags().String("confidence", "", "Update confidence")

	findingListCmd.Flags().String("severity", "", "Filter by severity")
	findingListCmd.Flags().String("status", "", "Filter by status")
	findingListCmd.Flags().String("cwe", "", "Filter by CWE")

	findingExportCmd.Flags().StringP("format", "f", "json", "Export format (sarif, json, md, html, csv)")
	findingExportCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
}
