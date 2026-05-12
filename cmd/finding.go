package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ihavespoons/zrok/internal/agent"
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
	Use:   "create [-]",
	Short: "Create a new finding",
	Long: `Create a new security finding from a YAML file, stdin, or flags.

Three input modes are supported:

  1. YAML file:    zrok finding create -f finding.yaml
  2. Stdin:        zrok finding create -          (also: -f -)
  3. Flags:        zrok finding create --title ... --severity high \
                       --cwe CWE-89 --file app.py --line 42 \
                       --description "..." [--remediation "..."]

Flag mode is triggered when --title is provided. Stdin mode reads YAML from
standard input. The three modes are mutually exclusive.

Example YAML format:
  title: "SQL Injection in user search"
  severity: high
  confidence: high
  cwe: CWE-89
  location:
    file: "src/api/users.go"
    line_start: 45
  description: "User input is concatenated into SQL query"
  remediation: "Use parameterized queries"

Valid statuses: open, confirmed, false_positive, fixed, duplicate.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		fileFlag, _ := cmd.Flags().GetString("file")
		title, _ := cmd.Flags().GetString("title")

		// Detect stdin mode: positional "-" or "-f -" / "--file -"
		// (only counts as stdin when not in flag mode, since --file in flag
		// mode means source file path)
		stdin := false
		if len(args) == 1 {
			if args[0] != "-" {
				exitError("unexpected positional argument %q (use '-' for stdin)", args[0])
			}
			stdin = true
		}
		if title == "" && fileFlag == "-" {
			stdin = true
			fileFlag = ""
		}

		// Reject obvious conflicts before counting modes.
		// e.g. `finding create -f foo.yaml -` (positional stdin + non-dash -f)
		if stdin && fileFlag != "" && title == "" {
			exitError("cannot combine stdin '-' with -f <file>")
		}

		// In flag mode, --file is the source file path, not a YAML file.
		// In file mode (no --title, no stdin), --file is the YAML path.
		yamlFile := ""
		if title == "" && !stdin {
			yamlFile = fileFlag
		}

		modes := 0
		if stdin {
			modes++
		}
		if yamlFile != "" {
			modes++
		}
		if title != "" {
			modes++
		}
		if modes == 0 {
			exitError("provide finding via -f <file>, '-' for stdin, or --title (with other flags)")
		}
		if modes > 1 {
			exitError("conflicting input modes: pass exactly one of -f, '-' (stdin), or --title flag-mode")
		}

		var f finding.Finding

		switch {
		case title != "":
			// Flag mode
			f, err = buildFindingFromFlags(cmd, title)
			if err != nil {
				exitError("%v", err)
			}
		case stdin:
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				exitError("failed to read stdin: %v", err)
			}
			if err := yaml.Unmarshal(data, &f); err != nil {
				exitError("failed to parse finding: %v", err)
			}
		default:
			data, err := os.ReadFile(yamlFile)
			if err != nil {
				exitError("failed to read file: %v", err)
			}
			if err := yaml.Unmarshal(data, &f); err != nil {
				exitError("failed to parse finding: %v", err)
			}
		}

		// Validate ownership: if --created-by names a known agent with a
		// non-empty owns_cwes list, warn (or reject under --strict) when the
		// finding's CWE is outside that agent's scope.
		strict, _ := cmd.Flags().GetBool("strict")
		if err := validateOwnsCWEs(p, &f, strict); err != nil {
			exitError("%v", err)
		}

		store := finding.NewStore(p)
		if err := store.Create(&f); err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			if err := outputJSON(map[string]interface{}{
				"success": true,
				"id":      f.ID,
				"finding": f,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Printf("Created finding: %s\n", f.ID)
			fmt.Printf("Title: %s\n", f.Title)
			fmt.Printf("Severity: %s\n", f.Severity)
		}
	},
}

// validateOwnsCWEs checks that f.CWE is within the owning agent's owns_cwes list.
// Returns nil for the warn case (writes to stderr) and a non-nil error in --strict
// mode for out-of-scope findings. Returns nil (no validation) when:
//   - f.CreatedBy is empty
//   - the named agent is not found in the registry/config
//   - the agent has no owns_cwes declared
//   - f.CWE is empty
func validateOwnsCWEs(p *project.Project, f *finding.Finding, strict bool) error {
	if f.CreatedBy == "" || f.CWE == "" {
		return nil
	}

	mgr := agent.NewConfigManager(p, "")
	cfg, err := mgr.Get(f.CreatedBy)
	if err != nil || cfg == nil {
		return nil // agent not found, skip validation
	}
	if len(cfg.Specialization.OwnsCWEs) == 0 {
		return nil
	}

	want := strings.ToUpper(strings.TrimSpace(f.CWE))
	for _, c := range cfg.Specialization.OwnsCWEs {
		if strings.ToUpper(strings.TrimSpace(c)) == want {
			return nil
		}
	}

	if strict {
		return fmt.Errorf("%s is not in %s's owns_cwes %v; finding rejected (--strict)",
			f.CWE, f.CreatedBy, cfg.Specialization.OwnsCWEs)
	}
	fmt.Fprintf(os.Stderr,
		"warning: %s is not in %s's owns_cwes %v; finding created anyway. Pass --strict to reject out-of-scope findings.\n",
		f.CWE, f.CreatedBy, cfg.Specialization.OwnsCWEs)
	return nil
}

// buildFindingFromFlags constructs a Finding from CLI flags.
func buildFindingFromFlags(cmd *cobra.Command, title string) (finding.Finding, error) {
	severity, _ := cmd.Flags().GetString("severity")
	cwe, _ := cmd.Flags().GetString("cwe")
	srcFile, _ := cmd.Flags().GetString("file")
	line, _ := cmd.Flags().GetInt("line")
	description, _ := cmd.Flags().GetString("description")
	remediation, _ := cmd.Flags().GetString("remediation")
	confidence, _ := cmd.Flags().GetString("confidence")
	tags, _ := cmd.Flags().GetStringSlice("tag")
	createdBy, _ := cmd.Flags().GetString("created-by")

	f := finding.Finding{
		Title:       title,
		Severity:    finding.Severity(severity),
		Confidence:  finding.Confidence(confidence),
		CWE:         cwe,
		Description: description,
		Remediation: remediation,
		Tags:        tags,
		CreatedBy:   createdBy,
		Location: finding.Location{
			File:      srcFile,
			LineStart: line,
		},
	}
	return f, nil
}

// findingUpdateCmd represents the finding update command
var findingUpdateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update a finding",
	Long: `Update an existing finding by ID.

You can update status, severity, or provide a new YAML file.

Valid statuses: open, confirmed, false_positive, fixed, duplicate.
When marking a finding as duplicate, optionally pass --duplicate-of FIND-XXX
to record the canonical finding ID.`,
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
		if exploitability, _ := cmd.Flags().GetString("exploitability"); exploitability != "" {
			f.Exploitability = finding.Exploitability(exploitability)
		}
		if fixPriority, _ := cmd.Flags().GetString("fix-priority"); fixPriority != "" {
			f.FixPriority = finding.FixPriority(fixPriority)
		}
		if dupOf, _ := cmd.Flags().GetString("duplicate-of"); dupOf != "" {
			f.DuplicateOf = dupOf
		}
		if note, _ := cmd.Flags().GetString("note"); note != "" {
			author, _ := cmd.Flags().GetString("note-author")
			if author == "" {
				author = "user"
			}
			f.Notes = append(f.Notes, finding.FindingNote{
				Timestamp: time.Now(),
				Author:    author,
				Text:      note,
			})
		}

		if err := store.Update(f); err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			if err := outputJSON(map[string]interface{}{
				"success": true,
				"finding": f,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
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
		if exp, _ := cmd.Flags().GetString("exploitability"); exp != "" {
			opts.Exploitability = finding.Exploitability(exp)
		}
		if pri, _ := cmd.Flags().GetString("fix-priority"); pri != "" {
			opts.FixPriority = finding.FixPriority(pri)
		}
		if cwe, _ := cmd.Flags().GetString("cwe"); cwe != "" {
			opts.CWE = cwe
		}

		result, err := store.List(opts)
		if err != nil {
			exitError("%v", err)
		}

		// Apply diff filter if specified
		if diffBase, _ := cmd.Flags().GetString("diff"); diffBase != "" {
			changedFiles, err := getChangedFiles(diffBase)
			if err != nil {
				exitError("%v", err)
			}
			result.Findings = filterFindingsByDiff(result.Findings, changedFiles)
			result.Total = len(result.Findings)
		}

		if jsonOutput {
			if err := outputJSON(result); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
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
			if err := outputJSON(f); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Printf("%s %s\n", getSeverityBadge(f.Severity), f.Title)
			fmt.Printf("ID: %s\n", f.ID)
			fmt.Printf("Status: %s\n", f.Status)
			fmt.Printf("Confidence: %s\n", f.Confidence)
			if f.Exploitability != "" {
				fmt.Printf("Exploitability: %s\n", f.Exploitability)
			}
			if f.FixPriority != "" {
				fmt.Printf("Fix Priority: %s\n", f.FixPriority)
			}
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
			if f.DuplicateOf != "" {
				fmt.Printf("Duplicate of: %s\n", f.DuplicateOf)
			}
			if len(f.Notes) > 0 {
				fmt.Println()
				fmt.Println("Notes:")
				for _, n := range f.Notes {
					author := n.Author
					if author == "" {
						author = "user"
					}
					fmt.Printf("  Note [%s] (%s): %s\n",
						n.Timestamp.Format(time.RFC3339), author, n.Text)
				}
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

		// Apply diff filter if specified
		if diffBase, _ := cmd.Flags().GetString("diff"); diffBase != "" {
			changedFiles, err := getChangedFiles(diffBase)
			if err != nil {
				exitError("%v", err)
			}
			result.Findings = filterFindingsByDiff(result.Findings, changedFiles)
			result.Total = len(result.Findings)
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
			if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
				exitError("failed to create directory: %v", err)
			}

			if err := os.WriteFile(output, data, 0644); err != nil {
				exitError("failed to write file: %v", err)
			}

			if jsonOutput {
				if err := outputJSON(map[string]interface{}{
					"success": true,
					"format":  format,
					"file":    output,
					"count":   result.Total,
				}); err != nil {
					exitError("failed to encode JSON: %v", err)
				}
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
			if err := outputJSON(map[string]interface{}{
				"success": true,
				"finding": f,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
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
			if err := outputJSON(stats); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
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

			if len(stats.ByExploitability) > 0 {
				fmt.Println("By Exploitability:")
				for _, exp := range finding.ValidExploitabilities {
					if count := stats.ByExploitability[string(exp)]; count > 0 {
						fmt.Printf("  %s: %d\n", exp, count)
					}
				}
				fmt.Println()
			}

			if len(stats.ByFixPriority) > 0 {
				fmt.Println("By Fix Priority:")
				for _, pri := range finding.ValidFixPriorities {
					if count := stats.ByFixPriority[string(pri)]; count > 0 {
						fmt.Printf("  %s: %d\n", pri, count)
					}
				}
				fmt.Println()
			}

			if len(stats.ByCWE) > 0 {
				fmt.Println("By CWE:")
				for cwe, count := range stats.ByCWE {
					fmt.Printf("  %s: %d\n", cwe, count)
				}
				fmt.Println()
			}

			if len(stats.ByCreatedBy) > 0 {
				fmt.Println("By Agent:")
				for agent, count := range stats.ByCreatedBy {
					fmt.Printf("  %s: %d\n", agent, count)
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
			if err := outputJSON(map[string]interface{}{
				"success": true,
				"id":      args[0],
				"action":  "deleted",
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Printf("Deleted finding: %s\n", args[0])
		}
	},
}

// getChangedFiles returns the list of files changed between base-ref and HEAD
func getChangedFiles(baseRef string) (map[string]bool, error) {
	cmd := exec.Command("git", "diff", "--name-only", baseRef+"...HEAD")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff failed: %w", err)
	}

	files := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			files[line] = true
		}
	}
	return files, nil
}

// filterFindingsByDiff filters findings to only those in changed files
func filterFindingsByDiff(findings []finding.Finding, changedFiles map[string]bool) []finding.Finding {
	var filtered []finding.Finding
	for _, f := range findings {
		if changedFiles[f.Location.File] {
			filtered = append(filtered, f)
		}
	}
	return filtered
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

	findingCreateCmd.Flags().StringP("file", "f", "", "YAML file path (file mode); in --title flag mode this is the source file the finding refers to. Use '-' to read YAML from stdin.")
	findingCreateCmd.Flags().String("title", "", "Finding title (triggers flag mode)")
	findingCreateCmd.Flags().String("severity", "", "Severity: critical, high, medium, low, info")
	findingCreateCmd.Flags().String("cwe", "", "CWE identifier (e.g. CWE-89)")
	findingCreateCmd.Flags().Int("line", 0, "Source file line number where the finding occurs (>=1 required)")
	findingCreateCmd.Flags().String("description", "", "Description of the finding")
	findingCreateCmd.Flags().String("remediation", "", "Suggested remediation")
	findingCreateCmd.Flags().String("confidence", "", "Confidence: high, medium, low (default: medium)")
	findingCreateCmd.Flags().StringSlice("tag", []string{}, "Tags (repeatable)")
	findingCreateCmd.Flags().String("created-by", "", "Identifier of agent/user creating the finding")
	findingCreateCmd.Flags().Bool("strict", false, "Reject findings whose CWE is outside the --created-by agent's owns_cwes")

	findingUpdateCmd.Flags().String("status", "", "Update status (open, confirmed, false_positive, fixed, duplicate)")
	findingUpdateCmd.Flags().String("severity", "", "Update severity")
	findingUpdateCmd.Flags().String("confidence", "", "Update confidence")
	findingUpdateCmd.Flags().String("exploitability", "", "Update exploitability (proven, likely, possible, unlikely, unknown)")
	findingUpdateCmd.Flags().String("fix-priority", "", "Update fix priority (immediate, high, medium, low, defer)")
	findingUpdateCmd.Flags().String("duplicate-of", "", "Canonical finding ID this is a duplicate of (e.g. FIND-001); typically paired with --status duplicate")
	findingUpdateCmd.Flags().String("note", "", "Append a timestamped note to the finding (repeatable across updates)")
	findingUpdateCmd.Flags().String("note-author", "", "Author for --note (default: \"user\")")

	findingListCmd.Flags().String("severity", "", "Filter by severity")
	findingListCmd.Flags().String("status", "", "Filter by status")
	findingListCmd.Flags().String("exploitability", "", "Filter by exploitability")
	findingListCmd.Flags().String("fix-priority", "", "Filter by fix priority")
	findingListCmd.Flags().String("cwe", "", "Filter by CWE")
	findingListCmd.Flags().String("diff", "", "Filter to findings in files changed since base ref (e.g., main)")

	findingExportCmd.Flags().StringP("format", "f", "json", "Export format (sarif, json, md, html, csv)")
	findingExportCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	findingExportCmd.Flags().String("diff", "", "Filter to findings in files changed since base ref (e.g., main)")
}
