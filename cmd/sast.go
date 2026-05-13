package cmd

import (
	"fmt"
	"os"

	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/ihavespoons/zrok/internal/rule"
	"github.com/ihavespoons/zrok/internal/sast"
	"github.com/spf13/cobra"
)

var sastCmd = &cobra.Command{
	Use:   "sast",
	Short: "Run a deterministic SAST scan and persist findings",
	Long: `Runs an opengrep-driven static analysis scan against the project and
persists findings into the zrok store.

Findings created here have created_by="opengrep" and status="open", so the
sast-triage-agent can later mark false positives or confirm them. They flow
through the same fingerprint pipeline as LLM-agent findings, so duplicates
across SAST + LLM dedup automatically in SARIF code-scanning uploads.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		config, _ := cmd.Flags().GetString("config")
		if config == "" {
			exitError("--config is required (path to rules dir, single YAML, or registry id like p/security-audit)")
		}
		tool, _ := cmd.Flags().GetString("tool")
		if tool != "opengrep" {
			exitError("unsupported --tool %q (supported: opengrep)", tool)
		}
		binary, _ := cmd.Flags().GetString("binary")
		diffBase, _ := cmd.Flags().GetString("diff")
		targetFlag, _ := cmd.Flags().GetStringSlice("path")

		// Determine the target paths the scanner walks. Default to the project
		// root; --path scopes to specific files/dirs; --diff scopes to the
		// changed files relative to a base ref (reusing the existing helper).
		targets := targetFlag
		if len(targets) == 0 {
			targets = []string{p.RootPath}
		}
		if diffBase != "" {
			changed, err := getChangedFiles(diffBase)
			if err != nil {
				exitError("%v", err)
			}
			if len(changed) == 0 {
				if jsonOutput {
					if err := outputJSON(map[string]any{"total": 0, "created": 0, "diff_base": diffBase}); err != nil {
					exitError("failed to encode JSON: %v", err)
				}
				} else {
					fmt.Printf("No changed files since %s — skipping SAST scan.\n", diffBase)
				}
				return
			}
			targets = nil
			for f := range changed {
				targets = append(targets, f)
			}
		}

		// Merge project-local rules. Each enabled rule under .zrok/rules/
		// becomes an extra --config to opengrep, so org-specific rules
		// apply automatically alongside the user's chosen ruleset. Retired
		// rules (verdict=retire on their metadata) are skipped here.
		ruleStore := rule.NewStore(p)
		localRulePaths, err := ruleStore.EnabledRulePaths()
		if err != nil {
			exitError("read project rules: %v", err)
		}

		scanner := &sast.Scanner{
			Binary:       binary,
			Config:       config,
			ExtraConfigs: localRulePaths,
		}
		results, err := scanner.Scan(targets)
		if err != nil {
			exitError("%v", err)
		}

		store := finding.NewStore(p)
		created := 0
		skipped := 0
		for _, f := range results {
			f := f
			// Skip results outside the project (opengrep can pick these up
			// when configs include vendored rule directories).
			if _, err := os.Stat(f.Location.File); err != nil {
				skipped++
				continue
			}
			if err := store.Create(&f); err != nil {
				skipped++
				continue
			}
			created++
		}

		bySeverity := map[string]int{}
		for _, f := range results {
			bySeverity[string(f.Severity)]++
		}

		if jsonOutput {
			if err := outputJSON(map[string]any{
				"total":        len(results),
				"created":      created,
				"skipped":      skipped,
				"by_severity":  bySeverity,
				"diff_base":    diffBase,
				"target_count": len(targets),
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
			return
		}

		fmt.Printf("opengrep scan complete\n")
		if len(localRulePaths) > 0 {
			fmt.Printf("  + %d project-local rule(s) from .zrok/rules\n", len(localRulePaths))
		}
		fmt.Printf("  results:  %d\n", len(results))
		fmt.Printf("  created:  %d\n", created)
		if skipped > 0 {
			fmt.Printf("  skipped:  %d (out-of-project or store errors)\n", skipped)
		}
		for _, sev := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo} {
			if n := bySeverity[string(sev)]; n > 0 {
				fmt.Printf("  %s: %d\n", sev, n)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(sastCmd)
	sastCmd.Flags().String("tool", "opengrep", "SAST tool to invoke (currently only: opengrep)")
	sastCmd.Flags().String("config", "", "opengrep --config arg: rules path or registry id (required)")
	sastCmd.Flags().String("binary", "", "Override opengrep binary path (default: opengrep on PATH)")
	sastCmd.Flags().String("diff", "", "Scope scan to files changed since this git ref (e.g. origin/main)")
	sastCmd.Flags().StringSlice("path", nil, "Explicit paths to scan (repeatable). Default: project root.")
}
