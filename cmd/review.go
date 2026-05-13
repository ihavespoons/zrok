package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ihavespoons/zrok/internal/agent"
	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/finding/export"
	"github.com/ihavespoons/zrok/internal/memory"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/spf13/cobra"
)

var reviewCmd = &cobra.Command{
	Use:   "review",
	Short: "PR/diff-scoped code review workflows",
	Long: `Commands for running zrok against a pull request or diff.

The 'pr' subcommands are designed to be called by CI (e.g. a GitHub Action):
  zrok review pr setup  --base <ref>   Prepare scope and emit agent prompts
  zrok review pr report --base <ref>   Filter findings to diff and render outputs`,
}

var reviewPrCmd = &cobra.Command{
	Use:   "pr",
	Short: "Run a review scoped to a pull request",
}

// reviewSetup is the JSON payload emitted by `review pr setup`.
type reviewSetup struct {
	Base            string                       `json:"base"`
	HeadSHA         string                       `json:"head_sha"`
	ChangedFiles    []string                     `json:"changed_files"`
	Classification  project.ProjectClassification `json:"classification"`
	SuggestedAgents []string                     `json:"suggested_agents"`
	PromptsDir      string                       `json:"prompts_dir,omitempty"`
	AgentPrompts    map[string]string            `json:"agent_prompts,omitempty"`
}

// reviewReport is the JSON payload emitted by `review pr report`.
type reviewReport struct {
	Base            string               `json:"base"`
	Total           int                  `json:"total"`
	BySeverity      map[string]int       `json:"by_severity"`
	Findings        []finding.Finding    `json:"findings"`
	CommentMarkdown string               `json:"comment_markdown"`
	SarifPath       string               `json:"sarif_path,omitempty"`
	CommentPath     string               `json:"comment_path,omitempty"`
}

var reviewPrSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Prepare scope for a PR review and emit agent prompts",
	Long: `Resolves the diff against --base, classifies the project, and emits the
set of agents that apply along with their fully-rendered prompts. The output
is consumed by the CI driver (Claude Code, OpenCode) to spawn agents.`,
	Run: func(cmd *cobra.Command, args []string) {
		base, _ := cmd.Flags().GetString("base")
		if base == "" {
			exitError("--base is required (e.g. origin/main)")
		}
		inlinePrompts, _ := cmd.Flags().GetBool("inline-prompts")
		promptsDirFlag, _ := cmd.Flags().GetString("prompts-dir")

		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		// Classification drives agent gating. If it's empty (fresh `zrok init`
		// in CI), run static onboarding so suggestion sees real project type
		// and traits rather than falling back to always-include agents only.
		if isEmptyClassification(p.Config.Classification) {
			ob := project.NewOnboarder(p)
			if _, err := ob.RunAuto(); err != nil {
				exitError("auto-classify failed: %v", err)
			}
		}

		changed, err := gitChangedFiles(base)
		if err != nil {
			exitError("%v", err)
		}
		head, err := gitHeadSHA()
		if err != nil {
			exitError("%v", err)
		}

		classification := p.Config.Classification
		suggested := agent.SuggestAgents(classification)

		// Render each agent's prompt. Default: write to disk (small JSON
		// output, friendly to CI step output limits). With --inline-prompts:
		// embed in the JSON payload for callers that want a single blob.
		gen := agent.NewPromptGenerator(p, memory.NewStore(p))
		prompts := map[string]string{}
		promptsDir := promptsDirFlag
		if promptsDir == "" {
			promptsDir = filepath.Join(p.GetZrokPath(), "review", "prompts")
		}
		if !inlinePrompts {
			if err := os.MkdirAll(promptsDir, 0755); err != nil {
				exitError("failed to create prompts dir: %v", err)
			}
		}
		for _, name := range suggested {
			cfg := agent.GetBuiltinAgent(name)
			if cfg == nil {
				continue
			}
			text, perr := gen.Generate(cfg)
			if perr != nil {
				exitError("generate prompt for %s: %v", name, perr)
			}
			if inlinePrompts {
				prompts[name] = text
				continue
			}
			path := filepath.Join(promptsDir, name+".md")
			if err := os.WriteFile(path, []byte(text), 0644); err != nil {
				exitError("failed to write prompt %s: %v", name, err)
			}
		}

		out := reviewSetup{
			Base:            base,
			HeadSHA:         head,
			ChangedFiles:    changed,
			Classification:  classification,
			SuggestedAgents: suggested,
		}
		if inlinePrompts {
			out.AgentPrompts = prompts
		} else {
			out.PromptsDir = promptsDir
		}

		if jsonOutput {
			if err := outputJSON(out); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
			return
		}

		fmt.Printf("Base: %s\nHead: %s\n", out.Base, out.HeadSHA)
		fmt.Printf("Changed files: %d\n", len(out.ChangedFiles))
		for _, f := range out.ChangedFiles {
			fmt.Printf("  - %s\n", f)
		}
		fmt.Printf("\nSuggested agents (%d):\n", len(out.SuggestedAgents))
		for _, name := range out.SuggestedAgents {
			fmt.Printf("  - %s\n", name)
		}
		if !inlinePrompts {
			fmt.Printf("\nPrompts written to: %s\n", out.PromptsDir)
		}
	},
}

func isEmptyClassification(c project.ProjectClassification) bool {
	return len(c.Types) == 0 && len(c.Traits) == 0
}

var reviewPrReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Render PR-ready outputs from findings in the diff",
	Long: `Filters the finding store to issues located in the diff against --base,
renders a standardized PR comment, and writes a SARIF file with stable
partialFingerprints. Designed to be consumed by a GitHub Action posting via
gh api and uploading to code-scanning.`,
	Run: func(cmd *cobra.Command, args []string) {
		base, _ := cmd.Flags().GetString("base")
		if base == "" {
			exitError("--base is required (e.g. origin/main)")
		}
		topN, _ := cmd.Flags().GetInt("top-n")
		threshold, _ := cmd.Flags().GetString("severity-threshold")
		outDir, _ := cmd.Flags().GetString("output-dir")
		sarifLink, _ := cmd.Flags().GetString("sarif-link")

		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		changed, err := gitChangedFiles(base)
		if err != nil {
			exitError("%v", err)
		}
		changedSet := make(map[string]bool, len(changed))
		for _, f := range changed {
			changedSet[f] = true
		}

		store := finding.NewStore(p)
		all, err := store.List(nil)
		if err != nil {
			exitError("%v", err)
		}
		inDiff := filterFindingsByDiff(all.Findings, changedSet)

		bySeverity := map[string]int{}
		for _, f := range inDiff {
			bySeverity[string(f.Severity)]++
		}

		md := renderPRComment(inDiff, topN, finding.Severity(strings.ToLower(threshold)), sarifLink)

		// Write artifacts to disk so the action can pick them up.
		if outDir == "" {
			outDir = filepath.Join(store.GetExportsPath(), "pr")
		}
		if err := os.MkdirAll(outDir, 0755); err != nil {
			exitError("failed to create output dir: %v", err)
		}
		commentPath := filepath.Join(outDir, "comment.md")
		if err := os.WriteFile(commentPath, []byte(md), 0644); err != nil {
			exitError("failed to write comment.md: %v", err)
		}
		sarifBytes, err := export.ExportFindings(inDiff, "sarif", p.Config.Name)
		if err != nil {
			exitError("failed to render SARIF: %v", err)
		}
		sarifPath := filepath.Join(outDir, "report.sarif")
		if err := os.WriteFile(sarifPath, sarifBytes, 0644); err != nil {
			exitError("failed to write SARIF: %v", err)
		}

		out := reviewReport{
			Base:            base,
			Total:           len(inDiff),
			BySeverity:      bySeverity,
			Findings:        inDiff,
			CommentMarkdown: md,
			SarifPath:       sarifPath,
			CommentPath:     commentPath,
		}

		if jsonOutput {
			if err := outputJSON(out); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
			return
		}

		fmt.Printf("Findings in diff: %d\n", out.Total)
		for _, sev := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo} {
			if n := bySeverity[string(sev)]; n > 0 {
				fmt.Printf("  %s: %d\n", sev, n)
			}
		}
		fmt.Printf("\nComment: %s\nSARIF:   %s\n", commentPath, sarifPath)
	},
}

// renderPRComment is the standardized PR comment template. Kept pure so it can
// be tested without git or filesystem state.
func renderPRComment(findings []finding.Finding, topN int, threshold finding.Severity, sarifLink string) string {
	if topN <= 0 {
		topN = 10
	}

	var b strings.Builder
	b.WriteString("## zrok security review\n\n")

	if len(findings) == 0 {
		b.WriteString("No security findings in the changes on this PR.\n")
		return b.String()
	}

	bySeverity := map[finding.Severity]int{}
	for _, f := range findings {
		bySeverity[f.Severity]++
	}
	b.WriteString(fmt.Sprintf("Found **%d** finding(s) in this PR", len(findings)))
	var counts []string
	for _, sev := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo} {
		if n := bySeverity[sev]; n > 0 {
			counts = append(counts, fmt.Sprintf("**%d** %s", n, sev))
		}
	}
	if len(counts) > 0 {
		b.WriteString(" — " + strings.Join(counts, ", "))
	}
	b.WriteString(".\n\n")

	// Findings are already sorted by severity by the store. Apply threshold to
	// comment posting only — full SARIF still contains everything.
	shown := 0
	thresholdWeight := finding.SeverityWeight(threshold)
	for _, f := range findings {
		if thresholdWeight > 0 && finding.SeverityWeight(f.Severity) < thresholdWeight {
			continue
		}
		if shown >= topN {
			break
		}
		shown++
		b.WriteString(renderFindingBlock(shown, f))
	}

	if shown == 0 {
		b.WriteString(fmt.Sprintf("_All %d finding(s) are below the `%s` severity threshold. See full SARIF report for details._\n\n", len(findings), threshold))
	} else if shown < len(findings) {
		b.WriteString(fmt.Sprintf("_… and %d more finding(s). See full SARIF report for details._\n\n", len(findings)-shown))
	}

	if sarifLink != "" {
		b.WriteString(fmt.Sprintf("[View all findings in code-scanning](%s)\n", sarifLink))
	}
	return b.String()
}

func renderFindingBlock(n int, f finding.Finding) string {
	var b strings.Builder
	badge := strings.ToUpper(string(f.Severity))
	cweSuffix := ""
	if f.CWE != "" {
		cweSuffix = fmt.Sprintf(" (%s)", f.CWE)
	}
	b.WriteString(fmt.Sprintf("### %d. [%s] %s%s\n", n, badge, f.Title, cweSuffix))

	loc := fmt.Sprintf("`%s:%d", f.Location.File, f.Location.LineStart)
	if f.Location.LineEnd > f.Location.LineStart {
		loc += fmt.Sprintf("-%d", f.Location.LineEnd)
	}
	loc += "`"
	if f.Location.Function != "" {
		loc += fmt.Sprintf(" in `%s`", f.Location.Function)
	}
	b.WriteString("**Location:** " + loc + "\n\n")

	if f.Description != "" {
		b.WriteString("**What:** " + strings.TrimSpace(f.Description) + "\n\n")
	}
	if f.Impact != "" {
		b.WriteString("**Why it matters:** " + strings.TrimSpace(f.Impact) + "\n\n")
	}
	if f.Remediation != "" {
		b.WriteString("**Suggested fix:**\n\n")
		b.WriteString(strings.TrimSpace(f.Remediation))
		b.WriteString("\n\n")
	}

	var meta []string
	if f.Confidence != "" {
		meta = append(meta, "confidence: "+string(f.Confidence))
	}
	if f.CreatedBy != "" {
		meta = append(meta, "agent: "+f.CreatedBy)
	}
	if len(meta) > 0 {
		b.WriteString("_" + strings.Join(meta, " · ") + "_\n\n")
	}
	return b.String()
}

// gitChangedFiles returns the list of files changed between base-ref and HEAD.
// This is the slice form of cmd/finding.go's getChangedFiles, suitable for
// emitting in JSON and for building a set.
func gitChangedFiles(baseRef string) ([]string, error) {
	out, err := exec.Command("git", "diff", "--name-only", baseRef+"...HEAD").Output()
	if err != nil {
		return nil, fmt.Errorf("git diff failed: %w", err)
	}
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

func gitHeadSHA() (string, error) {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func init() {
	rootCmd.AddCommand(reviewCmd)
	reviewCmd.AddCommand(reviewPrCmd)
	reviewPrCmd.AddCommand(reviewPrSetupCmd)
	reviewPrCmd.AddCommand(reviewPrReportCmd)

	reviewPrSetupCmd.Flags().String("base", "", "Base git ref to diff against (e.g. origin/main)")
	reviewPrSetupCmd.Flags().Bool("inline-prompts", false, "Embed agent prompts in JSON output instead of writing to disk")
	reviewPrSetupCmd.Flags().String("prompts-dir", "", "Directory to write per-agent prompt files (default: .zrok/review/prompts)")

	reviewPrReportCmd.Flags().String("base", "", "Base git ref to diff against (e.g. origin/main)")
	reviewPrReportCmd.Flags().Int("top-n", 10, "Maximum findings to inline in the PR comment")
	reviewPrReportCmd.Flags().String("severity-threshold", "", "Only inline findings at or above this severity (critical, high, medium, low, info)")
	reviewPrReportCmd.Flags().String("output-dir", "", "Directory to write comment.md and report.sarif (default: .zrok/findings/exports/pr)")
	reviewPrReportCmd.Flags().String("sarif-link", "", "URL to link to in the PR comment (e.g. code-scanning view)")
}
