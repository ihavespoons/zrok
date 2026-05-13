package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ihavespoons/zrok/internal/project"
	"github.com/ihavespoons/zrok/internal/rule"
	"github.com/spf13/cobra"
)

var ruleCmd = &cobra.Command{
	Use:   "rule",
	Short: "Manage project-local opengrep rules",
	Long: `Rules live as opengrep-compatible YAML files in .zrok/rules/<slug>.yaml.
Each has a sidecar <slug>.zmeta.yaml recording provenance (who authored it,
why, for which PR) and any judge verdict. zrok sast picks up enabled rules
automatically; retired rules stay on disk but are skipped at scan time.`,
}

var ruleAddCmd = &cobra.Command{
	Use:   "add <slug>",
	Short: "Add a new opengrep rule",
	Long: `Reads opengrep-format YAML from --file or stdin and stores it as
.zrok/rules/<slug>.yaml with a metadata sidecar capturing provenance.

The rule YAML is validated for minimal opengrep structure (top-level
"rules:" list, each with id/message/pattern) before being written —
malformed rules are rejected at authoring time rather than failing later
during scan.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		slug := args[0]

		file, _ := cmd.Flags().GetString("file")
		createdBy, _ := cmd.Flags().GetString("created-by")
		createdFor, _ := cmd.Flags().GetString("created-for")
		reasoning, _ := cmd.Flags().GetString("reasoning")

		var content []byte
		if file == "-" || file == "" {
			content, err = io.ReadAll(os.Stdin)
			if err != nil {
				exitError("read stdin: %v", err)
			}
		} else {
			content, err = os.ReadFile(file)
			if err != nil {
				exitError("read file: %v", err)
			}
		}
		if len(content) == 0 {
			exitError("rule YAML is empty (pass --file or pipe via stdin)")
		}

		if createdBy == "" {
			createdBy = defaultCreatedBy()
		}

		meta := rule.Meta{
			CreatedBy:  createdBy,
			CreatedAt:  time.Now().UTC(),
			CreatedFor: createdFor,
			Reasoning:  reasoning,
		}

		store := rule.NewStore(p)
		if err := store.Add(slug, content, meta); err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			outputJSON(map[string]any{
				"slug":       slug,
				"created_by": createdBy,
			})
			return
		}
		fmt.Printf("Added rule %s (by %s)\n", slug, createdBy)
	},
}

var ruleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List project-local rules",
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		store := rule.NewStore(p)
		list, err := store.List()
		if err != nil {
			exitError("%v", err)
		}
		if jsonOutput {
			outputJSON(list)
			return
		}
		if len(list) == 0 {
			fmt.Println("No project-local rules")
			return
		}
		for _, m := range list {
			status := "enabled"
			if m.Disabled {
				status = "disabled"
			}
			verdict := string(m.Verdict)
			if verdict == "" {
				verdict = "—"
			}
			fmt.Printf("%-30s  %-8s  verdict=%-9s  by %s\n",
				m.Slug, status, verdict, m.CreatedBy)
		}
		fmt.Printf("\n%d rule(s)\n", len(list))
	},
}

var ruleRemoveCmd = &cobra.Command{
	Use:   "remove <slug>",
	Short: "Remove a rule and its metadata sidecar",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		store := rule.NewStore(p)
		if err := store.Remove(args[0]); err != nil {
			exitError("%v", err)
		}
		if jsonOutput {
			outputJSON(map[string]string{"removed": args[0]})
			return
		}
		fmt.Printf("Removed rule %s\n", args[0])
	},
}

var ruleAnnotateCmd = &cobra.Command{
	Use:   "annotate <slug>",
	Short: "Set the rule-judge-agent verdict on a rule",
	Long: `Records a verdict (keep / refine / retire / escalate) on the rule's
metadata. Retire marks the rule disabled, so subsequent zrok sast runs skip
it; the rule file itself is preserved for archaeology.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		verdictStr, _ := cmd.Flags().GetString("verdict")
		note, _ := cmd.Flags().GetString("note")
		verdict := rule.Verdict(strings.ToLower(strings.TrimSpace(verdictStr)))
		if !rule.IsValidVerdict(verdict) {
			exitError("invalid --verdict %q (valid: keep, refine, retire, escalate)", verdictStr)
		}
		store := rule.NewStore(p)
		if err := store.Annotate(args[0], verdict, note); err != nil {
			exitError("%v", err)
		}
		if jsonOutput {
			outputJSON(map[string]any{"slug": args[0], "verdict": verdict, "note": note})
			return
		}
		fmt.Printf("Annotated %s: verdict=%s\n", args[0], verdict)
		if verdict == rule.VerdictRetire {
			fmt.Println("(Rule will be skipped by zrok sast — file preserved.)")
		}
	},
}

// ruleAuditEntry is the per-rule payload `zrok rule audit` emits. The rule-
// judge-agent reads this (typically via --json) to assess each rule and
// decide a verdict.
type ruleAuditEntry struct {
	Slug       string    `json:"slug"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	CreatedFor string    `json:"created_for,omitempty"`
	Reasoning  string    `json:"reasoning,omitempty"`

	// Prior judge assessment.
	Verdict     rule.Verdict `json:"verdict,omitempty"`
	VerdictNote string       `json:"verdict_note,omitempty"`
	LastAuditAt time.Time    `json:"last_audit_at,omitempty"`

	// Activity signals (populated when zrok tracks them; zero otherwise).
	TriggerCount int `json:"trigger_count"`
	FPCount      int `json:"fp_count"`

	Disabled bool   `json:"disabled"`
	RuleBody string `json:"rule_body"` // raw opengrep YAML content
}

var ruleAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Emit current rule state for the rule-judge-agent to assess",
	Long: `Outputs a structured view of every project-local rule — provenance,
verdict history, and rule body — designed to be consumed by the
rule-judge-agent. With --json (recommended), the agent can parse the result
in one call and emit annotate verdicts for each rule.

This command makes no changes. The judge applies verdicts via
zrok rule annotate.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		store := rule.NewStore(p)
		metas, err := store.List()
		if err != nil {
			exitError("%v", err)
		}
		entries := make([]ruleAuditEntry, 0, len(metas))
		for _, m := range metas {
			body, err := store.ReadRule(m.Slug)
			if err != nil {
				continue
			}
			entries = append(entries, ruleAuditEntry{
				Slug:         m.Slug,
				CreatedBy:    m.CreatedBy,
				CreatedAt:    m.CreatedAt,
				CreatedFor:   m.CreatedFor,
				Reasoning:    m.Reasoning,
				Verdict:      m.Verdict,
				VerdictNote:  m.VerdictNote,
				LastAuditAt:  m.LastAuditAt,
				TriggerCount: m.TriggerCount,
				FPCount:      m.FPCount,
				Disabled:     m.Disabled,
				RuleBody:     string(body),
			})
		}

		if jsonOutput {
			outputJSON(entries)
			return
		}
		if len(entries) == 0 {
			fmt.Println("No project-local rules to audit")
			return
		}
		for _, e := range entries {
			fmt.Printf("=== %s ===\n", e.Slug)
			fmt.Printf("  created_by:   %s\n", e.CreatedBy)
			fmt.Printf("  created_at:   %s\n", e.CreatedAt.Format(time.RFC3339))
			if e.CreatedFor != "" {
				fmt.Printf("  created_for:  %s\n", e.CreatedFor)
			}
			if e.Reasoning != "" {
				fmt.Printf("  reasoning:    %s\n", e.Reasoning)
			}
			fmt.Printf("  verdict:      %s\n", string(e.Verdict))
			if e.VerdictNote != "" {
				fmt.Printf("  verdict_note: %s\n", e.VerdictNote)
			}
			if !e.LastAuditAt.IsZero() {
				fmt.Printf("  last_audit:   %s\n", e.LastAuditAt.Format(time.RFC3339))
			}
			fmt.Printf("  triggers:     %d (fp: %d)\n", e.TriggerCount, e.FPCount)
			fmt.Printf("  disabled:     %v\n", e.Disabled)
			fmt.Println()
		}
		fmt.Printf("%d rule(s)\n", len(entries))
	},
}

func defaultCreatedBy() string {
	if u := strings.TrimSpace(os.Getenv("USER")); u != "" {
		return "human:" + u
	}
	return "human:unknown"
}

func init() {
	rootCmd.AddCommand(ruleCmd)
	ruleCmd.AddCommand(ruleAddCmd)
	ruleCmd.AddCommand(ruleListCmd)
	ruleCmd.AddCommand(ruleRemoveCmd)
	ruleCmd.AddCommand(ruleAnnotateCmd)
	ruleCmd.AddCommand(ruleAuditCmd)

	ruleAddCmd.Flags().String("file", "-", "Path to rule YAML (default: stdin)")
	ruleAddCmd.Flags().String("created-by", "", "Attribution (e.g. agent:injection-agent or human:alice). Defaults to human:$USER.")
	ruleAddCmd.Flags().String("created-for", "", "Optional context (e.g. PR #482)")
	ruleAddCmd.Flags().String("reasoning", "", "Why this rule was added (encouraged, not required)")

	ruleAnnotateCmd.Flags().String("verdict", "", "Verdict: keep, refine, retire, escalate (required)")
	ruleAnnotateCmd.Flags().String("note", "", "Free-form note explaining the verdict")
}
