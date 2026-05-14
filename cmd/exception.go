package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ihavespoons/quokka/internal/exception"
	"github.com/ihavespoons/quokka/internal/project"
	"github.com/spf13/cobra"
)

var exceptionCmd = &cobra.Command{
	Use:   "exception",
	Short: "Manage finding suppressions (exceptions)",
	Long: `Exceptions suppress findings either by fingerprint (one specific
finding) or by path glob + CWE (a class of findings within a path).

Every exception requires a reason, an expires date, and an approver.
Suppressions are time-bounded by design — they expire and reappear for
re-evaluation rather than silently masking issues forever.`,
}

var exceptionAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new suppression",
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		fp, _ := cmd.Flags().GetString("fingerprint")
		pg, _ := cmd.Flags().GetString("path-glob")
		cwe, _ := cmd.Flags().GetString("cwe")
		reason, _ := cmd.Flags().GetString("reason")
		expiresStr, _ := cmd.Flags().GetString("expires")
		approvedBy, _ := cmd.Flags().GetString("approved-by")
		approvedFor, _ := cmd.Flags().GetString("approved-for")

		if reason == "" {
			exitError("--reason is required")
		}
		if expiresStr == "" {
			exitError("--expires is required (YYYY-MM-DD); suppressions must be time-bounded")
		}
		expires, err := parseExpires(expiresStr)
		if err != nil {
			exitError("invalid --expires: %v", err)
		}
		if approvedBy == "" {
			approvedBy = defaultApprovedBy()
		}

		e := exception.Exception{
			Fingerprint: strings.TrimSpace(fp),
			PathGlob:    strings.TrimSpace(pg),
			CWE:         strings.ToUpper(strings.TrimSpace(cwe)),
			Reason:      reason,
			Expires:     expires,
			ApprovedBy:  approvedBy,
			ApprovedFor: approvedFor,
		}

		store := exception.NewStore(p)
		saved, err := store.Add(e)
		if err != nil {
			exitError("%v", err)
		}

		if jsonOutput {
			if err := outputJSON(saved); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
			return
		}
		fmt.Printf("Added %s (expires %s)\n", saved.ID, saved.Expires.Format("2006-01-02"))
	},
}

var exceptionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active suppressions",
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		includeExpired, _ := cmd.Flags().GetBool("include-expired")
		store := exception.NewStore(p)
		list, err := store.List(includeExpired)
		if err != nil {
			exitError("%v", err)
		}
		exception.SortByExpires(list)

		if jsonOutput {
			if err := outputJSON(list); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
			return
		}
		if len(list) == 0 {
			fmt.Println("No exceptions")
			return
		}
		now := time.Now()
		for _, e := range list {
			target := ""
			if e.IsFingerprint() {
				target = "fp=" + shortFP(e.Fingerprint)
			} else {
				target = e.PathGlob + " (" + e.CWE + ")"
			}
			status := ""
			if e.IsExpired(now) {
				status = " EXPIRED"
			} else if e.Expires.Before(now.Add(14 * 24 * time.Hour)) {
				status = " EXPIRING-SOON"
			}
			fmt.Printf("%s  %s  expires %s%s\n  reason: %s\n  by: %s\n",
				e.ID, target, e.Expires.Format("2006-01-02"), status, e.Reason, e.ApprovedBy)
		}
		fmt.Printf("\n%d exception(s)\n", len(list))
	},
}

var exceptionRemoveCmd = &cobra.Command{
	Use:   "remove <id>",
	Short: "Remove a suppression by ID",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		store := exception.NewStore(p)
		if err := store.Remove(args[0]); err != nil {
			exitError("%v", err)
		}
		if jsonOutput {
			if err := outputJSON(map[string]string{"removed": args[0]}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
			return
		}
		fmt.Printf("Removed %s\n", args[0])
	},
}

var exceptionExpireCmd = &cobra.Command{
	Use:   "expire",
	Short: "Remove all expired suppressions",
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		store := exception.NewStore(p)
		removed, err := store.Expire()
		if err != nil {
			exitError("%v", err)
		}
		if jsonOutput {
			if err := outputJSON(map[string]any{"removed": removed, "count": len(removed)}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
			return
		}
		if len(removed) == 0 {
			fmt.Println("No expired exceptions")
			return
		}
		fmt.Printf("Removed %d expired exception(s): %s\n", len(removed), strings.Join(removed, ", "))
	},
}

// parseExpires accepts YYYY-MM-DD or full RFC3339. Anchors the date at
// 23:59:59 UTC so "expires: 2026-09-01" means "good through 2026-09-01."
func parseExpires(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.Add(24*time.Hour - time.Second), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("expected YYYY-MM-DD or RFC3339, got %q", s)
}

// defaultApprovedBy infers a sensible attribution when --approved-by is
// omitted. CLI invocations usually want "human:<username>"; agent-driven
// invocations are expected to pass --approved-by="agent:<name>" explicitly.
func defaultApprovedBy() string {
	if u := strings.TrimSpace(os.Getenv("USER")); u != "" {
		return "human:" + u
	}
	return "human:unknown"
}

func shortFP(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

func init() {
	rootCmd.AddCommand(exceptionCmd)
	exceptionCmd.AddCommand(exceptionAddCmd)
	exceptionCmd.AddCommand(exceptionListCmd)
	exceptionCmd.AddCommand(exceptionRemoveCmd)
	exceptionCmd.AddCommand(exceptionExpireCmd)

	exceptionAddCmd.Flags().String("fingerprint", "", "Finding fingerprint to suppress (mutually exclusive with --path-glob)")
	exceptionAddCmd.Flags().String("path-glob", "", "filepath.Match glob to suppress (e.g. tests/*.py); requires --cwe")
	exceptionAddCmd.Flags().String("cwe", "", "CWE identifier this exception scopes to (required with --path-glob)")
	exceptionAddCmd.Flags().String("reason", "", "Why this finding is acceptable (required)")
	exceptionAddCmd.Flags().String("expires", "", "When this exception expires (YYYY-MM-DD, required)")
	exceptionAddCmd.Flags().String("approved-by", "", "Approver attribution (e.g. human:alice or agent:sast-triage-agent)")
	exceptionAddCmd.Flags().String("approved-for", "", "Optional context (e.g. PR #482)")

	exceptionListCmd.Flags().Bool("include-expired", false, "Include expired exceptions in the output")
}
