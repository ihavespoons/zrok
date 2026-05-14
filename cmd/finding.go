package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ihavespoons/zrok/internal/agent"
	"github.com/ihavespoons/zrok/internal/exception"
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
  3. Flags (complete example — copy and edit values):

       zrok finding create \
         --title "SQL injection in user lookup" \
         --severity high \
         --confidence high \
         --cwe CWE-89 \
         --file src/api/users.py \
         --line 42 \
         --description "User-supplied id is concatenated into the SQL query without parameterisation." \
         --remediation "Use parameterised queries: cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))" \
         --created-by injection-agent \
         --tag injection:sql
       # NOTE: --cwe MUST include the "CWE-" prefix (e.g. CWE-89). Bare numbers like "89" are rejected.
       # NOTE: --file MUST be relative to the project root (e.g. src/api/users.py), NOT an absolute filesystem path.

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
			applyFlagOverrides(cmd, &f)
		default:
			data, err := os.ReadFile(yamlFile)
			if err != nil {
				exitError("failed to read file: %v", err)
			}
			if err := yaml.Unmarshal(data, &f); err != nil {
				exitError("failed to parse finding: %v", err)
			}
			applyFlagOverrides(cmd, &f)
		}

		// Reject invalid --created-by values. The CLI flag-mode path is
		// reserved for LLM agents (zrok sast uses store.Create directly,
		// bypassing the CLI). So we can apply an ALLOW-LIST against the
		// agent registry — every accepted value must be either:
		//   - a registered agent name (built-in or .zrok/agents override), or
		//   - a `human:<id>` / `bot:<id>` prefixed identity.
		//
		// History: started as a deny-list, but each OWASP eval iteration
		// surfaced a new evasion (opencode → opencode-security-agent →
		// opengrep). The allow-list is the only stable answer.
		if rejectReason := rejectInvalidCreatedBy(p, f.CreatedBy); rejectReason != "" {
			exitError("--created-by %q is invalid: %s. "+
				"Use the agent's name from its system prompt frontmatter "+
				"(e.g. injection-agent), or a prefixed identity like `human:%s`.",
				f.CreatedBy, rejectReason, os.Getenv("USER"))
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

		quiet, _ := cmd.Flags().GetBool("quiet")

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

		// Informational hint when other findings already exist at the same
		// file. Suppressed under --json (preserves clean structured output)
		// and --quiet. Never blocks creation.
		if !jsonOutput && !quiet {
			printSameFileHint(store, &f, os.Stderr)
		}
	},
}

// printSameFileHint writes an informational hint to w when one or more
// findings (other than the just-created one) exist at the same
// location.file. The hint is purely informational and never returns an
// error: failures listing findings are swallowed silently so creation
// stays a success-path operation.
func printSameFileHint(store *finding.Store, f *finding.Finding, w io.Writer) {
	if f == nil || f.Location.File == "" {
		return
	}
	result, err := store.List(&finding.FilterOptions{File: f.Location.File})
	if err != nil || result == nil {
		return
	}
	// Filter out the just-created finding by ID.
	var others []finding.Finding
	for _, existing := range result.Findings {
		if existing.ID == f.ID {
			continue
		}
		others = append(others, existing)
	}
	if len(others) == 0 {
		return
	}

	_, _ = fmt.Fprintf(w, "hint: %d existing finding(s) at this file (%s):\n",
		len(others), f.Location.File)
	const maxListed = 5
	listed := others
	truncated := 0
	if len(listed) > maxListed {
		truncated = len(listed) - maxListed
		listed = listed[:maxListed]
	}
	for _, ex := range listed {
		sev := string(ex.Severity)
		if sev == "" {
			sev = "?"
		}
		cwe := ex.CWE
		if cwe == "" {
			cwe = "no-CWE"
		}
		createdBy := ex.CreatedBy
		if createdBy == "" {
			createdBy = "unknown"
		}
		_, _ = fmt.Fprintf(w, "  %s [%s] %s (%s)\n", ex.ID, sev, cwe, createdBy)
	}
	if truncated > 0 {
		_, _ = fmt.Fprintf(w, "  ... and %d more\n", truncated)
	}
	// Use the first existing finding's ID in the example command.
	exampleID := others[0].ID
	_, _ = fmt.Fprintf(w, "Consider whether the new finding adds new information or should be a\n")
	_, _ = fmt.Fprintf(w, "--note on the existing finding via:\n")
	_, _ = fmt.Fprintf(w, "  zrok finding update %s --note \"<your perspective>\"\n", exampleID)
}

// rejectInvalidCreatedBy returns "" if the value is an acceptable
// --created-by, or a reason string if it should be rejected. The CLI
// flag-mode path is for LLM agents (the `zrok sast` programmatic path
// uses store.Create directly), so the bar is positive identification:
// the value must be a registered agent name or a `human:`/`bot:`
// prefixed identity. Tool names like `opengrep` are NOT acceptable here
// — they're reserved for the SAST programmatic flow, and accepting
// them via CLI lets LLM agents impersonate the SAST tool and trigger
// dedup collisions that drop their findings silently.
//
// History: this used to be a deny-list of known-bad values. Each OWASP
// eval iteration found a new evasion (opencode → opencode-security-
// agent → opengrep). Switched to allow-list to stop the arms race.
func rejectInvalidCreatedBy(p *project.Project, value string) string {
	normalised := strings.TrimSpace(value)
	if normalised == "" {
		return "value is empty"
	}

	// Prefixed identities: `human:alice`, `bot:dependabot`. Suffix must
	// be a non-empty plain identifier — no runtime names sneaking through
	// via `human:opencode` etc.
	for _, prefix := range []string{"human:", "bot:"} {
		if strings.HasPrefix(strings.ToLower(normalised), prefix) {
			suffix := strings.TrimSpace(strings.TrimPrefix(normalised, prefix))
			if suffix == "" {
				return "prefix `" + prefix + "` with no identity after it"
			}
			// Even prefixed forms reject runtime/provider names — a
			// human user shouldn't be filing as `human:opencode`.
			if isRuntimeOrProvider(strings.ToLower(suffix)) {
				return "after `" + prefix + "` prefix: `" + suffix + "` is a runtime/provider/model name, not a person"
			}
			return ""
		}
	}

	// `agent:foo` prefix is allowed as a synonym for `foo` — strip and
	// continue with the registry check.
	registryName := normalised
	if strings.HasPrefix(strings.ToLower(registryName), "agent:") {
		registryName = strings.TrimSpace(strings.TrimPrefix(registryName, "agent:"))
		if strings.HasPrefix(strings.ToLower(registryName), "agent:") {
			registryName = strings.TrimSpace(strings.TrimPrefix(registryName, "agent:"))
		}
		if registryName == "" {
			return "prefix `agent:` with no identity after it"
		}
	}

	// Registry check: must be a known agent (built-in or project-local
	// override in .zrok/agents/). The ConfigManager already walks both.
	mgr := agent.NewConfigManager(p, "")
	if _, err := mgr.Get(registryName); err == nil {
		return "" // accepted: registered agent
	}

	// Not in registry: reject. Surface a hint about what would be
	// accepted (registered name or human/bot prefix).
	return "not a registered agent (no `" + registryName + "` in built-in registry or `.zrok/agents/`)"
}

// isRuntimeOrProvider returns true when v matches a known LLM runtime,
// provider, or model family. Used to keep these strings from sneaking
// in via `human:` / `bot:` prefixes too.
func isRuntimeOrProvider(v string) bool {
	switch v {
	case "opencode", "claude", "claude-code", "claude_code",
		"anthropic", "openai", "openrouter",
		"qwen", "qwen3", "deepseek", "gpt", "gemma",
		"llm", "ai", "model":
		return true
	}
	for _, p := range []string{"opencode-", "claude-", "qwen3-", "deepseek-", "gpt-", "gemma-"} {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
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

// applyFlagOverrides applies CLI flag values onto a finding parsed from
// stdin/file YAML. Only flags that the user explicitly passed are applied
// (detected via cobra's Flags().Changed) — defaults do not silently overwrite
// YAML-supplied values. Currently this handles --created-by; other flags
// (--severity, --cwe, --confidence, --tag) are left to the YAML to keep the
// override surface small and well-defined. Document this precedence in the
// --created-by help text below.
func applyFlagOverrides(cmd *cobra.Command, f *finding.Finding) {
	if cmd.Flags().Changed("created-by") {
		if v, err := cmd.Flags().GetString("created-by"); err == nil {
			f.CreatedBy = v
		}
	}
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

// triagePlan is the on-disk shape produced by a triage agent and
// consumed by `zrok finding triage`. Captures status / severity /
// duplicate-of / note overrides in one shot so the dispatcher can apply
// them deterministically after the agent exits.
//
// Why we don't ask the agent to call `zrok finding update` per finding:
// LLM compliance with multi-call update flows is unreliable
// (validation-agent updated 0 of 82 findings across OWASP v5-v8). LLMs
// are much better at emitting structured output than at executing
// side-effecting tool calls in a loop. This file is that structured
// output; the apply step is deterministic Go code with no model
// involvement.
type triagePlan struct {
	Version   int              `json:"version"`
	Author    string           `json:"author"`
	Decisions []triageDecision `json:"decisions"`
}

type triageDecision struct {
	FindingID         string `json:"finding_id"`
	Status            string `json:"status"`             // open, confirmed, false_positive, duplicate
	Reason            string `json:"reason"`             // becomes the note body
	DuplicateOf       string `json:"duplicate_of,omitempty"`
	SeverityOverride  string `json:"severity_override,omitempty"`
	FixPriority       string `json:"fix_priority,omitempty"`
	Exploitability    string `json:"exploitability,omitempty"`
	ConfidenceOverride string `json:"confidence_override,omitempty"`
}

// findingTriageCmd applies a JSON triage plan to existing findings.
// Companion to `zrok finding update` (single-finding flags) — this is
// the batch path used by validation-agent / sast-triage-agent.
var findingTriageCmd = &cobra.Command{
	Use:   "triage",
	Short: "Apply a JSON triage plan to existing findings (batch updates)",
	Long: `Reads a JSON triage plan and applies status / severity / duplicate-of
updates to the named findings. Designed as the deterministic counterpart to
the LLM-as-updater pattern: a triage agent emits JSON, this command applies.

Plan file shape (` + "`zrok finding triage --plan path/to/plan.json`" + `):

  {
    "version": 1,
    "author": "validation-agent",
    "decisions": [
      {
        "finding_id": "FIND-001",
        "status": "false_positive",
        "reason": "ORM auto-parameterises; concat is on a static column name.",
        "duplicate_of": "FIND-002",     // optional, pairs with status:duplicate
        "severity_override": "medium",   // optional
        "fix_priority": "low",           // optional
        "exploitability": "unlikely",    // optional
        "confidence_override": "low"     // optional
      }
    ]
  }

Default plan path: .zrok/review/triage-plan.json (where the dispatcher
expects validation-agent and sast-triage-agent to write).

Each decision is applied independently:
  - Missing finding_id: counted as skipped, reported, no fatal error
  - Invalid status value: counted as errored, reported, run continues
  - Apply error (e.g. store I/O): counted as errored, reported

Exit code: 0 if any decisions applied successfully OR plan had zero
decisions; non-zero only if EVERY decision errored (suggests systemic
problem worth surfacing).`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		planPath, _ := cmd.Flags().GetString("plan")
		if planPath == "" {
			planPath = filepath.Join(p.GetZrokPath(), "review", "triage-plan.json")
		}
		authorOverride, _ := cmd.Flags().GetString("author")

		data, err := os.ReadFile(planPath)
		if err != nil {
			exitError("read triage plan %s: %v", planPath, err)
		}
		var plan triagePlan
		if err := json.Unmarshal(data, &plan); err != nil {
			exitError("parse triage plan: %v", err)
		}
		if plan.Version != 0 && plan.Version != 1 {
			exitError("unsupported triage plan version: %d (this build supports v1)", plan.Version)
		}

		author := plan.Author
		if authorOverride != "" {
			author = authorOverride
		}
		if author == "" {
			author = "triage"
		}

		store := finding.NewStore(p)
		var applied, skipped, errored int
		statusBreakdown := map[string]int{}

		for _, d := range plan.Decisions {
			if d.FindingID == "" {
				errored++
				fmt.Fprintf(os.Stderr, "  skip: decision has no finding_id\n")
				continue
			}
			f, err := store.Read(d.FindingID)
			if err != nil {
				skipped++
				fmt.Fprintf(os.Stderr, "  skip %s: %v\n", d.FindingID, err)
				continue
			}

			// Validate status (let blank pass — means caller only wanted
			// to tweak severity / notes / etc.).
			if d.Status != "" && !isValidStatus(d.Status) {
				errored++
				fmt.Fprintf(os.Stderr, "  error %s: invalid status %q (use open/confirmed/false_positive/fixed/duplicate)\n", d.FindingID, d.Status)
				continue
			}
			if d.Status != "" {
				f.Status = finding.Status(d.Status)
				statusBreakdown[d.Status]++
			}
			if d.DuplicateOf != "" {
				f.DuplicateOf = d.DuplicateOf
			}
			if d.SeverityOverride != "" {
				f.Severity = finding.Severity(d.SeverityOverride)
			}
			if d.FixPriority != "" {
				f.FixPriority = finding.FixPriority(d.FixPriority)
			}
			if d.Exploitability != "" {
				f.Exploitability = finding.Exploitability(d.Exploitability)
			}
			if d.ConfidenceOverride != "" {
				f.Confidence = finding.Confidence(d.ConfidenceOverride)
			}
			if d.Reason != "" {
				f.Notes = append(f.Notes, finding.FindingNote{
					Timestamp: time.Now(),
					Author:    author,
					Text:      d.Reason,
				})
			}
			if err := store.Update(f); err != nil {
				errored++
				fmt.Fprintf(os.Stderr, "  error %s: update failed: %v\n", d.FindingID, err)
				continue
			}
			applied++
		}

		if jsonOutput {
			_ = outputJSON(map[string]interface{}{
				"applied":          applied,
				"skipped":          skipped,
				"errored":          errored,
				"status_breakdown": statusBreakdown,
				"plan_path":        planPath,
				"author":           author,
			})
		} else {
			fmt.Printf("Triage applied: %d (skipped %d, errored %d)\n", applied, skipped, errored)
			for status, n := range statusBreakdown {
				fmt.Printf("  %s: %d\n", status, n)
			}
		}

		// Non-zero only when the plan had decisions but EVERY one
		// errored — that indicates a systemic problem (bad plan, store
		// broken, etc.) the caller should surface.
		if len(plan.Decisions) > 0 && applied == 0 && skipped == 0 {
			os.Exit(1)
		}
	},
}

// isValidStatus matches the validation logic in store.validate — kept
// here so the triage command can fail fast on a bad value without doing
// a Read+Update round trip.
func isValidStatus(s string) bool {
	switch finding.Status(s) {
	case finding.StatusOpen, finding.StatusConfirmed, finding.StatusFalsePositive,
		finding.StatusFixed, finding.StatusDuplicate:
		return true
	}
	return false
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
		if file, _ := cmd.Flags().GetString("file"); file != "" {
			opts.File = file
		}
		if createdBy, _ := cmd.Flags().GetString("created-by"); createdBy != "" {
			opts.CreatedBy = createdBy
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

		// Apply suppression filter from .zrok/exceptions.yaml. By default
		// suppressed findings are hidden; --include-suppressed surfaces them
		// with a SUPPRESSED tag so reviewers can see what was filtered.
		includeSuppressed, _ := cmd.Flags().GetBool("include-suppressed")
		excStore := exception.NewStore(p)
		suppressedFor := map[string]string{} // ID → reason
		filtered := result.Findings[:0]
		var suppressedCount int
		for _, f := range result.Findings {
			match, _ := excStore.Match(f)
			if match != nil {
				suppressedCount++
				suppressedFor[f.ID] = match.Reason
				if !includeSuppressed {
					continue
				}
			}
			filtered = append(filtered, f)
		}
		result.Findings = filtered
		result.Total = len(result.Findings)

		if jsonOutput {
			payload := map[string]any{
				"findings":          result.Findings,
				"total":             result.Total,
				"suppressed_count":  suppressedCount,
			}
			if includeSuppressed {
				payload["suppressed_by"] = suppressedFor
			}
			if err := outputJSON(payload); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			if result.Total == 0 {
				if suppressedCount > 0 {
					fmt.Printf("No findings (%d suppressed by exception; pass --include-suppressed to see)\n", suppressedCount)
				} else {
					fmt.Println("No findings")
				}
				return
			}

			for _, f := range result.Findings {
				badge := getSeverityBadge(f.Severity)
				suppressTag := ""
				if reason, ok := suppressedFor[f.ID]; ok {
					suppressTag = " [SUPPRESSED: " + reason + "]"
				}
				fmt.Printf("%s [%s] %s - %s%s\n", badge, f.ID, f.Title, f.Status, suppressTag)
				fmt.Printf("   Location: %s:%d\n", f.Location.File, f.Location.LineStart)
			}
			fmt.Printf("\nTotal: %d findings", result.Total)
			if suppressedCount > 0 {
				fmt.Printf(" (%d suppressed)", suppressedCount)
			}
			fmt.Println()
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

		// Surface active suppression so reviewers see immediately when a
		// finding has been dismissed by an exception.
		excStore := exception.NewStore(p)
		suppression, _ := excStore.Match(*f)

		if jsonOutput {
			payload := map[string]any{"finding": f}
			if suppression != nil {
				payload["suppressed_by"] = map[string]any{
					"exception_id": suppression.ID,
					"reason":       suppression.Reason,
					"expires":      suppression.Expires,
					"approved_by":  suppression.ApprovedBy,
				}
			}
			if err := outputJSON(payload); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Printf("%s %s\n", getSeverityBadge(f.Severity), f.Title)
			if suppression != nil {
				fmt.Printf("SUPPRESSED by %s — %s (expires %s)\n",
					suppression.ID, suppression.Reason, suppression.Expires.Format("2006-01-02"))
			}
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
	findingCmd.AddCommand(findingTriageCmd)
	findingTriageCmd.Flags().String("plan", "", "Path to triage plan JSON (default: .zrok/review/triage-plan.json)")
	findingTriageCmd.Flags().String("author", "", "Override the plan's `author` field for note attribution")
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
	findingCreateCmd.Flags().String("created-by", "", "Identifier of agent/user creating the finding. In stdin/-f YAML modes, this CLI flag overrides any created_by: in the YAML when explicitly passed.")
	findingCreateCmd.Flags().Bool("strict", false, "Reject findings whose CWE is outside the --created-by agent's owns_cwes")
	findingCreateCmd.Flags().Bool("quiet", false, "Suppress the informational same-file hint on stderr")

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
	findingListCmd.Flags().String("file", "", "Filter by location file (exact match against finding's location.file)")
	findingListCmd.Flags().String("diff", "", "Filter to findings in files changed since base ref (e.g., main)")
	findingListCmd.Flags().String("created-by", "", "Filter by creator (e.g., opengrep, security-agent). Matches finding.created_by exactly.")
	findingListCmd.Flags().Bool("include-suppressed", false, "Show findings that would be filtered by .zrok/exceptions.yaml")

	findingExportCmd.Flags().StringP("format", "f", "json", "Export format (sarif, json, md, html, csv)")
	findingExportCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	findingExportCmd.Flags().String("diff", "", "Filter to findings in files changed since base ref (e.g., main)")
}
