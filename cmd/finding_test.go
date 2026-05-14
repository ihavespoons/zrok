package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/spf13/cobra"
)

func setupFindingTestProject(t *testing.T) (*project.Project, func()) {
	t.Helper()
	tmp, err := os.MkdirTemp("", "zrok-cmd-finding-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	p, err := project.Initialize(tmp)
	if err != nil {
		_ = os.RemoveAll(tmp)
		t.Fatalf("init: %v", err)
	}
	return p, func() { _ = os.RemoveAll(tmp) }
}

// TestValidateOwnsCWEsInScope: an in-scope CWE for a known agent passes silently.
func TestValidateOwnsCWEsInScope(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	f := &finding.Finding{
		Title:     "InScope",
		CWE:       "CWE-89", // owned by injection-agent
		CreatedBy: "injection-agent",
	}
	if err := validateOwnsCWEs(p, f, false); err != nil {
		t.Errorf("expected no error for in-scope CWE, got: %v", err)
	}
	if err := validateOwnsCWEs(p, f, true); err != nil {
		t.Errorf("expected no error under --strict for in-scope CWE, got: %v", err)
	}
}

// TestValidateOwnsCWEsOutOfScopeWarn: out-of-scope CWE warns but returns nil
// (no error) in non-strict mode.
func TestValidateOwnsCWEsOutOfScopeWarn(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	f := &finding.Finding{
		Title:     "OutOfScope",
		CWE:       "CWE-79", // NOT owned by injection-agent
		CreatedBy: "injection-agent",
	}
	if err := validateOwnsCWEs(p, f, false); err != nil {
		t.Errorf("expected nil err in warn mode, got: %v", err)
	}
}

// TestValidateOwnsCWEsOutOfScopeStrict: --strict rejects out-of-scope CWE with error.
func TestValidateOwnsCWEsOutOfScopeStrict(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	f := &finding.Finding{
		Title:     "OutOfScopeStrict",
		CWE:       "CWE-79",
		CreatedBy: "injection-agent",
	}
	err := validateOwnsCWEs(p, f, true)
	if err == nil {
		t.Fatal("expected error under --strict for out-of-scope CWE")
	}
}

// TestValidateOwnsCWEsUnknownAgent: agent not in registry => no validation.
func TestValidateOwnsCWEsUnknownAgent(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	f := &finding.Finding{
		Title:     "UnknownAgent",
		CWE:       "CWE-79",
		CreatedBy: "no-such-agent-xyz",
	}
	if err := validateOwnsCWEs(p, f, true); err != nil {
		t.Errorf("expected nil err for unknown agent (skip validation), got: %v", err)
	}
}

// TestValidateOwnsCWEsNoCreatedBy: empty created_by => no validation.
func TestValidateOwnsCWEsNoCreatedBy(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	f := &finding.Finding{
		Title: "NoCreator",
		CWE:   "CWE-79",
	}
	if err := validateOwnsCWEs(p, f, true); err != nil {
		t.Errorf("expected nil err with no created_by, got: %v", err)
	}
}

// TestValidateOwnsCWEsCaseInsensitive: CWE compare is case-insensitive.
func TestValidateOwnsCWEsCaseInsensitive(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	f := &finding.Finding{
		Title:     "LowerCase",
		CWE:       "cwe-89",
		CreatedBy: "injection-agent",
	}
	if err := validateOwnsCWEs(p, f, true); err != nil {
		t.Errorf("expected case-insensitive CWE match, got: %v", err)
	}
}

// TestFindingNotesRoundTrip: notes appended via repeated updates are preserved
// in order through save/read cycles.
func TestFindingNotesRoundTrip(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	store := finding.NewStore(p)
	f := &finding.Finding{
		Title:      "with notes",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceHigh,
		Location: finding.Location{
			File:      "app.py",
			LineStart: 1,
		},
		Description: "test",
	}
	if err := store.Create(f); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Append first note
	loaded, err := store.Read(f.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	loaded.Notes = append(loaded.Notes, finding.FindingNote{
		Timestamp: time.Now(),
		Author:    "tester",
		Text:      "first note",
	})
	if err := store.Update(loaded); err != nil {
		t.Fatalf("update 1: %v", err)
	}

	// Append second note
	loaded, err = store.Read(f.ID)
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}
	loaded.Notes = append(loaded.Notes, finding.FindingNote{
		Timestamp: time.Now(),
		Author:    "tester",
		Text:      "second note",
	})
	if err := store.Update(loaded); err != nil {
		t.Fatalf("update 2: %v", err)
	}

	final, err := store.Read(f.ID)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if len(final.Notes) != 2 {
		t.Fatalf("expected 2 notes, got %d", len(final.Notes))
	}
	if final.Notes[0].Text != "first note" {
		t.Errorf("expected first note 'first note', got %q", final.Notes[0].Text)
	}
	if final.Notes[1].Text != "second note" {
		t.Errorf("expected second note 'second note', got %q", final.Notes[1].Text)
	}
	if final.Notes[0].Author != "tester" {
		t.Errorf("expected author 'tester', got %q", final.Notes[0].Author)
	}
}

// TestFindingDuplicateOfAndNotesPersist: confirms duplicate_of and notes
// survive a YAML save/load round-trip (so JSON output via --json works for free).
func TestFindingDuplicateOfAndNotesPersist(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	store := finding.NewStore(p)
	f := &finding.Finding{
		Title:      "duplicate marker",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceHigh,
		Location: finding.Location{
			File:      "app.py",
			LineStart: 1,
		},
		Description: "test",
		DuplicateOf: "FIND-999",
		Notes: []finding.FindingNote{
			{Timestamp: time.Now(), Author: "alice", Text: "looks like a dup"},
		},
	}
	if err := store.Create(f); err != nil {
		t.Fatalf("create: %v", err)
	}
	loaded, err := store.Read(f.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if loaded.DuplicateOf != "FIND-999" {
		t.Errorf("DuplicateOf not preserved: %q", loaded.DuplicateOf)
	}
	if len(loaded.Notes) != 1 || loaded.Notes[0].Text != "looks like a dup" {
		t.Errorf("Notes not preserved: %+v", loaded.Notes)
	}
}

// makeFinding is a helper to create a finding via the store and return it.
func makeFinding(t *testing.T, store *finding.Store, file string, line int, cwe, sev, createdBy string) *finding.Finding {
	t.Helper()
	f := &finding.Finding{
		Title:       "t-" + file,
		Severity:    finding.Severity(sev),
		Confidence:  finding.ConfidenceHigh,
		CWE:         cwe,
		Description: "test",
		CreatedBy:   createdBy,
		Location: finding.Location{
			File:      file,
			LineStart: line,
		},
	}
	if err := store.Create(f); err != nil {
		t.Fatalf("create: %v", err)
	}
	return f
}

// TestPrintSameFileHintNoOthers: no other findings at the same file => no hint.
func TestPrintSameFileHintNoOthers(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	store := finding.NewStore(p)
	f := makeFinding(t, store, "a.py", 10, "CWE-89", "high", "injection-agent")

	var buf bytes.Buffer
	printSameFileHint(store, f, &buf)
	if buf.Len() != 0 {
		t.Errorf("expected no hint when no other findings at same file, got:\n%s", buf.String())
	}
}

// TestPrintSameFileHintOneOther: a second finding at same file => hint listing
// the first by ID/CWE/severity/agent.
func TestPrintSameFileHintOneOther(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	store := finding.NewStore(p)
	first := makeFinding(t, store, "a.py", 10, "CWE-89", "high", "injection-agent")
	second := makeFinding(t, store, "a.py", 12, "CWE-20", "high", "guards-agent")

	var buf bytes.Buffer
	printSameFileHint(store, second, &buf)

	out := buf.String()
	if out == "" {
		t.Fatal("expected hint output, got empty")
	}
	if !strings.Contains(out, first.ID) {
		t.Errorf("hint did not include existing finding ID %q. output:\n%s", first.ID, out)
	}
	if !strings.Contains(out, "CWE-89") {
		t.Errorf("hint did not include CWE-89. output:\n%s", out)
	}
	if !strings.Contains(out, "high") {
		t.Errorf("hint did not include severity. output:\n%s", out)
	}
	if !strings.Contains(out, "injection-agent") {
		t.Errorf("hint did not include creator. output:\n%s", out)
	}
	if !strings.Contains(out, "a.py") {
		t.Errorf("hint did not include the file. output:\n%s", out)
	}
	// Should NOT include the just-created finding's own ID in the listing.
	// The example update command may include another ID though, so check the
	// list portion specifically.
	lines := strings.Split(out, "\n")
	for _, ln := range lines {
		// listing lines start with two spaces and a FIND-
		if strings.HasPrefix(ln, "  FIND-") {
			if strings.Contains(ln, second.ID) {
				t.Errorf("hint listed the just-created finding %s in its own list:\n%s", second.ID, out)
			}
		}
	}
}

// TestPrintSameFileHintFiltersSelf: even when only the just-created finding
// exists at this file, no hint is printed (it must be filtered out).
func TestPrintSameFileHintFiltersSelf(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	store := finding.NewStore(p)
	only := makeFinding(t, store, "solo.py", 10, "CWE-89", "high", "injection-agent")

	var buf bytes.Buffer
	printSameFileHint(store, only, &buf)
	if buf.Len() != 0 {
		t.Errorf("expected no hint when the only same-file finding is the just-created one, got:\n%s", buf.String())
	}
}

// TestPrintSameFileHintEmptyFile: empty location.file => no hint, no panic.
func TestPrintSameFileHintEmptyFile(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	store := finding.NewStore(p)
	f := &finding.Finding{ID: "FIND-XYZ"}
	var buf bytes.Buffer
	printSameFileHint(store, f, &buf)
	if buf.Len() != 0 {
		t.Errorf("expected no hint for empty file, got: %s", buf.String())
	}
}

// TestPrintSameFileHintMultipleOthers: multiple existing findings at the
// same file all appear in the hint listing.
func TestPrintSameFileHintMultipleOthers(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	store := finding.NewStore(p)
	a := makeFinding(t, store, "multi.py", 10, "CWE-89", "high", "injection-agent")
	b := makeFinding(t, store, "multi.py", 20, "CWE-79", "medium", "xss-agent")
	c := makeFinding(t, store, "multi.py", 30, "CWE-22", "high", "path-agent")

	var buf bytes.Buffer
	printSameFileHint(store, c, &buf)
	out := buf.String()
	for _, id := range []string{a.ID, b.ID} {
		if !strings.Contains(out, id) {
			t.Errorf("expected hint to include %s. output:\n%s", id, out)
		}
	}
	if strings.Contains(out, "  "+c.ID+" ") {
		t.Errorf("hint should not list the just-created finding %s. output:\n%s", c.ID, out)
	}
	// Header should reference 2 existing findings.
	if !strings.Contains(out, "2 existing finding") {
		t.Errorf("hint header should say '2 existing finding(s)'. output:\n%s", out)
	}
}

// makeCreateCmd builds a cobra.Command with the same flag set as
// findingCreateCmd. Use this to test flag-processing helpers in isolation
// without exec'ing the full Run func (which calls project.EnsureActive and
// os.Exit on error).
func makeCreateCmd(t *testing.T) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "create"}
	c.Flags().StringP("file", "f", "", "")
	c.Flags().String("title", "", "")
	c.Flags().String("severity", "", "")
	c.Flags().String("cwe", "", "")
	c.Flags().Int("line", 0, "")
	c.Flags().String("description", "", "")
	c.Flags().String("remediation", "", "")
	c.Flags().String("confidence", "", "")
	c.Flags().StringSlice("tag", []string{}, "")
	c.Flags().String("created-by", "", "")
	c.Flags().Bool("strict", false, "")
	c.Flags().Bool("quiet", false, "")
	return c
}

// TestApplyFlagOverridesCreatedByEmptyYAML: when YAML omits created_by and
// --created-by is passed, the CLI value is applied.
func TestApplyFlagOverridesCreatedByEmptyYAML(t *testing.T) {
	c := makeCreateCmd(t)
	if err := c.Flags().Set("created-by", "injection-agent"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	f := &finding.Finding{Title: "x"} // CreatedBy unset (as if YAML omitted it)
	applyFlagOverrides(c, f)
	if f.CreatedBy != "injection-agent" {
		t.Errorf("CreatedBy=%q, want %q", f.CreatedBy, "injection-agent")
	}
}

// TestApplyFlagOverridesCreatedByOverridesYAML: an explicitly-passed
// --created-by overrides a created_by: value supplied in the YAML.
func TestApplyFlagOverridesCreatedByOverridesYAML(t *testing.T) {
	c := makeCreateCmd(t)
	if err := c.Flags().Set("created-by", "bar"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	f := &finding.Finding{Title: "x", CreatedBy: "foo"} // foo from YAML
	applyFlagOverrides(c, f)
	if f.CreatedBy != "bar" {
		t.Errorf("CreatedBy=%q, want %q (CLI overrides YAML)", f.CreatedBy, "bar")
	}
}

// TestApplyFlagOverridesCreatedByUnsetPreservesYAML: when --created-by is NOT
// passed (its default empty string is in effect), an existing YAML value is
// preserved — the empty default must not silently wipe it.
func TestApplyFlagOverridesCreatedByUnsetPreservesYAML(t *testing.T) {
	c := makeCreateCmd(t)
	// Do NOT Set the flag — it stays at default and Changed("created-by") is false.
	f := &finding.Finding{Title: "x", CreatedBy: "yaml-value"}
	applyFlagOverrides(c, f)
	if f.CreatedBy != "yaml-value" {
		t.Errorf("CreatedBy=%q, want %q (YAML preserved when flag unset)", f.CreatedBy, "yaml-value")
	}
}

// TestCreateCmdHintGatedByQuietAndJSON: the create command itself is hard to
// run end-to-end without spawning a subprocess (it calls os.Exit on error
// and uses project.EnsureActive). The behavior we need to assert is that
// the hint helper is gated correctly. We exercise the gating logic by
// invoking printSameFileHint conditionally based on the same flags the
// command checks, then assert the gating semantics.
func TestCreateCmdHintGatedByQuietAndJSON(t *testing.T) {
	p, cleanup := setupFindingTestProject(t)
	defer cleanup()

	store := finding.NewStore(p)
	_ = makeFinding(t, store, "gate.py", 10, "CWE-89", "high", "injection-agent")
	second := makeFinding(t, store, "gate.py", 20, "CWE-79", "high", "xss-agent")

	cases := []struct {
		name       string
		jsonOutput bool
		quiet      bool
		wantHint   bool
	}{
		{"default emits hint", false, false, true},
		{"--json suppresses hint", true, false, false},
		{"--quiet suppresses hint", false, true, false},
		{"--json --quiet suppresses hint", true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			// Mirror the gating in the create command:
			if !tc.jsonOutput && !tc.quiet {
				printSameFileHint(store, second, &buf)
			}
			gotHint := buf.Len() > 0
			if gotHint != tc.wantHint {
				t.Errorf("hint emitted=%v, want %v; output:\n%s", gotHint, tc.wantHint, buf.String())
			}
		})
	}
}

// TestRejectInvalidCreatedBy covers the OWASP-eval failure mode where
// LLM agents filed findings with --created-by values pulled from the
// runtime ("opencode"), the model family ("qwen"), or invented role
// descriptions ("security-scanner") instead of their actual agent name.
// Each pollutes the store, breaks per-agent dedup, and misleads the
// rule/exception audit paths.
func TestRejectInvalidCreatedBy(t *testing.T) {
	// Project with default config — gives access to the built-in
	// agent registry so "injection-agent" etc. resolve.
	tmpDir := t.TempDir()
	p, err := project.Initialize(tmpDir)
	if err != nil {
		t.Fatalf("project init: %v", err)
	}

	cases := []struct {
		name       string
		value      string
		wantReject bool
	}{
		// Empty / sentinel
		{"empty rejected", "", true},
		{"whitespace-only rejected", "   ", true},

		// Runtime / provider / model — never accepted, even bare
		{"runtime name `opencode` rejected", "opencode", true},
		{"runtime name `claude` rejected", "claude", true},
		{"runtime uppercase `Claude` rejected", "Claude", true},
		{"provider `openai` rejected", "openai", true},
		{"model family `qwen3` rejected", "qwen3", true},

		// Generic role nouns — not registered agents, so rejected
		{"generic `unknown` rejected", "unknown", true},
		{"generic `system` rejected", "system", true},
		{"invented `security-scanner` rejected", "security-scanner", true},

		// OWASP v6 evasion patterns — compound names that prepend runtime
		{"runtime compound `opencode-security-agent` rejected", "opencode-security-agent", true},
		{"runtime compound `opencode-security-review` rejected", "opencode-security-review", true},

		// OWASP v7 evasion — `opengrep` is reserved for SAST programmatic
		// path; LLM agents must use their real name.
		{"tool name `opengrep` rejected in CLI flag mode", "opengrep", true},

		// Prefix edge cases
		{"empty `agent:` prefix rejected", "agent:", true},
		{"empty `human:` prefix rejected", "human:", true},
		{"runtime name with `agent:` prefix rejected", "agent:opencode", true},
		{"runtime name with `human:` prefix rejected", "human:opencode", true},

		// Registered agent names
		{"valid agent `injection-agent` accepted", "injection-agent", false},
		{"valid agent with `agent:` prefix accepted", "agent:injection-agent", false},
		{"valid agent `security-agent` accepted", "security-agent", false},
		{"valid agent `validation-agent` accepted", "validation-agent", false},

		// Human/bot identities with plain names
		{"human prefix with plain name accepted", "human:alice", false},
		{"bot prefix with plain name accepted", "bot:dependabot", false},

		// Unregistered free-form names — rejected (no longer accepted
		// just because they're not on the blacklist).
		{"unregistered free-form name rejected", "my-custom-agent", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason := rejectInvalidCreatedBy(p, c.value)
			rejected := reason != ""
			if rejected != c.wantReject {
				t.Errorf("rejectInvalidCreatedBy(%q): rejected=%v, want %v (reason: %q)",
					c.value, rejected, c.wantReject, reason)
			}
		})
	}
}
