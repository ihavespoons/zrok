package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONHasFindings(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty body", "", false},
		{"empty object", "{}", false},
		{"explicit total zero", `{"total": 0, "findings": null}`, false},
		{"total positive", `{"total": 3, "findings": [{}]}`, true},
		{"findings array non-empty without total", `{"findings": [{"id":"FIND-001"}]}`, true},
		{"findings null", `{"findings": null, "suppressed_count": 0}`, false},
		{"malformed json", `not json`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := jsonHasFindings([]byte(c.in)); got != c.want {
				t.Errorf("jsonHasFindings(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestEvaluateGateEmptyVsNonEmpty(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	// Empty result: gate command returns valid JSON with total=0
	ok, err := evaluateGate(ctx, `echo '{"total":0,"findings":null}'`, tmp)
	if err != nil {
		t.Fatalf("evaluateGate(empty): %v", err)
	}
	if ok {
		t.Errorf("expected ok=false for empty gate result, got true")
	}

	// Non-empty: total > 0
	ok, err = evaluateGate(ctx, `echo '{"total":2,"findings":[{},{}]}'`, tmp)
	if err != nil {
		t.Fatalf("evaluateGate(non-empty): %v", err)
	}
	if !ok {
		t.Errorf("expected ok=true for non-empty gate result, got false")
	}
}

func TestEvaluateGateSurfacesErrors(t *testing.T) {
	// Non-zero exit from the gate command is propagated as an error.
	// This is intentional — a failing gate likely means zrok isn't on
	// PATH or the project isn't initialized, and silently skipping the
	// phase would hide that.
	ctx := context.Background()
	_, err := evaluateGate(ctx, `false`, t.TempDir())
	if err == nil {
		t.Fatal("expected error from failing gate command, got nil")
	}
}

func TestDynamicFanoutItems(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	cases := []struct {
		name  string
		shell string
		want  []string
	}{
		{
			"two findings",
			`echo '{"findings":[{"id":"FIND-001"},{"id":"FIND-002"}]}'`,
			[]string{"FIND-001", "FIND-002"},
		},
		{
			"no findings (null)",
			`echo '{"findings":null,"total":0}'`,
			[]string{},
		},
		{
			"empty findings array",
			`echo '{"findings":[],"total":0}'`,
			[]string{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := dynamicFanoutItems(ctx, c.shell, tmp)
			if err != nil {
				t.Fatalf("dynamicFanoutItems: %v", err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("item %d: got %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestLookupRunner(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantName  string
		wantError bool
	}{
		{"opencode", "opencode", "opencode", false},
		{"claude", "claude", "claude", false},
		{"unknown", "foo", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := LookupRunner(c.input)
			if c.wantError {
				if err == nil {
					t.Errorf("expected error for %q, got nil", c.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("LookupRunner(%q): %v", c.input, err)
			}
			if r.Name() != c.wantName {
				t.Errorf("runner name: got %q, want %q", r.Name(), c.wantName)
			}
		})
	}
}

func TestClassifyFailure(t *testing.T) {
	cases := []struct {
		name      string
		exitCode  int
		log       string
		wantCat   failureCategory
		wantInLbl string // substring expected in the returned reason
	}{
		{"exit 0 is success", 0, "", failureNone, ""},
		{"exit 0 with parse error in log still success", 0, "yaml: unmarshal errors", failureNone, ""},
		{"SchemaError → recoverable", 1, "SchemaError(Missing key at [\"description\"])", failureRecoverable, "SchemaError"},
		{"yaml unmarshal → recoverable", 1, "Error: yaml: unmarshal errors:\n  line 3: cannot unmarshal", failureRecoverable, "yaml: unmarshal errors"},
		// "failed to parse" matches first (it's earlier in the patterns list);
		// either reason is acceptable — both correctly classify as recoverable.
		{"finding create failed → recoverable", 2, "zrok finding create: failed to parse YAML", failureRecoverable, "failed to parse"},
		{"missing key gemma-style → recoverable", 1, "Missing key at [\"prompt\"]", failureRecoverable, "Missing key at ["},
		{"quota → hard", 1, "Error: rate limit exceeded", failureHard, "rate limit"},
		{"429 → hard", 1, "HTTP 429 Too Many Requests", failureHard, ""}, // matches either word boundary or "too many requests"
		{"overloaded → hard", 1, "model is overloaded", failureHard, "overloaded"},
		{"auth fail → hard", 1, "401 unauthorized: invalid api key", failureHard, ""},
		{"hard wins when both present", 1, "rate limit exceeded\nyaml: unmarshal errors", failureHard, "rate limit"},
		{"unknown failure → hard (no retry on unknown)", 1, "something weird happened", failureHard, "exit=1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cat, reason := classifyFailure(c.exitCode, []byte(c.log))
			if cat != c.wantCat {
				t.Errorf("category: got %v, want %v (reason: %q)", cat, c.wantCat, reason)
			}
			if c.wantInLbl != "" && !strings.Contains(strings.ToLower(reason), strings.ToLower(c.wantInLbl)) {
				t.Errorf("reason missing %q: got %q", c.wantInLbl, reason)
			}
		})
	}
}

func TestCorrectiveUserTurnContainsScaffolding(t *testing.T) {
	turn := correctiveUserTurn("original task", "SchemaError", "injection-agent")
	// Must mention what went wrong so the model can correct.
	if !strings.Contains(turn, "SchemaError") {
		t.Error("corrective turn missing failure reason")
	}
	// Must remind the model of the Task tool's required fields — this
	// was the specific Gemma failure mode the retry was designed for.
	if !strings.Contains(turn, "description") || !strings.Contains(turn, "prompt") {
		t.Error("corrective turn missing Task tool field reminder")
	}
	// Must remind about zrok finding create schema (CWE- prefix etc.).
	if !strings.Contains(turn, "CWE-") {
		t.Error("corrective turn missing CWE- prefix reminder")
	}
	// Must echo the original task so the agent still knows what to do.
	if !strings.Contains(turn, "original task") {
		t.Error("corrective turn dropped the original task")
	}
	// Must pin --created-by to the agent's actual name to prevent the
	// "model picks 'opencode' because that's the runtime" failure mode
	// observed in OWASP eval runs.
	if !strings.Contains(turn, "injection-agent") {
		t.Error("corrective turn must inject the agent's actual name for --created-by")
	}
}

func TestCorrectiveUserTurnEmptyAgentFallback(t *testing.T) {
	// When agentName is empty (caller doesn't have it in scope), the
	// corrective turn should still warn the model NOT to use the
	// runtime name as the creator.
	turn := correctiveUserTurn("task", "SchemaError", "")
	if !strings.Contains(turn, "frontmatter") {
		t.Error("expected hint pointing the model at its system-prompt frontmatter for --created-by")
	}
}

func TestRunnerInvocationShape(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	logFile, err := os.Create(filepath.Join(tmp, "log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	cases := []struct {
		runner Runner
		path   string // expected binary basename
		args   []string
	}{
		{NewOpenCodeRunner(), "opencode", []string{"run", "--agent", "injection-agent", "--model", "gpt-4o", "do work"}},
		{NewClaudeRunner(), "claude", []string{"-p", "--agent", "injection-agent", "--model", "sonnet", "do work"}},
	}
	for _, c := range cases {
		t.Run(c.runner.Name(), func(t *testing.T) {
			model := "gpt-4o"
			if c.runner.Name() == "claude" {
				model = "sonnet"
			}
			cmd := c.runner.AgentInvocation(ctx, tmp, "injection-agent", model, "do work", logFile)
			if filepath.Base(cmd.Path) != c.path && cmd.Path != c.path {
				// On macOS PATH lookup, cmd.Path may be the absolute resolved path.
				// Accept either form as long as the basename matches.
				if filepath.Base(cmd.Path) != c.path {
					t.Errorf("binary path: got %q, want basename %q", cmd.Path, c.path)
				}
			}
			if len(cmd.Args) != len(c.args)+1 {
				t.Errorf("arg count: got %v, want %d (with argv[0])", cmd.Args, len(c.args)+1)
			}
			for i, want := range c.args {
				got := cmd.Args[i+1]
				if got != want {
					t.Errorf("arg %d: got %q, want %q", i, got, want)
				}
			}
			if cmd.Dir != tmp {
				t.Errorf("workdir: got %q, want %q", cmd.Dir, tmp)
			}
		})
	}
}
