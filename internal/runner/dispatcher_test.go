package runner

import (
	"context"
	"os"
	"path/filepath"
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
