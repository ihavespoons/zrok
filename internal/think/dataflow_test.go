package think

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ihavespoons/zrok/internal/project"
)

// writeTempProject creates a minimal project rooted in t.TempDir() and
// returns the project plus the root path. The project has .zrok/ scaffolding
// but no memories or findings unless added by the caller.
func writeTempProject(t *testing.T) (*project.Project, string) {
	t.Helper()
	root := t.TempDir()
	p, err := project.Initialize(root)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	return p, root
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestAnalyzeDataflow_UnguardedChain(t *testing.T) {
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `
def view():
    param = request.form.get("x")
    sql = f"SELECT * FROM u WHERE n = '{param}'"
    cur.execute(sql)
`)
	r, err := AnalyzeDataflow(p, DataflowOptions{
		Source: `request\.form\.get`,
		Sink:   `cur\.execute`,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.Chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(r.Chains))
	}
	c := r.Chains[0]
	if c.Verdict != "unguarded" {
		t.Errorf("want verdict unguarded, got %s", c.Verdict)
	}
	if len(c.Guards) != 0 {
		t.Errorf("want no guards, got %d", len(c.Guards))
	}
	if c.SourceLine == 0 || c.SinkLine == 0 || c.SinkLine <= c.SourceLine {
		t.Errorf("source/sink lines incorrect: src=%d sink=%d", c.SourceLine, c.SinkLine)
	}
}

func TestAnalyzeDataflow_GuardedChain(t *testing.T) {
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `
def view():
    param = request.form.get("x")
    safe = bleach.clean(param)
    cur.execute("SELECT * FROM u WHERE n = ?", (safe,))
`)
	r, err := AnalyzeDataflow(p, DataflowOptions{
		Source: `request\.form\.get`,
		Sink:   `cur\.execute`,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.Chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(r.Chains))
	}
	c := r.Chains[0]
	if len(c.Guards) == 0 {
		t.Errorf("want guards, got 0")
	}
	if c.Verdict != "guarded" && c.Verdict != "guard-uncertain" {
		t.Errorf("want guarded verdict, got %s", c.Verdict)
	}
}

func TestAnalyzeDataflow_NoMatch(t *testing.T) {
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", "print('hello')\n")
	r, err := AnalyzeDataflow(p, DataflowOptions{
		Source: `request\.form\.get`,
		Sink:   `cur\.execute`,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.Chains) != 0 {
		t.Errorf("want 0 chains, got %d", len(r.Chains))
	}
}

func TestAnalyzeDataflow_RequiresPatterns(t *testing.T) {
	p, _ := writeTempProject(t)
	_, err := AnalyzeDataflow(p, DataflowOptions{})
	if err == nil {
		t.Errorf("want error when source/sink missing")
	}
}

func TestGuardRegex_DoesNotFalseHitStringLiteral(t *testing.T) {
	// 'safe!' is a string literal containing the word safe; it must NOT
	// match the guard pattern.
	if guardPatterns.MatchString(`bar = 'safe!'`) {
		t.Errorf("guard regex falsely matched a string literal 'safe!'")
	}
	// But a real call should match.
	if !guardPatterns.MatchString(`x = bleach.clean(y)`) {
		t.Errorf("guard regex missed bleach.clean(...) call")
	}
	if !guardPatterns.MatchString(`safe = html.escape(y)`) {
		t.Errorf("guard regex missed html.escape(...) call")
	}
}

func TestExtractAfter(t *testing.T) {
	desc := strings.Join([]string{
		"Some context.",
		"SOURCE: request.form.get(\"x\") at app.py:10",
		"SINK: cur.execute(sql) at app.py:20",
	}, "\n")
	if got := extractAfter(desc, "SOURCE:"); got != "request.form.get" {
		t.Errorf("extractAfter SOURCE: got %q", got)
	}
	if got := extractAfter(desc, "SINK:"); got != "cur.execute" {
		t.Errorf("extractAfter SINK: got %q", got)
	}
}
