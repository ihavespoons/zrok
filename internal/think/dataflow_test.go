package think

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ihavespoons/zrok/internal/project"
)

// regexpCompileCaseInsensitive compiles a regex with the (?i) flag, mirroring
// what AnalyzeDataflow does at runtime so tests check against the same
// matching behavior.
func regexpCompileCaseInsensitive(pat string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + pat)
}

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

// ---- C1: sink classes ----

func TestSinkClasses_DefaultCoversDeserialization(t *testing.T) {
	// The default sink pattern (no class supplied) must match pickle.loads,
	// yaml.load (but not yaml.safe_load), jsonpickle.decode, xml.etree
	// parsers, ldap search, flask.redirect, render_template_string.
	cases := map[string]bool{
		"data = pickle.loads(payload)":                 true,
		"data = yaml.load(payload)":                    true,
		"data = yaml.safe_load(payload)":               false,
		"data = jsonpickle.decode(payload)":            true,
		"data = jsonpickle.loads(payload)":             true,
		"tree = etree.fromstring(payload)":             true,
		"tree = xml.etree.ElementTree.parse(payload)":  true,
		"tree = lxml.etree.parse(payload)":             true,
		"return flask.redirect(payload)":               true,
		"out = render_template_string(payload)":        true,
		"conn.simple_bind_s(user, password)":           true,
		"results = ldap3.search(filter)":               true,
		"print('nothing relevant here')":               false,
	}
	pat := DefaultSinkPattern()
	if pat == "" {
		t.Fatal("default sink pattern is empty")
	}
	re, err := regexpCompileCaseInsensitive(pat)
	if err != nil {
		t.Fatalf("compile default sink: %v", err)
	}
	for line, want := range cases {
		got := re.MatchString(line)
		if got != want {
			t.Errorf("default sink pattern: line=%q want=%v got=%v", line, want, got)
		}
	}
}

func TestSinkClasses_ClassNarrowing(t *testing.T) {
	pat, unknown := BuildSinkPatternFromClasses([]string{"deserialization", "xxe"})
	if len(unknown) != 0 {
		t.Fatalf("unexpected unknown classes: %v", unknown)
	}
	re, err := regexpCompileCaseInsensitive(pat)
	if err != nil {
		t.Fatalf("compile pat: %v", err)
	}
	if !re.MatchString("data = pickle.loads(x)") {
		t.Errorf("expected deserialization class to match pickle.loads")
	}
	if !re.MatchString("etree.fromstring(x)") {
		t.Errorf("expected xxe class to match etree.fromstring")
	}
	if re.MatchString("cur.execute(sql)") {
		t.Errorf("expected narrowed class set to NOT match cur.execute")
	}
}

func TestSinkClasses_UnknownClassReported(t *testing.T) {
	_, unknown := BuildSinkPatternFromClasses([]string{"sqli", "nonsense-class"})
	if len(unknown) != 1 || unknown[0] != "nonsense-class" {
		t.Errorf("want unknown=[nonsense-class], got %v", unknown)
	}
}

func TestSinkClasses_CommaSeparated(t *testing.T) {
	pat, unknown := BuildSinkPatternFromClasses([]string{"deserialization,xxe"})
	if len(unknown) != 0 {
		t.Fatalf("unexpected unknown classes: %v", unknown)
	}
	re, err := regexpCompileCaseInsensitive(pat)
	if err != nil {
		t.Fatalf("compile pat: %v", err)
	}
	if !re.MatchString("pickle.loads(x)") || !re.MatchString("etree.fromstring(x)") {
		t.Errorf("comma-separated class list did not produce expected pattern")
	}
}

func TestListSinkClasses(t *testing.T) {
	classes := ListSinkClasses()
	if len(classes) == 0 {
		t.Fatal("ListSinkClasses returned empty")
	}
	// Must include at least the canonical families.
	names := make(map[string]bool)
	for _, c := range classes {
		names[c.Name] = true
	}
	for _, required := range []string{"sqli", "cmdi", "deserialization", "xxe", "ldap", "redirect"} {
		if !names[required] {
			t.Errorf("ListSinkClasses missing %q", required)
		}
	}
}

func TestAnalyzeDataflow_SinkClassPickle(t *testing.T) {
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `
def view():
    body = request.data
    data = pickle.loads(body)
`)
	r, err := AnalyzeDataflow(p, DataflowOptions{
		Source:      `request\.data`,
		SinkClasses: []string{"deserialization"},
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.Chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(r.Chains))
	}
	if !strings.Contains(r.Chains[0].SinkCode, "pickle.loads") {
		t.Errorf("expected sink at pickle.loads line, got %q", r.Chains[0].SinkCode)
	}
}

// ---- C2: imports skipped as sinks ----

func TestAnalyzeDataflow_ImportLineNotSink(t *testing.T) {
	p, root := writeTempProject(t)
	// The `import xml.etree.ElementTree` line matches a naive sink regex for
	// xxe; the real sink is `tree = etree.parse(body)` two lines below.
	writeFile(t, root, "app.py", `
def view():
    body = request.data
    import xml.etree.ElementTree as etree
    tree = etree.parse(body)
`)
	r, err := AnalyzeDataflow(p, DataflowOptions{
		Source: `request\.data`,
		Sink:   `xml\.etree|etree\.parse`,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.Chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(r.Chains))
	}
	if !strings.Contains(r.Chains[0].SinkCode, "etree.parse") {
		t.Errorf("expected sink line to be the etree.parse call, got %q", r.Chains[0].SinkCode)
	}
	if strings.Contains(r.Chains[0].SinkCode, "import") {
		t.Errorf("sink line is an import; should have been skipped")
	}
}

func TestAnalyzeDataflow_FromImportLineSkipped(t *testing.T) {
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `
def view():
    body = request.data
    from xml.etree.ElementTree import fromstring
    tree = fromstring(body)
`)
	r, err := AnalyzeDataflow(p, DataflowOptions{
		Source: `request\.data`,
		Sink:   `fromstring|xml\.etree`,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.Chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(r.Chains))
	}
	if strings.HasPrefix(strings.TrimSpace(r.Chains[0].SinkCode), "from ") {
		t.Errorf("sink line is a `from import`; should have been skipped: %q", r.Chains[0].SinkCode)
	}
}

// ---- C3: parameterized SQL recognized as guarded ----

func TestAnalyzeDataflow_FStringSQLUnguarded(t *testing.T) {
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
	if r.Chains[0].Verdict != "unguarded" {
		t.Errorf("want unguarded, got %s (reason=%q)", r.Chains[0].Verdict, r.Chains[0].Reasoning)
	}
}

func TestAnalyzeDataflow_ParameterizedTupleGuarded(t *testing.T) {
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `
def view():
    param = request.form.get("x")
    sql = "SELECT * FROM u WHERE n = ?"
    cur.execute(sql, (param,))
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
	if r.Chains[0].Verdict != "guarded" {
		t.Errorf("want guarded (parameterized), got %s (reason=%q)", r.Chains[0].Verdict, r.Chains[0].Reasoning)
	}
}

func TestAnalyzeDataflow_ParameterizedListGuarded(t *testing.T) {
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `
def view():
    param = request.form.get("x")
    cursor.execute("SELECT * FROM u WHERE n = %s", [param])
`)
	r, err := AnalyzeDataflow(p, DataflowOptions{
		Source: `request\.form\.get`,
		Sink:   `cursor\.execute`,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.Chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(r.Chains))
	}
	if r.Chains[0].Verdict != "guarded" {
		t.Errorf("want guarded (parameterized list), got %s", r.Chains[0].Verdict)
	}
}

func TestAnalyzeDataflow_ExecutemanyGuarded(t *testing.T) {
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `
def view():
    params = request.json
    cur.executemany("INSERT INTO t VALUES (?, ?)", params)
`)
	r, err := AnalyzeDataflow(p, DataflowOptions{
		Source: `request\.json`,
		Sink:   `cur\.executemany`,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.Chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(r.Chains))
	}
	if r.Chains[0].Verdict != "guarded" {
		t.Errorf("want guarded (executemany), got %s", r.Chains[0].Verdict)
	}
}

func TestAnalyzeDataflow_BareExecuteConcatUnguarded(t *testing.T) {
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `
def view():
    param = request.form.get("x")
    cur.execute("SELECT * FROM u WHERE n = '" + param + "'")
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
	if r.Chains[0].Verdict != "unguarded" {
		t.Errorf("want unguarded (string concat), got %s (reason=%q)", r.Chains[0].Verdict, r.Chains[0].Reasoning)
	}
}

func TestAnalyzeDataflow_FStringWithCommasInside(t *testing.T) {
	// Defensive: comma-counting must not be tricked by commas inside an
	// f-string. This should still classify as unguarded (1 arg only).
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `
def view():
    param = request.form.get("x")
    cur.execute(f"SELECT a, b, c FROM u WHERE n = '{param}'")
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
	if r.Chains[0].Verdict != "unguarded" {
		t.Errorf("want unguarded (f-string with embedded commas), got %s", r.Chains[0].Verdict)
	}
}

func TestAnalyzeDataflow_YamlLoadWithLoaderNotAutoGuarded(t *testing.T) {
	// yaml.load(bar, Loader=yaml.Loader) has 2 args BUT is not SQL-shaped;
	// the 2-args-equals-guarded heuristic must NOT trigger.
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `
def view():
    bar = request.form.get("x")
    yobj = yaml.load(bar, Loader=yaml.Loader)
`)
	r, err := AnalyzeDataflow(p, DataflowOptions{
		Source: `request\.form\.get`,
		Sink:   `yaml\.load`,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.Chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(r.Chains))
	}
	if r.Chains[0].Verdict == "guarded" {
		t.Errorf("yaml.load with kwargs must not be auto-guarded; got verdict=%s reason=%q",
			r.Chains[0].Verdict, r.Chains[0].Reasoning)
	}
}

func TestAnalyzeDataflow_SubprocessShellTrueNotAutoGuarded(t *testing.T) {
	// subprocess.run(cmd, shell=True) has 2 args BUT is the exact opposite
	// of guarded — it enables shell injection. Must not auto-guard.
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `
def view():
    cmd = request.form.get("x")
    subprocess.run(cmd, shell=True)
`)
	r, err := AnalyzeDataflow(p, DataflowOptions{
		Source: `request\.form\.get`,
		Sink:   `subprocess\.run`,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.Chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(r.Chains))
	}
	if r.Chains[0].Verdict == "guarded" {
		t.Errorf("subprocess.run(cmd, shell=True) must not be auto-guarded; got verdict=%s",
			r.Chains[0].Verdict)
	}
}

// ---- Summary ----

func TestAnalyzeDataflow_SummaryCounts(t *testing.T) {
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `
def view():
    a = request.form.get("x")
    cur.execute(f"SELECT {a}")
    b = request.form.get("y")
    cur.execute("SELECT %s", (b,))
`)
	r, err := AnalyzeDataflow(p, DataflowOptions{
		Source: `request\.form\.get`,
		Sink:   `cur\.execute`,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if r.Summary.Chains != 2 {
		t.Errorf("want 2 chains in summary, got %d", r.Summary.Chains)
	}
	if r.Summary.Unguarded < 1 || r.Summary.Guarded < 1 {
		t.Errorf("want at least 1 unguarded and 1 guarded, got %+v", r.Summary)
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
