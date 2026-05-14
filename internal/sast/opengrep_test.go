package sast

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diffsec/quokka/internal/finding"
)

// sampleSARIF mirrors what opengrep actually emits in production: the rule's
// shortDescription is the synthetic "Opengrep Finding: <ruleId>" string,
// CWE tags carry a description suffix ("CWE-89: ..."), and the result
// message holds the real security guidance.
const sampleSARIF = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "opengrep",
        "rules": [
          {
            "id": "python.lang.security.sql-injection",
            "shortDescription": {"text": "Opengrep Finding: python.lang.security.sql-injection"},
            "fullDescription": {"text": "User-controlled data flows into a SQL query without parameterization."},
            "help": {"text": "Use parameterized queries. Example: cur.execute('SELECT * FROM t WHERE id = %s', (uid,))"},
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["security", "CWE-89: SQL Injection", "owasp-a03"]}
          },
          {
            "id": "generic.note.todo",
            "shortDescription": {"text": "Opengrep Finding: generic.note.todo"},
            "defaultConfiguration": {"level": "note"},
            "properties": {"tags": ["maintenance"]}
          }
        ]
      }
    },
    "results": [
      {
        "ruleId": "python.lang.security.sql-injection",
        "level": "error",
        "message": {"text": "User-supplied input flows into a SQL query without parameterization. Use parameterized queries."},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "app/handlers.py"},
            "region": {
              "startLine": 42,
              "endLine": 44,
              "snippet": {"text": "query = 'SELECT * FROM users WHERE id = ' + user_id"}
            }
          }
        }]
      },
      {
        "ruleId": "generic.note.todo",
        "message": {"text": "TODO: refactor"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "app/util.py"},
            "region": {"startLine": 7}
          }
        }]
      }
    ]
  }]
}`

func TestParseSARIF_ConvertsTwoResults(t *testing.T) {
	got, err := ParseSARIF([]byte(sampleSARIF))
	if err != nil {
		t.Fatalf("ParseSARIF: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(got))
	}
}

func TestParseSARIF_HighSeverityHasFullMetadata(t *testing.T) {
	got, _ := ParseSARIF([]byte(sampleSARIF))
	var sql *finding.Finding
	for i := range got {
		if got[i].CWE == "CWE-89" {
			sql = &got[i]
			break
		}
	}
	if sql == nil {
		t.Fatal("did not find the SQL-injection result")
	}
	wantTitle := "User-supplied input flows into a SQL query without parameterization"
	if sql.Title != wantTitle {
		t.Errorf("title = %q, want first sentence of message %q", sql.Title, wantTitle)
	}
	if sql.Severity != finding.SeverityHigh {
		t.Errorf("severity = %v, want high (level=error)", sql.Severity)
	}
	if sql.Confidence != finding.ConfidenceMedium {
		t.Errorf("confidence = %v, want medium (SAST default)", sql.Confidence)
	}
	if sql.Status != finding.StatusOpen {
		t.Errorf("status = %v, want open", sql.Status)
	}
	if sql.CreatedBy != "opengrep" {
		t.Errorf("created_by = %q, want opengrep", sql.CreatedBy)
	}
	if sql.Location.File != "app/handlers.py" || sql.Location.LineStart != 42 || sql.Location.LineEnd != 44 {
		t.Errorf("location wrong: %+v", sql.Location)
	}
	if !strings.Contains(sql.Description, "parameterization") {
		t.Errorf("description should come from result message, got: %q", sql.Description)
	}
	if !strings.Contains(sql.Remediation, "parameterized") {
		t.Errorf("remediation should come from rule.help, got: %q", sql.Remediation)
	}
}

func TestParseSARIF_LowSeverityRuleLevel(t *testing.T) {
	got, _ := ParseSARIF([]byte(sampleSARIF))
	var todo *finding.Finding
	for i := range got {
		// Title comes from first-sentence-of-message, falling through to a
		// cleaned rule id when the message has no separable sentence.
		if strings.Contains(got[i].Title, "TODO") {
			todo = &got[i]
			break
		}
	}
	if todo == nil {
		t.Fatalf("did not find TODO result; titles: %v", titlesOf(got))
	}
	if todo.Severity != finding.SeverityLow {
		t.Errorf("severity = %v, want low (rule level=note)", todo.Severity)
	}
	if todo.CWE != "" {
		t.Errorf("CWE = %q, want empty (rule has no CWE tag)", todo.CWE)
	}
}

func titlesOf(fs []finding.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Title
	}
	return out
}

func TestParseSARIF_CWEExtractionStripsDescription(t *testing.T) {
	got, _ := ParseSARIF([]byte(sampleSARIF))
	var sql *finding.Finding
	for i := range got {
		if strings.Contains(got[i].Title, "parameterization") {
			sql = &got[i]
			break
		}
	}
	if sql == nil {
		t.Fatal("did not find SQL injection result")
	}
	if sql.CWE != "CWE-89" {
		t.Errorf("CWE = %q, want canonical CWE-89 (description suffix stripped)", sql.CWE)
	}
}

func TestParseSARIF_SyntheticShortDescriptionIgnored(t *testing.T) {
	// "Opengrep Finding: <ruleId>" is a useless title; converter should
	// fall through to the message text instead. Regression test for the
	// behavior we observed in real opengrep output.
	got, _ := ParseSARIF([]byte(sampleSARIF))
	for _, f := range got {
		if strings.HasPrefix(f.Title, "Opengrep Finding:") {
			t.Errorf("title %q leaked opengrep's synthetic shortDescription", f.Title)
		}
	}
}

func TestExtractCWE(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"CWE-89", "CWE-89"},
		{"CWE-327: Use of a Broken or Risky Cryptographic Algorithm", "CWE-327"},
		{"cwe-22: path traversal", "CWE-22"},
		{"security", ""},
		{"CWE-", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := extractCWE(c.in); got != c.want {
			t.Errorf("extractCWE(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseSARIF_TagsIncludeOpengrepRuleID(t *testing.T) {
	got, _ := ParseSARIF([]byte(sampleSARIF))
	if len(got) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range got {
		hasRuleTag := false
		for _, tag := range f.Tags {
			if strings.HasPrefix(tag, OpengrepRuleTagPrefix) {
				hasRuleTag = true
				break
			}
		}
		if !hasRuleTag {
			t.Errorf("finding %q missing %q tag: %v", f.Title, OpengrepRuleTagPrefix, f.Tags)
		}
	}
}

func TestParseSARIF_TagsAlwaysIncludeSastMarker(t *testing.T) {
	got, _ := ParseSARIF([]byte(sampleSARIF))
	for _, f := range got {
		hasSAST := false
		hasOpengrep := false
		for _, t := range f.Tags {
			if t == "sast" {
				hasSAST = true
			}
			if t == "opengrep" {
				hasOpengrep = true
			}
		}
		if !hasSAST || !hasOpengrep {
			t.Errorf("finding %q tags missing sast/opengrep marker: %v", f.Title, f.Tags)
		}
	}
}

func TestParseSARIF_EmptyInputReturnsNil(t *testing.T) {
	got, err := ParseSARIF([]byte(`{"version":"2.1.0","runs":[]}`))
	if err != nil {
		t.Fatalf("empty runs should not error: %v", err)
	}
	if got != nil {
		t.Errorf("empty runs should produce nil findings, got %d", len(got))
	}
}

func TestParseSARIF_InvalidJSONErrors(t *testing.T) {
	if _, err := ParseSARIF([]byte("not json")); err == nil {
		t.Fatal("expected error parsing invalid JSON")
	}
}

func TestMapSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want finding.Severity
	}{
		{"error", finding.SeverityHigh},
		{"ERROR", finding.SeverityHigh},
		{"warning", finding.SeverityMedium},
		{"note", finding.SeverityLow},
		{"none", finding.SeverityInfo},
		{"", finding.SeverityInfo},
		{"bogus", finding.SeverityMedium},
	}
	for _, c := range cases {
		if got := mapSeverity(c.in); got != c.want {
			t.Errorf("mapSeverity(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestScanner_RequiresConfig(t *testing.T) {
	s := &Scanner{}
	if _, err := s.Scan([]string{"."}); err == nil {
		t.Fatal("expected error when Config is empty")
	}
}

// TestRelativizePath covers the absolute-path normalisation opengrep
// findings need before they can match ground truth, dedup against other
// agents' findings, or render in SARIF without working-directory leakage.
//
// The OWASP-eval failure mode that motivated this: opengrep was run
// from /var/folders/.../tmp.Cigwc9rdHa/ (the macOS tmp dir, itself a
// symlink to /private/var/folders/...) and emitted absolute paths in
// SARIF. ParseSARIF returned them as-is, and 15 of 43 findings became
// FPs because their .location.file didn't match `testcode/Foo.py`
// in the ground truth.
func TestRelativizePath(t *testing.T) {
	// Use a real tmpdir so the symlink behavior on macOS exercises the
	// EvalSymlinks branch.
	root, err := os.MkdirTemp("", "quokka-relpath-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	// Make a nested file we'll reference, since EvalSymlinks needs the
	// path to exist to resolve.
	nested := filepath.Join(root, "testcode")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(nested, "Foo.py")
	if err := os.WriteFile(target, []byte("# fixture"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		path string
		root string
		want string
	}{
		{"already relative passes through", "testcode/Foo.py", root, "testcode/Foo.py"},
		{"empty root passes through cleaned", target, "", filepath.Clean(target)},
		{"file:// URI prefix stripped", "file://" + target, root, "testcode/Foo.py"},
		{"absolute under root becomes relative", target, root, "testcode/Foo.py"},
		{"absolute outside root stays absolute", "/usr/lib/python3/something.py", root, "/usr/lib/python3/something.py"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got := relativizePath(c.path, c.root)
			if got != c.want {
				t.Errorf("relativizePath(%q, %q) = %q, want %q", c.path, c.root, got, c.want)
			}
		})
	}
}

func TestScanner_MissingBinaryGivesActionableError(t *testing.T) {
	s := &Scanner{Binary: "definitely-not-a-real-binary-xyz", Config: "p/security"}
	_, err := s.Scan([]string{"."})
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
	if !strings.Contains(err.Error(), "opengrep binary") || !strings.Contains(err.Error(), "PATH") {
		t.Errorf("error should mention opengrep binary + PATH, got: %v", err)
	}
}

func TestScanner_BuildArgsMergesExtraConfigs(t *testing.T) {
	s := &Scanner{
		Config:       "p/security",
		ExtraConfigs: []string{"/proj/.quokka/rules/foo.yaml", "/proj/.quokka/rules/bar.yaml"},
	}
	args := s.buildArgs("/tmp/out.sarif", []string{"/proj/app.py"})
	// Each --config appears with its value immediately after; we count them
	// and check the values to confirm order is preserved.
	var configValues []string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--config" {
			configValues = append(configValues, args[i+1])
		}
	}
	want := []string{"p/security", "/proj/.quokka/rules/foo.yaml", "/proj/.quokka/rules/bar.yaml"}
	if len(configValues) != len(want) {
		t.Fatalf("got %d --config values, want %d: %v", len(configValues), len(want), configValues)
	}
	for i := range want {
		if configValues[i] != want[i] {
			t.Errorf("--config[%d] = %q, want %q", i, configValues[i], want[i])
		}
	}
	// Targets land after all --config args.
	if args[len(args)-1] != "/proj/app.py" {
		t.Errorf("expected /proj/app.py at end, got: %v", args)
	}
}

func TestScanner_BuildArgsWithoutExtraConfigs(t *testing.T) {
	s := &Scanner{Config: "p/security"}
	args := s.buildArgs("/tmp/out.sarif", []string{"."})
	configCount := 0
	for _, a := range args {
		if a == "--config" {
			configCount++
		}
	}
	if configCount != 1 {
		t.Errorf("expected single --config when ExtraConfigs empty, got %d", configCount)
	}
}
