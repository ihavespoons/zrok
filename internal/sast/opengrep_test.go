package sast

import (
	"strings"
	"testing"

	"github.com/ihavespoons/zrok/internal/finding"
)

// sampleSARIF is a trimmed opengrep-shaped SARIF blob covering the result
// fields zrok cares about. It carries two findings: one with a CWE tag and
// rule-level metadata, one minimal/edge-case.
const sampleSARIF = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "opengrep",
        "rules": [
          {
            "id": "python.lang.security.sql-injection",
            "shortDescription": {"text": "SQL injection via string concatenation"},
            "fullDescription": {"text": "User-controlled data flows into a SQL query without parameterization."},
            "help": {"text": "Use parameterized queries. Example: cur.execute('SELECT * FROM t WHERE id = %s', (uid,))"},
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["security", "CWE-89", "owasp-a03"]}
          },
          {
            "id": "generic.note.todo",
            "shortDescription": {"text": "TODO in code"},
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
        "message": {"text": "SQL query is built via string concatenation"},
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
	if sql.Title != "SQL injection via string concatenation" {
		t.Errorf("title = %q, want shortDescription text", sql.Title)
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
	if !strings.Contains(sql.Description, "string concatenation") {
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
		if got[i].Title == "TODO in code" {
			todo = &got[i]
			break
		}
	}
	if todo == nil {
		t.Fatal("did not find TODO result")
	}
	if todo.Severity != finding.SeverityLow {
		t.Errorf("severity = %v, want low (rule level=note)", todo.Severity)
	}
	if todo.CWE != "" {
		t.Errorf("CWE = %q, want empty (rule has no CWE tag)", todo.CWE)
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
