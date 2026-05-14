package think

import (
	"testing"

	"github.com/ihavespoons/quokka/internal/finding"
)

func TestAnalyzeValidate_TruePositive(t *testing.T) {
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `# header
def view():
    param = request.form.get("x")
    sql = f"SELECT * FROM u WHERE n = '{param}'"
    cur.execute(sql)
`)
	store := finding.NewStore(p)
	f := &finding.Finding{
		Title:    "SQLi",
		Severity: finding.SeverityCritical,
		Status:   finding.StatusOpen,
		CWE:      "CWE-89",
		Location: finding.Location{File: "app.py", LineStart: 5},
		Description: "SOURCE: request.form.get(\"x\") at app.py:3\nSINK: cur.execute(sql) at app.py:5",
	}
	if err := store.Create(f); err != nil {
		t.Fatalf("create: %v", err)
	}

	r, err := AnalyzeValidate(p, ValidateOptions{FindingID: f.ID})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !r.SourceFound {
		t.Errorf("want source found")
	}
	if !r.SinkFound {
		t.Errorf("want sink found")
	}
	if len(r.GuardsFound) != 0 {
		t.Errorf("want no guards, got %d", len(r.GuardsFound))
	}
	if r.Verdict != "likely_true_positive" {
		t.Errorf("want likely_true_positive, got %s", r.Verdict)
	}
}

func TestAnalyzeValidate_GuardPresent(t *testing.T) {
	p, root := writeTempProject(t)
	writeFile(t, root, "app.py", `# header
def view():
    param = request.form.get("x")
    safe = bleach.clean(param)
    cur.execute("SELECT * FROM u WHERE n = ?", (safe,))
`)
	store := finding.NewStore(p)
	f := &finding.Finding{
		Title:    "SQLi?",
		Severity: finding.SeverityHigh,
		Status:   finding.StatusOpen,
		CWE:      "CWE-89",
		Location: finding.Location{File: "app.py", LineStart: 5},
		Description: "SOURCE: request.form.get\nSINK: cur.execute",
	}
	if err := store.Create(f); err != nil {
		t.Fatalf("create: %v", err)
	}

	r, err := AnalyzeValidate(p, ValidateOptions{FindingID: f.ID})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(r.GuardsFound) == 0 {
		t.Fatalf("want at least one guard, got 0")
	}
	if r.Verdict != "uncertain_guard_present" {
		t.Errorf("want uncertain_guard_present, got %s", r.Verdict)
	}
}
