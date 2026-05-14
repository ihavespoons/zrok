package rule

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/diffsec/quokka/internal/project"
)

func newTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "quokka-rule-*")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	p, err := project.Initialize(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("project init: %v", err)
	}
	return NewStore(p), func() { _ = os.RemoveAll(dir) }
}

const validRule = `rules:
  - id: quokka-hand-built-sql
    message: Hand-built SQL string — use parameterized queries.
    severity: ERROR
    languages: [python]
    pattern: $DB.execute($X + $Y)
    metadata:
      cwe: CWE-89
`

func validMeta() Meta {
	return Meta{
		CreatedBy: "agent:injection-agent",
		CreatedAt: time.Now().UTC(),
		Reasoning: "Repeated SQL string concatenation pattern in this codebase.",
	}
}

func TestStore_AddAndReadRule(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	if err := s.Add("hand-built-sql", []byte(validRule), validMeta()); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := s.ReadRule("hand-built-sql")
	if err != nil {
		t.Fatalf("ReadRule: %v", err)
	}
	if !strings.Contains(string(got), "quokka-hand-built-sql") {
		t.Errorf("read content missing rule id, got: %s", got)
	}
	meta, err := s.ReadMeta("hand-built-sql")
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if meta.Slug != "hand-built-sql" || meta.CreatedBy != "agent:injection-agent" {
		t.Errorf("meta wrong: %+v", meta)
	}
}

func TestStore_AddRejectsBadSlug(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	cases := []string{"Has-Caps", "with_underscore", "-leading", "trailing-", "has space"}
	for _, slug := range cases {
		if err := s.Add(slug, []byte(validRule), validMeta()); err == nil {
			t.Errorf("Add(%q) should fail slug validation", slug)
		}
	}
}

func TestStore_AddRejectsMalformedYAML(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	if err := s.Add("bad", []byte("not: valid: yaml: structure"), validMeta()); err == nil {
		t.Fatal("Add with malformed YAML should error")
	}
}

func TestStore_AddRejectsMissingRequiredRuleFields(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	cases := map[string]string{
		"no rules key": `name: foo`,
		"empty rules":  `rules: []`,
		"missing id":   `rules: [{message: x, pattern: y}]`,
		"missing message": `rules:
  - id: x
    pattern: y`,
		"missing pattern": `rules:
  - id: x
    message: m`,
		"duplicate ids": `rules:
  - {id: dupe, message: a, pattern: x}
  - {id: dupe, message: b, pattern: y}`,
	}
	for name, body := range cases {
		err := s.Add(strings.ReplaceAll(name, " ", "-"), []byte(body), validMeta())
		if err == nil {
			t.Errorf("Add(%q) should have failed structure validation", name)
		}
	}
}

func TestStore_AddRejectsDuplicateSlug(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_ = s.Add("x", []byte(validRule), validMeta())
	if err := s.Add("x", []byte(validRule), validMeta()); err == nil {
		t.Fatal("second Add with same slug should error")
	}
}

func TestStore_UpdateReplaces(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_ = s.Add("x", []byte(validRule), validMeta())

	updated := strings.Replace(validRule, "ERROR", "WARNING", 1)
	m := validMeta()
	m.Reasoning = "tightened pattern after FP review"
	if err := s.Update("x", []byte(updated), m); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := s.ReadRule("x")
	if !strings.Contains(string(got), "WARNING") {
		t.Errorf("update didn't take, got: %s", got)
	}
	gotMeta, _ := s.ReadMeta("x")
	if gotMeta.Reasoning != "tightened pattern after FP review" {
		t.Errorf("meta not updated, got: %+v", gotMeta)
	}
}

func TestStore_UpdateMissingErrors(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	if err := s.Update("nonexistent", []byte(validRule), validMeta()); err == nil {
		t.Fatal("Update of nonexistent rule should error")
	}
}

func TestStore_Remove(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_ = s.Add("x", []byte(validRule), validMeta())
	if err := s.Remove("x"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := s.Remove("x"); err == nil {
		t.Fatal("Remove of missing rule should error")
	}
}

func TestStore_List(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_ = s.Add("alpha", []byte(validRule), validMeta())
	_ = s.Add("beta", []byte(validRule), validMeta())

	list, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(list))
	}
	// Sorted alphabetically.
	if list[0].Slug != "alpha" || list[1].Slug != "beta" {
		t.Errorf("expected sorted order alpha,beta got %s,%s", list[0].Slug, list[1].Slug)
	}
}

func TestStore_AnnotateAndDisable(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_ = s.Add("x", []byte(validRule), validMeta())

	if err := s.Annotate("x", VerdictRetire, "no triggers in 90 days"); err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	m, _ := s.ReadMeta("x")
	if m.Verdict != VerdictRetire {
		t.Errorf("verdict = %q, want retire", m.Verdict)
	}
	if !m.Disabled {
		t.Error("retire verdict should set Disabled=true")
	}
	if m.LastAuditAt.IsZero() {
		t.Error("LastAuditAt should be set")
	}
	if m.VerdictNote != "no triggers in 90 days" {
		t.Errorf("VerdictNote = %q", m.VerdictNote)
	}
}

func TestStore_AnnotateRejectsInvalidVerdict(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_ = s.Add("x", []byte(validRule), validMeta())
	if err := s.Annotate("x", Verdict("delete"), ""); err == nil {
		t.Fatal("invalid verdict should be rejected")
	}
}

func TestStore_EnabledRulePathsSkipsDisabled(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_ = s.Add("active", []byte(validRule), validMeta())
	_ = s.Add("retired", []byte(validRule), validMeta())
	_ = s.Annotate("retired", VerdictRetire, "")

	paths, err := s.EnabledRulePaths()
	if err != nil {
		t.Fatalf("EnabledRulePaths: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 enabled rule, got %d: %v", len(paths), paths)
	}
	if !strings.HasSuffix(paths[0], "active.yaml") {
		t.Errorf("expected active.yaml path, got %s", paths[0])
	}
}

const multiRuleYAML = `rules:
  - id: quokka-sql-concat
    message: hand-built SQL
    severity: ERROR
    pattern: $DB.execute($X + $Y)
  - id: quokka-fstring-sql
    message: f-string SQL
    severity: ERROR
    pattern: $DB.execute(f"$X")
`

func TestStore_ParseRuleIDs(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	if err := s.Add("multi", []byte(multiRuleYAML), validMeta()); err != nil {
		t.Fatalf("Add: %v", err)
	}
	ids, err := s.ParseRuleIDs("multi")
	if err != nil {
		t.Fatalf("ParseRuleIDs: %v", err)
	}
	if len(ids) != 2 || ids[0] != "quokka-sql-concat" || ids[1] != "quokka-fstring-sql" {
		t.Errorf("expected [quokka-sql-concat quokka-fstring-sql], got %v", ids)
	}
}

func TestStore_RuleIDToSlug(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_ = s.Add("multi", []byte(multiRuleYAML), validMeta())
	_ = s.Add("single", []byte(validRule), validMeta())

	m, err := s.RuleIDToSlug()
	if err != nil {
		t.Fatalf("RuleIDToSlug: %v", err)
	}
	cases := map[string]string{
		"quokka-sql-concat":    "multi",
		"quokka-fstring-sql":   "multi",
		"quokka-hand-built-sql": "single",
	}
	for id, wantSlug := range cases {
		if got := m[id]; got != wantSlug {
			t.Errorf("RuleIDToSlug[%q] = %q, want %q", id, got, wantSlug)
		}
	}
}

func TestStore_MetaRequiresCreatedBy(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	bad := Meta{CreatedAt: time.Now()}
	if err := s.Add("x", []byte(validRule), bad); err == nil {
		t.Fatal("missing CreatedBy should fail validation")
	}
}
