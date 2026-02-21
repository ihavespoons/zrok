package finding

import (
	"os"
	"testing"

	"github.com/ihavespoons/zrok/internal/project"
)

func setupTestProject(t *testing.T) (*project.Project, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "zrok-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	p, err := project.Initialize(tmpDir)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		t.Fatalf("failed to initialize project: %v", err)
	}

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	return p, cleanup
}

func TestStoreCreate(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	f := &Finding{
		Title:      "Test SQL Injection",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Location: Location{
			File:      "src/db.go",
			LineStart: 42,
		},
		Description: "User input in SQL query",
	}

	err := store.Create(f)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// ID should be auto-generated
	if f.ID == "" {
		t.Error("ID not generated")
	}

	if f.ID != "FIND-001" {
		t.Errorf("expected ID 'FIND-001', got '%s'", f.ID)
	}

	// Status should default to open
	if f.Status != StatusOpen {
		t.Errorf("expected status 'open', got '%s'", f.Status)
	}

	// Timestamps should be set
	if f.CreatedAt.IsZero() {
		t.Error("CreatedAt not set")
	}
}

func TestStoreCreateWithID(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	f := &Finding{
		ID:       "CUSTOM-001",
		Title:    "Test Finding",
		Severity: SeverityMedium,
		Location: Location{File: "test.go", LineStart: 1},
	}

	err := store.Create(f)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if f.ID != "CUSTOM-001" {
		t.Errorf("expected ID 'CUSTOM-001', got '%s'", f.ID)
	}
}

func TestStoreCreateValidation(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	// Missing title
	err := store.Create(&Finding{
		Severity: SeverityHigh,
		Location: Location{File: "test.go", LineStart: 1},
	})
	if err == nil {
		t.Error("expected error for missing title")
	}

	// Missing file
	err = store.Create(&Finding{
		Title:    "Test",
		Severity: SeverityHigh,
		Location: Location{LineStart: 1},
	})
	if err == nil {
		t.Error("expected error for missing file")
	}

	// Invalid severity
	err = store.Create(&Finding{
		Title:    "Test",
		Severity: "invalid",
		Location: Location{File: "test.go", LineStart: 1},
	})
	if err == nil {
		t.Error("expected error for invalid severity")
	}
}

func TestStoreRead(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	original := &Finding{
		Title:       "Test XSS",
		Severity:    SeverityCritical,
		Confidence:  ConfidenceMedium,
		CWE:         "CWE-79",
		Description: "Reflected XSS vulnerability",
		Location: Location{
			File:      "src/handler.go",
			LineStart: 100,
			LineEnd:   105,
			Function:  "RenderPage",
			Snippet:   "html := fmt.Sprintf(\"<div>%s</div>\", userInput)",
		},
		Impact:      "Account takeover",
		Remediation: "Use proper HTML escaping",
		Tags:        []string{"xss", "owasp-top-10"},
	}

	err := store.Create(original)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Read it back
	f, err := store.Read(original.ID)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if f.Title != "Test XSS" {
		t.Errorf("unexpected title: %s", f.Title)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("unexpected severity: %s", f.Severity)
	}
	if f.CWE != "CWE-79" {
		t.Errorf("unexpected CWE: %s", f.CWE)
	}
	if f.Location.Function != "RenderPage" {
		t.Errorf("unexpected function: %s", f.Location.Function)
	}
	if len(f.Tags) != 2 {
		t.Errorf("unexpected tags count: %d", len(f.Tags))
	}
}

func TestStoreReadNotFound(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	_, err := store.Read("NONEXISTENT")
	if err == nil {
		t.Error("expected error for nonexistent finding")
	}
}

func TestStoreUpdate(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	f := &Finding{
		Title:    "Test Finding",
		Severity: SeverityMedium,
		Status:   StatusOpen,
		Location: Location{File: "test.go", LineStart: 1},
	}

	err := store.Create(f)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	originalCreatedAt := f.CreatedAt

	// Update status
	f.Status = StatusConfirmed
	f.Severity = SeverityHigh

	err = store.Update(f)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Read and verify
	updated, err := store.Read(f.ID)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if updated.Status != StatusConfirmed {
		t.Errorf("expected status 'confirmed', got '%s'", updated.Status)
	}
	if updated.Severity != SeverityHigh {
		t.Errorf("expected severity 'high', got '%s'", updated.Severity)
	}

	// CreatedAt should be preserved
	if !updated.CreatedAt.Equal(originalCreatedAt) {
		t.Error("CreatedAt was modified")
	}
}

func TestStoreDelete(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	f := &Finding{
		Title:    "Test Finding",
		Severity: SeverityLow,
		Location: Location{File: "test.go", LineStart: 1},
	}

	err := store.Create(f)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err = store.Delete(f.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = store.Read(f.ID)
	if err == nil {
		t.Error("finding still exists after delete")
	}
}

func TestStoreList(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	// Create findings with different severities and statuses
	findings := []*Finding{
		{Title: "Critical 1", Severity: SeverityCritical, Status: StatusOpen, Location: Location{File: "a.go", LineStart: 1}},
		{Title: "High 1", Severity: SeverityHigh, Status: StatusOpen, Location: Location{File: "b.go", LineStart: 1}},
		{Title: "High 2", Severity: SeverityHigh, Status: StatusConfirmed, Location: Location{File: "c.go", LineStart: 1}},
		{Title: "Medium 1", Severity: SeverityMedium, Status: StatusFalsePositive, Location: Location{File: "d.go", LineStart: 1}},
		{Title: "Low 1", Severity: SeverityLow, Status: StatusFixed, Location: Location{File: "e.go", LineStart: 1}},
	}

	for _, f := range findings {
		if err := store.Create(f); err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	// List all
	result, err := store.List(nil)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if result.Total != 5 {
		t.Errorf("expected 5 findings, got %d", result.Total)
	}

	// Verify sorted by severity (critical first)
	if result.Findings[0].Severity != SeverityCritical {
		t.Error("findings not sorted by severity")
	}

	// Filter by severity
	result, err = store.List(&FilterOptions{Severity: SeverityHigh})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if result.Total != 2 {
		t.Errorf("expected 2 high severity findings, got %d", result.Total)
	}

	// Filter by status
	result, err = store.List(&FilterOptions{Status: StatusOpen})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if result.Total != 2 {
		t.Errorf("expected 2 open findings, got %d", result.Total)
	}
}

func TestStoreStats(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	// Create diverse findings
	findings := []*Finding{
		{Title: "F1", Severity: SeverityCritical, Status: StatusOpen, CWE: "CWE-89", Location: Location{File: "a.go", LineStart: 1}, Tags: []string{"sql", "injection"}},
		{Title: "F2", Severity: SeverityHigh, Status: StatusOpen, CWE: "CWE-89", Location: Location{File: "b.go", LineStart: 1}, Tags: []string{"sql"}},
		{Title: "F3", Severity: SeverityHigh, Status: StatusConfirmed, CWE: "CWE-79", Location: Location{File: "c.go", LineStart: 1}, Tags: []string{"xss"}},
		{Title: "F4", Severity: SeverityMedium, Status: StatusFixed, Location: Location{File: "d.go", LineStart: 1}},
	}

	for _, f := range findings {
		if err := store.Create(f); err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	stats, err := store.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}

	if stats.Total != 4 {
		t.Errorf("expected total 4, got %d", stats.Total)
	}

	if stats.BySeverity["critical"] != 1 {
		t.Errorf("expected 1 critical, got %d", stats.BySeverity["critical"])
	}

	if stats.BySeverity["high"] != 2 {
		t.Errorf("expected 2 high, got %d", stats.BySeverity["high"])
	}

	if stats.ByStatus["open"] != 2 {
		t.Errorf("expected 2 open, got %d", stats.ByStatus["open"])
	}

	if stats.ByCWE["CWE-89"] != 2 {
		t.Errorf("expected 2 CWE-89, got %d", stats.ByCWE["CWE-89"])
	}

	// Check top tags
	if len(stats.TopTags) == 0 {
		t.Error("no top tags")
	}
}

func TestStoreIDGeneration(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	// Create multiple findings and verify sequential IDs
	for i := 1; i <= 3; i++ {
		f := &Finding{
			Title:    "Test",
			Severity: SeverityInfo,
			Location: Location{File: "test.go", LineStart: 1},
		}
		if err := store.Create(f); err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		expectedID := "FIND-00" + string('0'+rune(i))
		if f.ID != expectedID {
			t.Errorf("expected ID '%s', got '%s'", expectedID, f.ID)
		}
	}
}

func TestStoreFlowTrace(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	f := &Finding{
		Title:      "SQL Injection with Flow Trace",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		CWE:        "CWE-89",
		Location: Location{
			File:      "src/handler.go",
			LineStart: 42,
		},
		Description: "User input flows to SQL query",
		FlowTrace: &FlowTrace{
			Source: "handler.go:30 - r.URL.Query().Get(\"name\")",
			Sink:   "db.go:55 - db.Query(query)",
			Path: []string{
				"handler.go:30 - URL parameter extraction",
				"handler.go:35 - passed to buildQuery()",
				"db.go:50 - string concatenation into SQL",
			},
			Guards:    []string{},
			Unguarded: true,
		},
		ReviewedBy: []string{"validation-agent", "review-agent"},
	}

	err := store.Create(f)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Read it back
	loaded, err := store.Read(f.ID)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if loaded.FlowTrace == nil {
		t.Fatal("FlowTrace not persisted")
	}

	if loaded.FlowTrace.Source != f.FlowTrace.Source {
		t.Errorf("FlowTrace.Source mismatch: got %q", loaded.FlowTrace.Source)
	}

	if loaded.FlowTrace.Sink != f.FlowTrace.Sink {
		t.Errorf("FlowTrace.Sink mismatch: got %q", loaded.FlowTrace.Sink)
	}

	if len(loaded.FlowTrace.Path) != 3 {
		t.Errorf("expected 3 path steps, got %d", len(loaded.FlowTrace.Path))
	}

	if !loaded.FlowTrace.Unguarded {
		t.Error("FlowTrace.Unguarded should be true")
	}

	if len(loaded.ReviewedBy) != 2 {
		t.Errorf("expected 2 ReviewedBy entries, got %d", len(loaded.ReviewedBy))
	}
}

func TestStoreStatsWithCreatedBy(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	findings := []*Finding{
		{Title: "F1", Severity: SeverityHigh, Location: Location{File: "a.go", LineStart: 1}, CreatedBy: "security-agent"},
		{Title: "F2", Severity: SeverityMedium, Location: Location{File: "b.go", LineStart: 1}, CreatedBy: "security-agent"},
		{Title: "F3", Severity: SeverityLow, Location: Location{File: "c.go", LineStart: 1}, CreatedBy: "guards-agent"},
	}

	for _, f := range findings {
		if err := store.Create(f); err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	stats, err := store.Stats()
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}

	if stats.ByCreatedBy["security-agent"] != 2 {
		t.Errorf("expected 2 security-agent findings, got %d", stats.ByCreatedBy["security-agent"])
	}
	if stats.ByCreatedBy["guards-agent"] != 1 {
		t.Errorf("expected 1 guards-agent finding, got %d", stats.ByCreatedBy["guards-agent"])
	}
}

func TestFindingTypes(t *testing.T) {
	// Test severity validation
	if !IsValidSeverity(SeverityCritical) {
		t.Error("critical should be valid")
	}
	if !IsValidSeverity(SeverityHigh) {
		t.Error("high should be valid")
	}
	if IsValidSeverity("invalid") {
		t.Error("invalid should not be valid")
	}

	// Test status validation
	if !IsValidStatus(StatusOpen) {
		t.Error("open should be valid")
	}
	if !IsValidStatus(StatusConfirmed) {
		t.Error("confirmed should be valid")
	}
	if IsValidStatus("invalid") {
		t.Error("invalid should not be valid")
	}

	// Test severity weight
	if SeverityWeight(SeverityCritical) <= SeverityWeight(SeverityHigh) {
		t.Error("critical should have higher weight than high")
	}
	if SeverityWeight(SeverityHigh) <= SeverityWeight(SeverityMedium) {
		t.Error("high should have higher weight than medium")
	}
}

func TestStoreImport(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	// Create a temp file with finding YAML
	tmpFile, err := os.CreateTemp("", "finding-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	yaml := `title: Imported Finding
severity: high
confidence: medium
location:
  file: imported.go
  line_start: 50
description: An imported finding
`
	if _, err := tmpFile.WriteString(yaml); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	_ = tmpFile.Close()

	// Import
	f, err := store.Import(tmpFile.Name())
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	if f.Title != "Imported Finding" {
		t.Errorf("unexpected title: %s", f.Title)
	}

	// Should have new ID
	if f.ID == "" {
		t.Error("ID not generated for imported finding")
	}

	// Verify it was persisted
	_, err = store.Read(f.ID)
	if err != nil {
		t.Error("imported finding not persisted")
	}
}
