package memory

import (
	"os"
	"path/filepath"
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
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to initialize project: %v", err)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return p, cleanup
}

func TestStoreCreate(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	mem := &Memory{
		Name:        "test-memory",
		Type:        MemoryTypeContext,
		Content:     "Test content",
		Description: "A test memory",
		Tags:        []string{"test", "unit"},
	}

	err := store.Create(mem)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify file was created
	path := filepath.Join(p.GetMemoriesPath(), "context", "test-memory.yaml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("memory file not created")
	}

	// Verify timestamps were set
	if mem.CreatedAt.IsZero() {
		t.Error("CreatedAt not set")
	}
	if mem.UpdatedAt.IsZero() {
		t.Error("UpdatedAt not set")
	}
}

func TestStoreCreateDuplicate(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	mem := &Memory{
		Name:    "test-memory",
		Type:    MemoryTypeContext,
		Content: "Test content",
	}

	err := store.Create(mem)
	if err != nil {
		t.Fatalf("first Create failed: %v", err)
	}

	// Try to create duplicate
	err = store.Create(mem)
	if err == nil {
		t.Error("expected error when creating duplicate memory")
	}
}

func TestStoreCreateValidation(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	// Empty name
	err := store.Create(&Memory{Name: "", Type: MemoryTypeContext, Content: "test"})
	if err == nil {
		t.Error("expected error for empty name")
	}

	// Invalid type
	err = store.Create(&Memory{Name: "test", Type: "invalid", Content: "test"})
	if err == nil {
		t.Error("expected error for invalid type")
	}
}

func TestStoreRead(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	// Create memory
	original := &Memory{
		Name:        "test-memory",
		Type:        MemoryTypeContext,
		Content:     "Test content",
		Description: "A test memory",
		Tags:        []string{"test"},
	}
	err := store.Create(original)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Read it back
	mem, err := store.Read("test-memory", MemoryTypeContext)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if mem.Name != "test-memory" {
		t.Errorf("expected name 'test-memory', got '%s'", mem.Name)
	}

	if mem.Content != "Test content" {
		t.Errorf("expected content 'Test content', got '%s'", mem.Content)
	}

	if mem.Description != "A test memory" {
		t.Errorf("expected description 'A test memory', got '%s'", mem.Description)
	}

	if len(mem.Tags) != 1 || mem.Tags[0] != "test" {
		t.Errorf("unexpected tags: %v", mem.Tags)
	}
}

func TestStoreReadByName(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	// Create memory in pattern type
	original := &Memory{
		Name:    "pattern-memory",
		Type:    MemoryTypePattern,
		Content: "Pattern content",
	}
	err := store.Create(original)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Read by name only (without specifying type)
	mem, err := store.ReadByName("pattern-memory")
	if err != nil {
		t.Fatalf("ReadByName failed: %v", err)
	}

	if mem.Type != MemoryTypePattern {
		t.Errorf("expected type 'pattern', got '%s'", mem.Type)
	}
}

func TestStoreReadNotFound(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	_, err := store.Read("nonexistent", MemoryTypeContext)
	if err == nil {
		t.Error("expected error for nonexistent memory")
	}
}

func TestStoreUpdate(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	// Create memory
	mem := &Memory{
		Name:    "test-memory",
		Type:    MemoryTypeContext,
		Content: "Original content",
	}
	err := store.Create(mem)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	originalCreatedAt := mem.CreatedAt

	// Update it
	mem.Content = "Updated content"
	err = store.Update(mem)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Read it back
	updated, err := store.Read("test-memory", MemoryTypeContext)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if updated.Content != "Updated content" {
		t.Errorf("expected content 'Updated content', got '%s'", updated.Content)
	}

	// CreatedAt should be preserved
	if !updated.CreatedAt.Equal(originalCreatedAt) {
		t.Error("CreatedAt was modified during update")
	}

	// UpdatedAt should be newer
	if !updated.UpdatedAt.After(originalCreatedAt) {
		t.Error("UpdatedAt was not updated")
	}
}

func TestStoreDelete(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	// Create memory
	mem := &Memory{
		Name:    "test-memory",
		Type:    MemoryTypeContext,
		Content: "Test content",
	}
	err := store.Create(mem)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Delete it
	err = store.Delete("test-memory", MemoryTypeContext)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify it's gone
	_, err = store.Read("test-memory", MemoryTypeContext)
	if err == nil {
		t.Error("memory still exists after delete")
	}
}

func TestStoreDeleteNotFound(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	err := store.Delete("nonexistent", MemoryTypeContext)
	if err == nil {
		t.Error("expected error when deleting nonexistent memory")
	}
}

func TestStoreList(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	// Create memories of different types
	memories := []*Memory{
		{Name: "context1", Type: MemoryTypeContext, Content: "c1"},
		{Name: "context2", Type: MemoryTypeContext, Content: "c2"},
		{Name: "pattern1", Type: MemoryTypePattern, Content: "p1"},
		{Name: "stack1", Type: MemoryTypeStack, Content: "s1"},
	}

	for _, mem := range memories {
		if err := store.Create(mem); err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	// List all
	result, err := store.List("")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if result.Total != 4 {
		t.Errorf("expected 4 memories, got %d", result.Total)
	}

	// List by type
	result, err = store.List(MemoryTypeContext)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if result.Total != 2 {
		t.Errorf("expected 2 context memories, got %d", result.Total)
	}

	if result.Type != "context" {
		t.Errorf("expected type 'context', got '%s'", result.Type)
	}
}

func TestStoreSearch(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	store := NewStore(p)

	// Create memories with searchable content
	memories := []*Memory{
		{Name: "sql-injection", Type: MemoryTypePattern, Content: "SQL injection vulnerability pattern", Tags: []string{"security", "sql"}},
		{Name: "xss-injection", Type: MemoryTypePattern, Content: "XSS injection attack pattern", Tags: []string{"security", "xss"}},
		{Name: "auth-flow", Type: MemoryTypeContext, Content: "Authentication flow description"},
	}

	for _, mem := range memories {
		if err := store.Create(mem); err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	// Search by content - both memories contain "injection" in content
	result, err := store.Search("injection")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if result.Total < 1 {
		t.Errorf("expected at least 1 result for 'injection', got %d", result.Total)
	}

	// Search by name/content - "sql" appears in sql-injection
	result, err = store.Search("sql")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if result.Total < 1 {
		t.Errorf("expected at least 1 result for 'sql', got %d", result.Total)
	}

	// Search for "authentication" in content
	result, err = store.Search("authentication")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if result.Total < 1 {
		t.Errorf("expected at least 1 result for 'authentication', got %d", result.Total)
	}

	// Search no results
	result, err = store.Search("nonexistent")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if result.Total != 0 {
		t.Errorf("expected 0 results for 'nonexistent', got %d", result.Total)
	}
}

func TestMemoryTypes(t *testing.T) {
	// Test IsValidType
	if !IsValidType(MemoryTypeContext) {
		t.Error("context should be valid")
	}
	if !IsValidType(MemoryTypePattern) {
		t.Error("pattern should be valid")
	}
	if !IsValidType(MemoryTypeStack) {
		t.Error("stack should be valid")
	}
	if IsValidType("invalid") {
		t.Error("invalid should not be valid")
	}

	// Test ParseMemoryType
	mt, ok := ParseMemoryType("context")
	if !ok || mt != MemoryTypeContext {
		t.Error("failed to parse 'context'")
	}

	_, ok = ParseMemoryType("invalid")
	if ok {
		t.Error("should fail to parse 'invalid'")
	}

	// Test GetTypeDir
	if GetTypeDir(MemoryTypeContext) != "context" {
		t.Error("unexpected dir for context")
	}
	if GetTypeDir(MemoryTypePattern) != "patterns" {
		t.Error("unexpected dir for pattern")
	}
	if GetTypeDir(MemoryTypeStack) != "stack" {
		t.Error("unexpected dir for stack")
	}
}
