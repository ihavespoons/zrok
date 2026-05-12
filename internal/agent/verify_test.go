package agent

import (
	"testing"
	"time"

	"github.com/ihavespoons/zrok/internal/memory"
)

// fakeStore is an in-memory MemoryStoreReader for unit tests.
type fakeStore struct {
	memories map[string]*memory.Memory
}

func (f *fakeStore) ReadByName(name string) (*memory.Memory, error) {
	if m, ok := f.memories[name]; ok {
		return m, nil
	}
	return nil, errNotFound
}

type notFoundError struct{}

func (notFoundError) Error() string { return "not found" }

var errNotFound = notFoundError{}

func newFakeStore(names ...string) *fakeStore {
	fs := &fakeStore{memories: map[string]*memory.Memory{}}
	now := time.Now()
	for _, n := range names {
		fs.memories[n] = &memory.Memory{
			Name:      n,
			Type:      memory.MemoryTypeContext,
			UpdatedAt: now,
		}
	}
	return fs
}

func TestVerifyAgentMemories_AllPresent(t *testing.T) {
	cfg := &AgentConfig{
		Name:            "security-agent",
		Phase:           PhaseAnalysis,
		ContextMemories: []string{"project_overview", "api_endpoints", "auth_patterns"},
	}
	store := newFakeStore("project_overview", "api_endpoints", "auth_patterns")

	rpt := VerifyAgentMemories(cfg, store)

	if !rpt.Pass {
		t.Fatalf("expected Pass=true, got false")
	}
	if rpt.Present != 3 {
		t.Errorf("expected 3 present, got %d", rpt.Present)
	}
	if rpt.Missing != 0 {
		t.Errorf("expected 0 missing, got %d", rpt.Missing)
	}
	if len(rpt.Memories) != 3 {
		t.Fatalf("expected 3 memory entries, got %d", len(rpt.Memories))
	}
	for _, m := range rpt.Memories {
		if !m.Present {
			t.Errorf("expected %s to be present", m.Name)
		}
	}
}

func TestVerifyAgentMemories_SomeMissing(t *testing.T) {
	cfg := &AgentConfig{
		Name:            "security-agent",
		Phase:           PhaseAnalysis,
		ContextMemories: []string{"project_overview", "auth_boundaries", "auth_patterns"},
	}
	// auth_boundaries is missing
	store := newFakeStore("project_overview", "auth_patterns")

	rpt := VerifyAgentMemories(cfg, store)

	if rpt.Pass {
		t.Fatalf("expected Pass=false")
	}
	if rpt.Present != 2 {
		t.Errorf("expected 2 present, got %d", rpt.Present)
	}
	if rpt.Missing != 1 {
		t.Errorf("expected 1 missing, got %d", rpt.Missing)
	}

	// Find the missing entry and assert it's auth_boundaries
	var foundMissing bool
	for _, m := range rpt.Memories {
		if m.Name == "auth_boundaries" {
			if m.Present {
				t.Errorf("auth_boundaries should be missing")
			}
			foundMissing = true
		}
	}
	if !foundMissing {
		t.Error("missing auth_boundaries entry not found in report")
	}
}

func TestVerifyAgentMemories_NoMemoriesExpected(t *testing.T) {
	cfg := &AgentConfig{
		Name:            "minimal-agent",
		Phase:           PhaseAnalysis,
		ContextMemories: nil,
	}
	store := newFakeStore()

	rpt := VerifyAgentMemories(cfg, store)
	if !rpt.Pass {
		t.Error("expected Pass=true when no memories expected")
	}
	if rpt.Expected != 0 || rpt.Present != 0 || rpt.Missing != 0 {
		t.Errorf("unexpected counts: %+v", rpt)
	}
}
