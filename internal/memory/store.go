package memory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ihavespoons/zrok/internal/project"
	"gopkg.in/yaml.v3"
)

// Store handles memory CRUD operations.
//
// Concurrency: Create/Update/Delete and Reindex serialize via reindexMu so a
// long-running rebuild cannot race with point writes. Close() blocks until any
// in-flight Reindex finishes (or its context is cancelled by the caller).
type Store struct {
	basePath    string
	searchIndex *SearchIndex

	// reindexMu serializes a full-index rebuild against single-doc updates.
	// Held in write mode by Reindex, read mode by Create/Update/Delete.
	reindexMu sync.RWMutex

	// closeOnce guards Close from running twice.
	closeOnce sync.Once
	// closed is set after Close completes; new Reindex calls fail fast.
	closedMu sync.Mutex
	closed   bool
	// reindexWG tracks in-flight Reindex calls so Close can wait them out.
	reindexWG sync.WaitGroup
}

// NewStore creates a new memory store for the given project.
//
// Unlike older versions of this function, NewStore does NOT launch a
// background reindex goroutine. Callers that need full-text search must call
// Reindex(ctx) explicitly (e.g. `zrok memory reindex` or before
// memory.Search). If the on-disk index is detected as empty but YAML
// memories exist, a one-line warning is emitted to stderr suggesting an
// explicit reindex.
func NewStore(p *project.Project) *Store {
	basePath := p.GetMemoriesPath()

	// Initialize search index
	searchIndex, err := NewSearchIndex(basePath)
	if err != nil {
		// Log error but continue without search index
		fmt.Fprintf(os.Stderr, "Warning: failed to initialize search index: %v\n", err)
	}

	store := &Store{
		basePath:    basePath,
		searchIndex: searchIndex,
	}

	// Detect missing/empty index when YAML memories exist; warn the user to
	// run an explicit reindex. We intentionally do NOT spawn a goroutine
	// here: doing so races against concurrent Create/Update calls and leaks
	// past Close. The reindex must be triggered explicitly.
	if searchIndex != nil {
		docs, derr := searchIndex.DocCount()
		if derr == nil && docs == 0 {
			// Cheap probe: does the YAML store have anything?
			if hasAny := store.hasAnyMemoriesOnDisk(); hasAny {
				fmt.Fprintln(os.Stderr,
					"Notice: memory search index is empty but memories exist on disk. "+
						"Run `zrok memory reindex` to rebuild the index.")
			}
		}
	}

	return store
}

// hasAnyMemoriesOnDisk is a low-cost check that returns true if any .yaml
// memory file is present under any type subdirectory. Used to gate the
// "empty index" warning so fresh projects stay quiet.
func (s *Store) hasAnyMemoriesOnDisk() bool {
	for _, t := range ValidMemoryTypes {
		typeDir := filepath.Join(s.basePath, GetTypeDir(t))
		entries, err := os.ReadDir(typeDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
				return true
			}
		}
	}
	return false
}

// Reindex rebuilds the search index from the on-disk YAML memories. It is
// cancellable via ctx: long projects can hand in a deadlined context. While
// Reindex is running, point writes (Create/Update/Delete) wait on
// reindexMu's read lock — so the index never observes a partial rebuild.
//
// If the search index is unavailable, Reindex returns nil (no-op): callers
// fall back to substring search regardless.
func (s *Store) Reindex(ctx context.Context) error {
	if s.searchIndex == nil {
		return nil
	}

	// Fail fast if the store has already been closed.
	s.closedMu.Lock()
	if s.closed {
		s.closedMu.Unlock()
		return fmt.Errorf("memory store is closed")
	}
	s.reindexWG.Add(1)
	s.closedMu.Unlock()
	defer s.reindexWG.Done()

	// Early-out if the caller's context is already done.
	if err := ctx.Err(); err != nil {
		return err
	}

	all, err := s.List("")
	if err != nil {
		return fmt.Errorf("failed to list memories for reindex: %w", err)
	}

	// Check cancellation again before doing the expensive Batch.
	if err := ctx.Err(); err != nil {
		return err
	}

	// Take the write lock so no Create/Update is in flight during the
	// batch rebuild. Reindex on bleve replaces existing docs by ID, so this
	// is safe; we just don't want a Create to fire between List and Batch.
	s.reindexMu.Lock()
	defer s.reindexMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	return s.searchIndex.Reindex(all.Memories)
}

// Create creates a new memory
func (s *Store) Create(mem *Memory) error {
	// Hold the read lock so a Reindex cannot overlap a single-doc write.
	s.reindexMu.RLock()
	defer s.reindexMu.RUnlock()

	// Validate
	if mem.Name == "" {
		return fmt.Errorf("memory name is required")
	}
	if !IsValidType(mem.Type) {
		return fmt.Errorf("invalid memory type: %s", mem.Type)
	}

	// Check if already exists
	if _, err := s.Read(mem.Name, mem.Type); err == nil {
		return fmt.Errorf("memory '%s' of type '%s' already exists", mem.Name, mem.Type)
	}

	// Set timestamps
	now := time.Now()
	mem.CreatedAt = now
	mem.UpdatedAt = now

	if err := s.save(mem); err != nil {
		return err
	}

	// Index the new memory
	if s.searchIndex != nil {
		_ = s.searchIndex.Index(mem) // Best effort index
	}

	return nil
}

// Read reads a memory by name and type
func (s *Store) Read(name string, memType MemoryType) (*Memory, error) {
	path := s.getPath(name, memType)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("memory '%s' not found", name)
		}
		return nil, fmt.Errorf("failed to read memory: %w", err)
	}

	var mem Memory
	if err := yaml.Unmarshal(data, &mem); err != nil {
		return nil, fmt.Errorf("failed to parse memory: %w", err)
	}

	return &mem, nil
}

// ReadByName reads a memory by name, searching all types
func (s *Store) ReadByName(name string) (*Memory, error) {
	for _, t := range ValidMemoryTypes {
		if mem, err := s.Read(name, t); err == nil {
			return mem, nil
		}
	}
	return nil, fmt.Errorf("memory '%s' not found in any type", name)
}

// Update updates an existing memory
func (s *Store) Update(mem *Memory) error {
	s.reindexMu.RLock()
	defer s.reindexMu.RUnlock()

	// Check if exists
	existing, err := s.Read(mem.Name, mem.Type)
	if err != nil {
		return err
	}

	// Preserve created_at
	mem.CreatedAt = existing.CreatedAt
	mem.UpdatedAt = time.Now()

	if err := s.save(mem); err != nil {
		return err
	}

	// Update the search index
	if s.searchIndex != nil {
		_ = s.searchIndex.Index(mem) // Best effort index
	}

	return nil
}

// Delete deletes a memory
func (s *Store) Delete(name string, memType MemoryType) error {
	s.reindexMu.RLock()
	defer s.reindexMu.RUnlock()

	path := s.getPath(name, memType)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("memory '%s' not found", name)
		}
		return fmt.Errorf("failed to delete memory: %w", err)
	}

	// Remove from search index
	if s.searchIndex != nil {
		_ = s.searchIndex.Delete(name) // Best effort delete from index
	}

	return nil
}

// DeleteByName deletes a memory by name, searching all types
func (s *Store) DeleteByName(name string) error {
	s.reindexMu.RLock()
	defer s.reindexMu.RUnlock()

	for _, t := range ValidMemoryTypes {
		path := s.getPath(name, t)
		if _, err := os.Stat(path); err == nil {
			if err := os.Remove(path); err != nil {
				return err
			}
			// Remove from search index
			if s.searchIndex != nil {
				_ = s.searchIndex.Delete(name) // Best effort delete from index
			}
			return nil
		}
	}
	return fmt.Errorf("memory '%s' not found in any type", name)
}

// List lists all memories, optionally filtered by type
func (s *Store) List(filterType MemoryType) (*MemoryList, error) {
	var memories []Memory

	types := ValidMemoryTypes
	if filterType != "" {
		if !IsValidType(filterType) {
			return nil, fmt.Errorf("invalid memory type: %s", filterType)
		}
		types = []MemoryType{filterType}
	}

	for _, t := range types {
		typeDir := filepath.Join(s.basePath, GetTypeDir(t))
		entries, err := os.ReadDir(typeDir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to read directory: %w", err)
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
				continue
			}

			name := strings.TrimSuffix(entry.Name(), ".yaml")
			mem, err := s.Read(name, t)
			if err != nil {
				continue
			}
			memories = append(memories, *mem)
		}
	}

	return &MemoryList{
		Memories: memories,
		Total:    len(memories),
		Type:     string(filterType),
	}, nil
}

// Search searches memories using full-text search
func (s *Store) Search(query string) (*MemoryList, error) {
	// If search index is available, use bleve for better results
	if s.searchIndex != nil {
		return s.searchWithBleve(query)
	}

	// Fallback to simple string matching
	return s.searchSimple(query)
}

// searchWithBleve performs full-text search using bleve
func (s *Store) searchWithBleve(query string) (*MemoryList, error) {
	results, err := s.searchIndex.Search(query, 50)
	if err != nil {
		// Fallback to simple search on error
		return s.searchSimple(query)
	}

	var memories []Memory
	for _, result := range results {
		// Load the full memory
		mem, err := s.ReadByName(result.Name)
		if err != nil {
			continue
		}
		memories = append(memories, *mem)
	}

	return &MemoryList{
		Memories: memories,
		Total:    len(memories),
	}, nil
}

// SearchByType searches memories within a specific type using full-text search
func (s *Store) SearchByType(query string, memType MemoryType) (*MemoryList, error) {
	if s.searchIndex != nil {
		results, err := s.searchIndex.SearchByType(query, memType, 50)
		if err == nil {
			var memories []Memory
			for _, result := range results {
				mem, err := s.Read(result.Name, memType)
				if err != nil {
					continue
				}
				memories = append(memories, *mem)
			}
			return &MemoryList{
				Memories: memories,
				Total:    len(memories),
				Type:     string(memType),
			}, nil
		}
	}

	// Fallback: list by type and filter
	all, err := s.List(memType)
	if err != nil {
		return nil, err
	}

	query = strings.ToLower(query)
	var matches []Memory
	for _, mem := range all.Memories {
		if strings.Contains(strings.ToLower(mem.Name), query) ||
			strings.Contains(strings.ToLower(mem.Content), query) ||
			strings.Contains(strings.ToLower(mem.Description), query) {
			matches = append(matches, mem)
		}
	}

	return &MemoryList{
		Memories: matches,
		Total:    len(matches),
		Type:     string(memType),
	}, nil
}

// searchSimple performs simple string matching search (fallback)
func (s *Store) searchSimple(query string) (*MemoryList, error) {
	all, err := s.List("")
	if err != nil {
		return nil, err
	}

	query = strings.ToLower(query)
	var matches []Memory

	for _, mem := range all.Memories {
		// Search in name, content, description, and tags
		if strings.Contains(strings.ToLower(mem.Name), query) ||
			strings.Contains(strings.ToLower(mem.Content), query) ||
			strings.Contains(strings.ToLower(mem.Description), query) {
			matches = append(matches, mem)
			continue
		}

		// Search in tags
		for _, tag := range mem.Tags {
			if strings.Contains(strings.ToLower(tag), query) {
				matches = append(matches, mem)
				break
			}
		}
	}

	return &MemoryList{
		Memories: matches,
		Total:    len(matches),
	}, nil
}

// Close closes the store and its resources.
//
// Close marks the store as closed (so further Reindex calls fail fast) and
// then blocks until any in-flight Reindex completes before closing the
// underlying bleve index. Callers that want to bound the wait should cancel
// the Reindex context themselves.
func (s *Store) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.closedMu.Lock()
		s.closed = true
		s.closedMu.Unlock()

		// Wait for any in-flight Reindex to drain. Callers can bound this
		// by cancelling the context they passed to Reindex.
		s.reindexWG.Wait()

		if s.searchIndex != nil {
			closeErr = s.searchIndex.Close()
		}
	})
	return closeErr
}

// RebuildIndex rebuilds the search index from scratch.
//
// Deprecated: use Reindex(ctx) for cancellable rebuilds. RebuildIndex calls
// Reindex with a background context.
func (s *Store) RebuildIndex() error {
	if s.searchIndex == nil {
		return fmt.Errorf("search index not initialized")
	}
	return s.Reindex(context.Background())
}

// save writes a memory to disk
func (s *Store) save(mem *Memory) error {
	path := s.getPath(mem.Name, mem.Type)

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := yaml.Marshal(mem)
	if err != nil {
		return fmt.Errorf("failed to marshal memory: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write memory: %w", err)
	}

	return nil
}

// getPath returns the file path for a memory
func (s *Store) getPath(name string, memType MemoryType) string {
	return filepath.Join(s.basePath, GetTypeDir(memType), name+".yaml")
}
