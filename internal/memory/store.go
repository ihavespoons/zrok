package memory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ihavespoons/zrok/internal/project"
	"gopkg.in/yaml.v3"
)

// Store handles memory CRUD operations
type Store struct {
	basePath    string
	searchIndex *SearchIndex
}

// NewStore creates a new memory store for the given project
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

	// Reindex existing memories if search index was created
	if searchIndex != nil {
		go store.reindexAll()
	}

	return store
}

// reindexAll rebuilds the search index from all existing memories
func (s *Store) reindexAll() {
	if s.searchIndex == nil {
		return
	}

	all, err := s.List("")
	if err != nil {
		return
	}

	_ = s.searchIndex.Reindex(all.Memories) // Best effort reindex
}

// Create creates a new memory
func (s *Store) Create(mem *Memory) error {
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

// Close closes the store and its resources
func (s *Store) Close() error {
	if s.searchIndex != nil {
		return s.searchIndex.Close()
	}
	return nil
}

// RebuildIndex rebuilds the search index from scratch
func (s *Store) RebuildIndex() error {
	if s.searchIndex == nil {
		return fmt.Errorf("search index not initialized")
	}

	all, err := s.List("")
	if err != nil {
		return err
	}

	return s.searchIndex.Reindex(all.Memories)
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
