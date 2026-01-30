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
	basePath string
}

// NewStore creates a new memory store for the given project
func NewStore(p *project.Project) *Store {
	return &Store{
		basePath: p.GetMemoriesPath(),
	}
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

	return s.save(mem)
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

	return s.save(mem)
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
	return nil
}

// DeleteByName deletes a memory by name, searching all types
func (s *Store) DeleteByName(name string) error {
	for _, t := range ValidMemoryTypes {
		path := s.getPath(name, t)
		if _, err := os.Stat(path); err == nil {
			return os.Remove(path)
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

// Search searches memories by query string
func (s *Store) Search(query string) (*MemoryList, error) {
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
