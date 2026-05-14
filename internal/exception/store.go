package exception

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/finding"
	"github.com/diffsec/quokka/internal/project"
	"gopkg.in/yaml.v3"
)

// fileName is the on-disk file under .quokka/ holding all exceptions.
const fileName = "exceptions.yaml"

// Store persists exceptions to .quokka/exceptions.yaml. All operations are
// file-locked at the OS level only by atomic-replace semantics — the store
// reads, mutates in memory, and writes the full file back. For quokka's
// expected scale (dozens, maybe hundreds of exceptions) this is fine and
// keeps the API simple.
type Store struct {
	path string
}

// NewStore creates a new exception store rooted at the given project.
func NewStore(p *project.Project) *Store {
	return &Store{path: filepath.Join(p.GetQuokkaPath(), fileName)}
}

// fileShape is the on-disk YAML layout. Wrapping the list in a struct keeps
// the file extensible (e.g. future schema_version field) without rewriting.
type fileShape struct {
	SchemaVersion int         `yaml:"schema_version"`
	Exceptions    []Exception `yaml:"exceptions"`
}

const schemaVersion = 1

// Load reads all exceptions from disk. Missing file is not an error —
// returns an empty store.
func (s *Store) Load() ([]Exception, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read exceptions file: %w", err)
	}
	var f fileShape
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse exceptions file: %w", err)
	}
	return f.Exceptions, nil
}

// List returns all exceptions, optionally filtering out expired entries.
func (s *Store) List(includeExpired bool) ([]Exception, error) {
	all, err := s.Load()
	if err != nil {
		return nil, err
	}
	if includeExpired {
		return all, nil
	}
	now := time.Now()
	out := all[:0]
	for _, e := range all {
		if !e.IsExpired(now) {
			out = append(out, e)
		}
	}
	return out, nil
}

// Add appends a new exception. ID is generated if not provided. Returns
// the stored exception (with ID populated).
func (s *Store) Add(e Exception) (Exception, error) {
	if err := e.Validate(); err != nil {
		return Exception{}, err
	}
	all, err := s.Load()
	if err != nil {
		return Exception{}, err
	}
	if e.ID == "" {
		e.ID = nextID(all)
	} else {
		for _, existing := range all {
			if existing.ID == e.ID {
				return Exception{}, fmt.Errorf("exception %q already exists", e.ID)
			}
		}
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	all = append(all, e)
	if err := s.save(all); err != nil {
		return Exception{}, err
	}
	return e, nil
}

// Remove deletes an exception by ID. Returns an error if not found.
func (s *Store) Remove(id string) error {
	all, err := s.Load()
	if err != nil {
		return err
	}
	idx := -1
	for i, e := range all {
		if e.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("exception %q not found", id)
	}
	all = append(all[:idx], all[idx+1:]...)
	return s.save(all)
}

// Expire removes all exceptions whose expires date is in the past. Returns
// the IDs that were removed.
func (s *Store) Expire() ([]string, error) {
	all, err := s.Load()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var kept []Exception
	var removed []string
	for _, e := range all {
		if e.IsExpired(now) {
			removed = append(removed, e.ID)
			continue
		}
		kept = append(kept, e)
	}
	if len(removed) == 0 {
		return nil, nil
	}
	if err := s.save(kept); err != nil {
		return nil, err
	}
	return removed, nil
}

// Match returns the first non-expired exception that suppresses the given
// finding, or nil if none match. A nil store (uninitialized project) is
// treated as no exceptions.
func (s *Store) Match(f finding.Finding) (*Exception, error) {
	if s == nil {
		return nil, nil
	}
	all, err := s.List(false)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if matches(all[i], f) {
			return &all[i], nil
		}
	}
	return nil, nil
}

func matches(e Exception, f finding.Finding) bool {
	if e.IsFingerprint() {
		return e.Fingerprint != "" && e.Fingerprint == f.Fingerprint
	}
	if e.IsPattern() {
		if !strings.EqualFold(e.CWE, f.CWE) {
			return false
		}
		ok, err := filepath.Match(e.PathGlob, f.Location.File)
		if err == nil && ok {
			return true
		}
		// Convenience: also match against the base filename so users can
		// write "tests/*.py" and have it apply across nested dirs without
		// remembering to prefix.
		if ok2, err2 := filepath.Match(e.PathGlob, filepath.Base(f.Location.File)); err2 == nil && ok2 {
			return true
		}
	}
	return false
}

// save writes the full list back to disk via tempfile + rename (atomic).
func (s *Store) save(all []Exception) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return fmt.Errorf("mkdir for exceptions file: %w", err)
	}
	data, err := yaml.Marshal(fileShape{SchemaVersion: schemaVersion, Exceptions: all})
	if err != nil {
		return fmt.Errorf("marshal exceptions: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("write exceptions file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("rename exceptions file: %w", err)
	}
	return nil
}

// nextID returns "EXC-001" style auto-incremented identifiers.
func nextID(existing []Exception) string {
	maxN := 0
	for _, e := range existing {
		if !strings.HasPrefix(e.ID, "EXC-") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(e.ID, "EXC-"))
		if err == nil && n > maxN {
			maxN = n
		}
	}
	return fmt.Sprintf("EXC-%03d", maxN+1)
}

// SortByExpires sorts in place, oldest expires date first. Convenience for
// CLI output and judge-agent prioritization.
func SortByExpires(list []Exception) {
	sort.Slice(list, func(i, j int) bool { return list[i].Expires.Before(list[j].Expires) })
}
