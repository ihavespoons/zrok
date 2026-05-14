package finding

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ihavespoons/quokka/internal/project"
	"gopkg.in/yaml.v3"
)

// Store handles finding CRUD operations
type Store struct {
	basePath    string
	rawPath     string
	exportsPath string
}

// NewStore creates a new finding store for the given project
func NewStore(p *project.Project) *Store {
	basePath := p.GetFindingsPath()
	return &Store{
		basePath:    basePath,
		rawPath:     filepath.Join(basePath, project.RawDir),
		exportsPath: filepath.Join(basePath, project.ExportsDir),
	}
}

// Create creates a new finding.
//
// Dedup: if a finding with the same fingerprint AND the same created_by
// already exists in the store, Create silently no-ops and the caller's
// passed-in struct is mutated to reflect the existing finding (ID,
// timestamps, fingerprint). This matches what callers reasonably expect
// when an LLM agent files the same vuln twice in a single run — the
// store should hold one row, not N. Dedup is scoped to "same creator"
// deliberately: when two different agents independently flag the same
// vuln, that's a confidence signal worth preserving until the validation
// phase consolidates them.
func (s *Store) Create(f *Finding) error {
	// Validate first so a malformed input can't even attempt dedup.
	if err := s.validate(f); err != nil {
		return err
	}

	// Compute fingerprint up-front so dedup check sees the same hash
	// that gets persisted (no double computation).
	f.Fingerprint = Fingerprint(*f)

	// Dedup: same fingerprint + same created_by → return existing.
	// CreatedBy="" findings (legacy / unattributed) skip dedup since the
	// match would be too coarse — any two unattributed findings on the
	// same CWE+file would collapse, which discards signal.
	if f.CreatedBy != "" {
		if existing, found, err := s.findByFingerprintAndCreator(f.Fingerprint, f.CreatedBy); err != nil {
			return err
		} else if found {
			*f = *existing
			return nil
		}
	}

	// Generate ID if not provided
	if f.ID == "" {
		id, err := s.generateID()
		if err != nil {
			return err
		}
		f.ID = id
	}

	// Check if already exists
	if _, err := s.Read(f.ID); err == nil {
		return fmt.Errorf("finding '%s' already exists", f.ID)
	}

	// Set defaults and timestamps
	if f.Status == "" {
		f.Status = StatusOpen
	}
	now := time.Now()
	f.CreatedAt = now
	f.UpdatedAt = now

	return s.save(f)
}

// findByFingerprintAndCreator returns the first stored finding with the
// given fingerprint+creator pair. Used by Create() to no-op a duplicate
// file from the same agent. Returns (nil, false, nil) when no match
// exists — that's the common case.
func (s *Store) findByFingerprintAndCreator(fingerprint, createdBy string) (*Finding, bool, error) {
	if fingerprint == "" || createdBy == "" {
		return nil, false, nil
	}
	result, err := s.List(&FilterOptions{CreatedBy: createdBy})
	if err != nil {
		return nil, false, fmt.Errorf("dedup lookup: %w", err)
	}
	for i := range result.Findings {
		existing := &result.Findings[i]
		// Some stored findings may pre-date the fingerprint field; recompute
		// rather than trust .Fingerprint blindly so dedup catches them too.
		fp := existing.Fingerprint
		if fp == "" {
			fp = Fingerprint(*existing)
		}
		if fp == fingerprint {
			return existing, true, nil
		}
	}
	return nil, false, nil
}

// Read reads a finding by ID
func (s *Store) Read(id string) (*Finding, error) {
	path := s.getPath(id)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("finding '%s' not found", id)
		}
		return nil, fmt.Errorf("failed to read finding: %w", err)
	}

	var f Finding
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse finding: %w", err)
	}

	if f.Fingerprint == "" {
		f.Fingerprint = Fingerprint(f)
	}

	return &f, nil
}

// Update updates an existing finding
func (s *Store) Update(f *Finding) error {
	// Check if exists
	existing, err := s.Read(f.ID)
	if err != nil {
		return err
	}

	// Validate
	if err := s.validate(f); err != nil {
		return err
	}

	// Preserve created_at
	f.CreatedAt = existing.CreatedAt
	f.UpdatedAt = time.Now()
	f.Fingerprint = Fingerprint(*f)

	return s.save(f)
}

// Delete deletes a finding
func (s *Store) Delete(id string) error {
	path := s.getPath(id)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("finding '%s' not found", id)
		}
		return fmt.Errorf("failed to delete finding: %w", err)
	}
	return nil
}

// List lists all findings, optionally filtered
func (s *Store) List(opts *FilterOptions) (*FindingList, error) {
	entries, err := os.ReadDir(s.rawPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &FindingList{Findings: []Finding{}, Total: 0}, nil
		}
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var findings []Finding
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		id := strings.TrimSuffix(entry.Name(), ".yaml")
		f, err := s.Read(id)
		if err != nil {
			continue
		}

		// Apply filters
		if opts != nil {
			if opts.Severity != "" && f.Severity != opts.Severity {
				continue
			}
			if opts.Status != "" && f.Status != opts.Status {
				continue
			}
			if opts.Confidence != "" && f.Confidence != opts.Confidence {
				continue
			}
			if opts.Exploitability != "" && f.Exploitability != opts.Exploitability {
				continue
			}
			if opts.FixPriority != "" && f.FixPriority != opts.FixPriority {
				continue
			}
			if opts.CWE != "" && f.CWE != opts.CWE {
				continue
			}
			if opts.File != "" && f.Location.File != opts.File {
				continue
			}
			if opts.Tag != "" && !containsTag(f.Tags, opts.Tag) {
				continue
			}
			if opts.CreatedBy != "" && f.CreatedBy != opts.CreatedBy {
				continue
			}
		}

		findings = append(findings, *f)
	}

	// Sort by severity (critical first), then by created_at (newest first)
	sort.Slice(findings, func(i, j int) bool {
		wi := SeverityWeight(findings[i].Severity)
		wj := SeverityWeight(findings[j].Severity)
		if wi != wj {
			return wi > wj
		}
		return findings[i].CreatedAt.After(findings[j].CreatedAt)
	})

	return &FindingList{
		Findings: findings,
		Total:    len(findings),
	}, nil
}

// Stats calculates statistics about findings
func (s *Store) Stats() (*FindingStats, error) {
	all, err := s.List(nil)
	if err != nil {
		return nil, err
	}

	stats := &FindingStats{
		Total:            all.Total,
		BySeverity:       make(map[string]int),
		ByStatus:         make(map[string]int),
		ByConfidence:     make(map[string]int),
		ByExploitability: make(map[string]int),
		ByFixPriority:    make(map[string]int),
		ByCWE:            make(map[string]int),
		ByCreatedBy:      make(map[string]int),
	}

	tagCounts := make(map[string]int)

	for _, f := range all.Findings {
		stats.BySeverity[string(f.Severity)]++
		stats.ByStatus[string(f.Status)]++
		stats.ByConfidence[string(f.Confidence)]++
		if f.Exploitability != "" {
			stats.ByExploitability[string(f.Exploitability)]++
		}
		if f.FixPriority != "" {
			stats.ByFixPriority[string(f.FixPriority)]++
		}
		if f.CWE != "" {
			stats.ByCWE[f.CWE]++
		}
		if f.CreatedBy != "" {
			stats.ByCreatedBy[f.CreatedBy]++
		}
		for _, tag := range f.Tags {
			tagCounts[tag]++
		}
	}

	// Get top tags
	var tags []TagCount
	for tag, count := range tagCounts {
		tags = append(tags, TagCount{Tag: tag, Count: count})
	}
	sort.Slice(tags, func(i, j int) bool {
		return tags[i].Count > tags[j].Count
	})
	if len(tags) > 10 {
		tags = tags[:10]
	}
	stats.TopTags = tags

	return stats, nil
}

// Import imports a finding from a file
func (s *Store) Import(path string) (*Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var f Finding
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse finding: %w", err)
	}

	// Generate new ID if importing
	f.ID = ""
	if err := s.Create(&f); err != nil {
		return nil, err
	}

	return &f, nil
}

// GetExportsPath returns the exports directory path
func (s *Store) GetExportsPath() string {
	return s.exportsPath
}

// save writes a finding to disk
func (s *Store) save(f *Finding) error {
	path := s.getPath(f.ID)

	// Ensure directory exists
	if err := os.MkdirAll(s.rawPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("failed to marshal finding: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write finding: %w", err)
	}

	return nil
}

// getPath returns the file path for a finding
func (s *Store) getPath(id string) string {
	return filepath.Join(s.rawPath, id+".yaml")
}

// generateID generates a new finding ID
func (s *Store) generateID() (string, error) {
	entries, err := os.ReadDir(s.rawPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "FIND-001", nil
		}
		return "", fmt.Errorf("failed to read directory: %w", err)
	}

	maxNum := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".yaml")
		if strings.HasPrefix(name, "FIND-") {
			numStr := strings.TrimPrefix(name, "FIND-")
			if num, err := strconv.Atoi(numStr); err == nil && num > maxNum {
				maxNum = num
			}
		}
	}

	return fmt.Sprintf("FIND-%03d", maxNum+1), nil
}

// validate validates a finding. It normalizes case for severity/confidence
// to lowercase, defaults empty confidence to "medium", and rejects invalid
// values. It also logs a warning to stderr when CWE is empty.
func (s *Store) validate(f *Finding) error {
	if f.Title == "" {
		return fmt.Errorf("title is required")
	}
	// Normalize severity to lowercase before validation
	if f.Severity != "" {
		f.Severity = Severity(strings.ToLower(string(f.Severity)))
		if !IsValidSeverity(f.Severity) {
			return fmt.Errorf("invalid severity: %s (valid: critical, high, medium, low, info)", f.Severity)
		}
	}
	// Normalize confidence; default empty to medium
	if f.Confidence == "" {
		f.Confidence = ConfidenceMedium
	} else {
		f.Confidence = Confidence(strings.ToLower(string(f.Confidence)))
		if !IsValidConfidence(f.Confidence) {
			return fmt.Errorf("invalid confidence: %s (valid: high, medium, low)", f.Confidence)
		}
	}
	if f.Status != "" && !IsValidStatus(f.Status) {
		return fmt.Errorf("invalid status: %s", f.Status)
	}
	if f.Exploitability != "" && !IsValidExploitability(f.Exploitability) {
		return fmt.Errorf("invalid exploitability: %s", f.Exploitability)
	}
	if f.FixPriority != "" && !IsValidFixPriority(f.FixPriority) {
		return fmt.Errorf("invalid fix_priority: %s", f.FixPriority)
	}
	if f.Location.File == "" {
		return fmt.Errorf("location.file is required")
	}
	if f.Location.LineStart < 1 {
		return fmt.Errorf("location.line_start must be >= 1, got %d", f.Location.LineStart)
	}
	if f.CWE == "" {
		fmt.Fprintf(os.Stderr, "warning: finding %q has no CWE\n", f.Title)
	}
	return nil
}

func containsTag(tags []string, tag string) bool {
	tag = strings.ToLower(tag)
	for _, t := range tags {
		if strings.ToLower(t) == tag {
			return true
		}
	}
	return false
}
