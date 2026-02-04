package navigate

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ihavespoons/zrok/internal/project"
)

// Finder handles file and content search operations
type Finder struct {
	project *project.Project
}

// NewFinder creates a new file finder
func NewFinder(p *project.Project) *Finder {
	return &Finder{project: p}
}

// FindResult contains matches from a find operation
type FindResult struct {
	Pattern string      `json:"pattern"`
	Matches []FileInfo  `json:"matches"`
	Total   int         `json:"total"`
}

// SearchMatch represents a single search match in a file
type SearchMatch struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Column     int    `json:"column,omitempty"`
	Content    string `json:"content"`
	Context    string `json:"context,omitempty"`
}

// SearchResult contains matches from a content search operation
type SearchResult struct {
	Pattern string        `json:"pattern"`
	Matches []SearchMatch `json:"matches"`
	Total   int           `json:"total"`
	Files   int           `json:"files"`
}

// FindOptions contains options for finding files
type FindOptions struct {
	Type      string // "file", "dir", or empty for both
	MaxDepth  int
	IgnoreCase bool
}

// SearchOptions contains options for content search
type SearchOptions struct {
	Regex      bool
	IgnoreCase bool
	MaxResults int
	Context    int // lines of context
	FilePattern string // glob pattern to filter files
}

// Find finds files matching a pattern
func (f *Finder) Find(pattern string, opts *FindOptions) (*FindResult, error) {
	if opts == nil {
		opts = &FindOptions{}
	}

	var matches []FileInfo
	var matcher func(string) bool

	// Prepare pattern matcher
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		// Glob pattern
		matcher = func(name string) bool {
			matched, _ := filepath.Match(pattern, name)
			if opts.IgnoreCase && !matched {
				matched, _ = filepath.Match(strings.ToLower(pattern), strings.ToLower(name))
			}
			return matched
		}
	} else {
		// Simple substring match
		matcher = func(name string) bool {
			if opts.IgnoreCase {
				return strings.Contains(strings.ToLower(name), strings.ToLower(pattern))
			}
			return strings.Contains(name, pattern)
		}
	}

	err := filepath.Walk(f.project.RootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		// Get relative path
		relPath, _ := filepath.Rel(f.project.RootPath, path)
		if relPath == "." {
			return nil
		}

		// Skip ignored directories
		if info.IsDir() && f.shouldIgnore(info.Name()) {
			return filepath.SkipDir
		}

		// Check depth
		if opts.MaxDepth > 0 {
			depth := strings.Count(relPath, string(os.PathSeparator))
			if depth >= opts.MaxDepth {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		// Filter by type
		if opts.Type == "file" && info.IsDir() {
			return nil
		}
		if opts.Type == "dir" && !info.IsDir() {
			return nil
		}

		// Check pattern match
		if matcher(info.Name()) {
			matches = append(matches, FileInfo{
				Name:    info.Name(),
				Path:    relPath,
				Size:    info.Size(),
				IsDir:   info.IsDir(),
				ModTime: info.ModTime().Unix(),
				Mode:    info.Mode().String(),
			})
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("find error: %w", err)
	}

	return &FindResult{
		Pattern: pattern,
		Matches: matches,
		Total:   len(matches),
	}, nil
}

// Search searches for a pattern in file contents
func (f *Finder) Search(pattern string, opts *SearchOptions) (*SearchResult, error) {
	if opts == nil {
		opts = &SearchOptions{}
	}

	var regex *regexp.Regexp
	var err error

	if opts.Regex {
		flags := ""
		if opts.IgnoreCase {
			flags = "(?i)"
		}
		regex, err = regexp.Compile(flags + pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	var matches []SearchMatch
	filesSearched := make(map[string]bool)

	err = filepath.Walk(f.project.RootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip directories
		if info.IsDir() {
			if f.shouldIgnore(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		// Check file pattern if specified
		if opts.FilePattern != "" {
			matched, _ := filepath.Match(opts.FilePattern, info.Name())
			if !matched {
				return nil
			}
		}

		// Skip binary and large files
		if !f.isSearchable(info) {
			return nil
		}

		// Get relative path
		relPath, _ := filepath.Rel(f.project.RootPath, path)

		// Search file
		fileMatches, err := f.searchFile(path, relPath, pattern, regex, opts)
		if err != nil {
			return nil // Skip files with errors
		}

		if len(fileMatches) > 0 {
			filesSearched[relPath] = true
			matches = append(matches, fileMatches...)

			// Check max results
			if opts.MaxResults > 0 && len(matches) >= opts.MaxResults {
				return filepath.SkipAll
			}
		}

		return nil
	})

	if err != nil && err != filepath.SkipAll {
		return nil, fmt.Errorf("search error: %w", err)
	}

	// Truncate to max results
	if opts.MaxResults > 0 && len(matches) > opts.MaxResults {
		matches = matches[:opts.MaxResults]
	}

	return &SearchResult{
		Pattern: pattern,
		Matches: matches,
		Total:   len(matches),
		Files:   len(filesSearched),
	}, nil
}

func (f *Finder) searchFile(fullPath, relPath, pattern string, regex *regexp.Regexp, opts *SearchOptions) ([]SearchMatch, error) {
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var matches []SearchMatch
	var lines []string
	scanner := bufio.NewScanner(file)

	// Read all lines for context support
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	for i, line := range lines {
		lineNum := i + 1
		var found bool
		var col int

		if regex != nil {
			loc := regex.FindStringIndex(line)
			if loc != nil {
				found = true
				col = loc[0] + 1
			}
		} else {
			searchLine := line
			searchPattern := pattern
			if opts.IgnoreCase {
				searchLine = strings.ToLower(line)
				searchPattern = strings.ToLower(pattern)
			}
			idx := strings.Index(searchLine, searchPattern)
			if idx >= 0 {
				found = true
				col = idx + 1
			}
		}

		if found {
			match := SearchMatch{
				File:    relPath,
				Line:    lineNum,
				Column:  col,
				Content: strings.TrimSpace(line),
			}

			// Add context if requested
			if opts.Context > 0 {
				var contextLines []string
				start := i - opts.Context
				if start < 0 {
					start = 0
				}
				end := i + opts.Context + 1
				if end > len(lines) {
					end = len(lines)
				}
				for j := start; j < end; j++ {
					prefix := "  "
					if j == i {
						prefix = "> "
					}
					contextLines = append(contextLines, fmt.Sprintf("%s%d: %s", prefix, j+1, lines[j]))
				}
				match.Context = strings.Join(contextLines, "\n")
			}

			matches = append(matches, match)
		}
	}

	return matches, nil
}

// shouldIgnore checks if a directory should be ignored
func (f *Finder) shouldIgnore(name string) bool {
	ignorePatterns := []string{
		"node_modules",
		"vendor",
		".git",
		".zrok",
		"__pycache__",
		".pytest_cache",
		".mypy_cache",
		"target",
		"dist",
		"build",
		".next",
		".nuxt",
		"coverage",
		".idea",
		".vscode",
	}

	if strings.HasPrefix(name, ".") {
		return true
	}

	for _, pattern := range ignorePatterns {
		if name == pattern {
			return true
		}
	}
	return false
}

// isSearchable checks if a file should be searched
func (f *Finder) isSearchable(info os.FileInfo) bool {
	// Skip large files (> 1MB)
	if info.Size() > 1024*1024 {
		return false
	}

	// Check extension
	ext := strings.ToLower(filepath.Ext(info.Name()))

	// Binary extensions to skip
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".dat": true, ".db": true, ".sqlite": true,
		".zip": true, ".tar": true, ".gz": true, ".rar": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".ico": true, ".svg": true, ".webp": true,
		".pdf": true, ".doc": true, ".docx": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
		".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
		".lock": true,
	}

	return !binaryExts[ext]
}
