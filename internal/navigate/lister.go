package navigate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ihavespoons/zrok/internal/project"
)

// Lister handles directory listing operations
type Lister struct {
	project *project.Project
}

// NewLister creates a new directory lister
func NewLister(p *project.Project) *Lister {
	return &Lister{project: p}
}

// ListResult contains the result of a directory listing
type ListResult struct {
	Path    string     `json:"path"`
	Entries []FileInfo `json:"entries"`
	Total   int        `json:"total"`
}

// ListOptions contains options for listing directories
type ListOptions struct {
	Recursive  bool
	MaxDepth   int
	ShowHidden bool
	DirsOnly   bool
	FilesOnly  bool
}

// List lists the contents of a directory
func (l *Lister) List(path string, opts *ListOptions) (*ListResult, error) {
	if opts == nil {
		opts = &ListOptions{}
	}

	fullPath := l.resolvePath(path)

	info, err := os.Stat(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access path: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", path)
	}

	var entries []FileInfo

	if opts.Recursive {
		entries, err = l.listRecursive(fullPath, path, opts, 0)
	} else {
		entries, err = l.listDir(fullPath, path, opts)
	}

	if err != nil {
		return nil, err
	}

	// Sort entries: directories first, then alphabetically
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return entries[i].Name < entries[j].Name
	})

	return &ListResult{
		Path:    path,
		Entries: entries,
		Total:   len(entries),
	}, nil
}

func (l *Lister) listDir(fullPath, relPath string, opts *ListOptions) ([]FileInfo, error) {
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var result []FileInfo
	for _, entry := range entries {
		name := entry.Name()

		// Skip hidden files if not requested
		if !opts.ShowHidden && strings.HasPrefix(name, ".") {
			continue
		}

		// Skip common ignore patterns
		if l.shouldIgnore(name) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Filter by type
		if opts.DirsOnly && !info.IsDir() {
			continue
		}
		if opts.FilesOnly && info.IsDir() {
			continue
		}

		entryPath := filepath.Join(relPath, name)
		result = append(result, FileInfo{
			Name:    name,
			Path:    entryPath,
			Size:    info.Size(),
			IsDir:   info.IsDir(),
			ModTime: info.ModTime().Unix(),
			Mode:    info.Mode().String(),
		})
	}

	return result, nil
}

func (l *Lister) listRecursive(fullPath, relPath string, opts *ListOptions, depth int) ([]FileInfo, error) {
	if opts.MaxDepth > 0 && depth >= opts.MaxDepth {
		return nil, nil
	}

	entries, err := l.listDir(fullPath, relPath, opts)
	if err != nil {
		return nil, err
	}

	var result []FileInfo
	result = append(result, entries...)

	for _, entry := range entries {
		if entry.IsDir {
			subPath := filepath.Join(fullPath, entry.Name)
			subRelPath := filepath.Join(relPath, entry.Name)
			subEntries, err := l.listRecursive(subPath, subRelPath, opts, depth+1)
			if err != nil {
				// Log but continue
				continue
			}
			result = append(result, subEntries...)
		}
	}

	return result, nil
}

// shouldIgnore checks if a file/directory should be ignored
func (l *Lister) shouldIgnore(name string) bool {
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
	}

	for _, pattern := range ignorePatterns {
		if name == pattern {
			return true
		}
	}
	return false
}

// resolvePath resolves a path relative to the project root
func (l *Lister) resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if path == "" || path == "." {
		return l.project.RootPath
	}
	return filepath.Join(l.project.RootPath, path)
}

// Tree generates a tree representation of the directory structure
func (l *Lister) Tree(path string, maxDepth int) (string, error) {
	fullPath := l.resolvePath(path)

	var b strings.Builder
	b.WriteString(path)
	if path == "" || path == "." {
		b.WriteString(".")
	}
	b.WriteString("\n")

	if err := l.buildTree(&b, fullPath, "", maxDepth, 0); err != nil {
		return "", err
	}

	return b.String(), nil
}

func (l *Lister) buildTree(b *strings.Builder, fullPath, prefix string, maxDepth, depth int) error {
	if maxDepth > 0 && depth >= maxDepth {
		return nil
	}

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return err
	}

	// Filter and sort entries
	var filtered []os.DirEntry
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || l.shouldIgnore(name) {
			continue
		}
		filtered = append(filtered, entry)
	}

	sort.Slice(filtered, func(i, j int) bool {
		iInfo, _ := filtered[i].Info()
		jInfo, _ := filtered[j].Info()
		iIsDir := iInfo != nil && iInfo.IsDir()
		jIsDir := jInfo != nil && jInfo.IsDir()
		if iIsDir != jIsDir {
			return iIsDir
		}
		return filtered[i].Name() < filtered[j].Name()
	})

	for i, entry := range filtered {
		isLast := i == len(filtered)-1
		connector := "├── "
		if isLast {
			connector = "└── "
		}

		b.WriteString(prefix)
		b.WriteString(connector)
		b.WriteString(entry.Name())

		info, _ := entry.Info()
		if info != nil && info.IsDir() {
			b.WriteString("/")
		}
		b.WriteString("\n")

		if info != nil && info.IsDir() {
			newPrefix := prefix + "│   "
			if isLast {
				newPrefix = prefix + "    "
			}
			_ = l.buildTree(b, filepath.Join(fullPath, entry.Name()), newPrefix, maxDepth, depth+1)
		}
	}

	return nil
}
