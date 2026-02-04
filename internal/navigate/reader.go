package navigate

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ihavespoons/zrok/internal/project"
)

// Reader handles file reading operations
type Reader struct {
	project *project.Project
}

// NewReader creates a new file reader
func NewReader(p *project.Project) *Reader {
	return &Reader{project: p}
}

// ReadResult contains the result of a file read operation
type ReadResult struct {
	Path       string   `json:"path"`
	Content    string   `json:"content"`
	Lines      []string `json:"lines,omitempty"`
	TotalLines int      `json:"total_lines"`
	StartLine  int      `json:"start_line,omitempty"`
	EndLine    int      `json:"end_line,omitempty"`
}

// Read reads a file and returns its contents
func (r *Reader) Read(path string) (*ReadResult, error) {
	fullPath := r.resolvePath(path)

	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	lines := strings.Split(string(content), "\n")

	return &ReadResult{
		Path:       path,
		Content:    string(content),
		Lines:      lines,
		TotalLines: len(lines),
		StartLine:  1,
		EndLine:    len(lines),
	}, nil
}

// ReadLines reads specific lines from a file
func (r *Reader) ReadLines(path string, start, end int) (*ReadResult, error) {
	fullPath := r.resolvePath(path)

	file, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var lines []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		if lineNum >= start && lineNum <= end {
			lines = append(lines, scanner.Text())
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if start > lineNum {
		return nil, fmt.Errorf("start line %d exceeds file length %d", start, lineNum)
	}

	// Adjust end if it exceeds file length
	actualEnd := end
	if end > lineNum {
		actualEnd = lineNum
	}

	return &ReadResult{
		Path:       path,
		Content:    strings.Join(lines, "\n"),
		Lines:      lines,
		TotalLines: lineNum,
		StartLine:  start,
		EndLine:    actualEnd,
	}, nil
}

// ReadContext reads lines around a specific line (for context)
func (r *Reader) ReadContext(path string, line, contextLines int) (*ReadResult, error) {
	start := line - contextLines
	if start < 1 {
		start = 1
	}
	end := line + contextLines

	return r.ReadLines(path, start, end)
}

// Exists checks if a file exists
func (r *Reader) Exists(path string) bool {
	fullPath := r.resolvePath(path)
	_, err := os.Stat(fullPath)
	return err == nil
}

// GetInfo returns file information
func (r *Reader) GetInfo(path string) (*FileInfo, error) {
	fullPath := r.resolvePath(path)

	info, err := os.Stat(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	return &FileInfo{
		Name:    info.Name(),
		Path:    path,
		Size:    info.Size(),
		IsDir:   info.IsDir(),
		ModTime: info.ModTime().Unix(),
		Mode:    info.Mode().String(),
	}, nil
}

// resolvePath resolves a path relative to the project root
func (r *Reader) resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(r.project.RootPath, path)
}

// FileInfo contains metadata about a file
type FileInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime int64  `json:"mod_time"`
	Mode    string `json:"mode"`
}
