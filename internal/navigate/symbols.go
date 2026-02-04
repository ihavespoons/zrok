package navigate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ihavespoons/zrok/internal/project"
)

// ExtractionMethod specifies how to extract symbols
type ExtractionMethod string

const (
	// MethodAuto tries LSP first, falls back to regex
	MethodAuto ExtractionMethod = "auto"
	// MethodLSP uses only LSP
	MethodLSP ExtractionMethod = "lsp"
	// MethodRegex uses only regex
	MethodRegex ExtractionMethod = "regex"
)

// ErrLSPNotAvailable indicates that LSP is not available for this file type
var ErrLSPNotAvailable = errors.New("LSP not available for this file type")

// SymbolKind represents the kind of symbol
type SymbolKind string

const (
	SymbolFunction  SymbolKind = "function"
	SymbolMethod    SymbolKind = "method"
	SymbolClass     SymbolKind = "class"
	SymbolStruct    SymbolKind = "struct"
	SymbolInterface SymbolKind = "interface"
	SymbolVariable  SymbolKind = "variable"
	SymbolConstant  SymbolKind = "constant"
	SymbolType      SymbolKind = "type"
	SymbolImport    SymbolKind = "import"
)

// Symbol represents a code symbol
type Symbol struct {
	Name      string     `json:"name"`
	Kind      SymbolKind `json:"kind"`
	File      string     `json:"file"`
	Line      int        `json:"line"`
	Signature string     `json:"signature,omitempty"`
	Parent    string     `json:"parent,omitempty"`
}

// SymbolResult contains symbols found in a file or project
type SymbolResult struct {
	File    string   `json:"file,omitempty"`
	Symbols []Symbol `json:"symbols"`
	Total   int      `json:"total"`
}

// SymbolExtractor extracts symbols from source files
type SymbolExtractor struct {
	project *project.Project
}

// NewSymbolExtractor creates a new symbol extractor
func NewSymbolExtractor(p *project.Project) *SymbolExtractor {
	return &SymbolExtractor{project: p}
}

// Extract extracts symbols from a file
func (s *SymbolExtractor) Extract(path string) (*SymbolResult, error) {
	fullPath := s.resolvePath(path)

	ext := strings.ToLower(filepath.Ext(path))
	extractor := s.getExtractor(ext)
	if extractor == nil {
		return &SymbolResult{File: path, Symbols: []Symbol{}, Total: 0}, nil
	}

	file, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	symbols, err := extractor(file, path)
	if err != nil {
		return nil, err
	}

	return &SymbolResult{
		File:    path,
		Symbols: symbols,
		Total:   len(symbols),
	}, nil
}

// Find finds a symbol by name across the project
func (s *SymbolExtractor) Find(name string) (*SymbolResult, error) {
	var allSymbols []Symbol

	err := filepath.Walk(s.project.RootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			dirName := info.Name()
			if strings.HasPrefix(dirName, ".") || s.shouldIgnore(dirName) {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if s.getExtractor(ext) == nil {
			return nil
		}

		relPath, _ := filepath.Rel(s.project.RootPath, path)
		result, err := s.Extract(relPath)
		if err != nil {
			return nil
		}

		for _, sym := range result.Symbols {
			if strings.Contains(strings.ToLower(sym.Name), strings.ToLower(name)) {
				allSymbols = append(allSymbols, sym)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &SymbolResult{
		Symbols: allSymbols,
		Total:   len(allSymbols),
	}, nil
}

// FindReferences finds references to a symbol
func (s *SymbolExtractor) FindReferences(symbol string) (*SearchResult, error) {
	finder := NewFinder(s.project)
	return finder.Search(symbol, &SearchOptions{
		MaxResults: 100,
	})
}

type symbolExtractorFunc func(*os.File, string) ([]Symbol, error)

func (s *SymbolExtractor) getExtractor(ext string) symbolExtractorFunc {
	switch ext {
	case ".go":
		return s.extractGo
	case ".js", ".ts", ".jsx", ".tsx":
		return s.extractJavaScript
	case ".py":
		return s.extractPython
	case ".java":
		return s.extractJava
	case ".rb":
		return s.extractRuby
	case ".rs":
		return s.extractRust
	case ".c", ".cpp", ".cc", ".h", ".hpp":
		return s.extractC
	default:
		return nil
	}
}

func (s *SymbolExtractor) extractGo(file *os.File, path string) ([]Symbol, error) {
	var symbols []Symbol
	scanner := bufio.NewScanner(file)
	lineNum := 0

	patterns := map[*regexp.Regexp]SymbolKind{
		regexp.MustCompile(`^func\s+\(([^)]+)\)\s+(\w+)\s*\(`): SymbolMethod,
		regexp.MustCompile(`^func\s+(\w+)\s*\(`):               SymbolFunction,
		regexp.MustCompile(`^type\s+(\w+)\s+struct`):           SymbolStruct,
		regexp.MustCompile(`^type\s+(\w+)\s+interface`):        SymbolInterface,
		regexp.MustCompile(`^type\s+(\w+)\s+`):                 SymbolType,
		regexp.MustCompile(`^var\s+(\w+)\s+`):                  SymbolVariable,
		regexp.MustCompile(`^const\s+(\w+)\s+`):                SymbolConstant,
	}

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		for pattern, kind := range patterns {
			if matches := pattern.FindStringSubmatch(line); len(matches) > 0 {
				var name string
				var parent string
				if kind == SymbolMethod {
					// Method: receiver is in matches[1], name in matches[2]
					parent = strings.TrimSpace(matches[1])
					// Extract type from receiver
					if idx := strings.LastIndex(parent, " "); idx >= 0 {
						parent = strings.TrimPrefix(parent[idx+1:], "*")
					}
					name = matches[2]
				} else {
					name = matches[1]
				}

				symbols = append(symbols, Symbol{
					Name:      name,
					Kind:      kind,
					File:      path,
					Line:      lineNum,
					Signature: line,
					Parent:    parent,
				})
				break
			}
		}
	}

	return symbols, scanner.Err()
}

func (s *SymbolExtractor) extractJavaScript(file *os.File, path string) ([]Symbol, error) {
	var symbols []Symbol
	scanner := bufio.NewScanner(file)
	lineNum := 0

	patterns := map[*regexp.Regexp]SymbolKind{
		regexp.MustCompile(`(?:export\s+)?(?:async\s+)?function\s+(\w+)`):                      SymbolFunction,
		regexp.MustCompile(`(?:export\s+)?class\s+(\w+)`):                                       SymbolClass,
		regexp.MustCompile(`(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(`):    SymbolFunction,
		regexp.MustCompile(`(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*\(`):                 SymbolFunction,
		regexp.MustCompile(`(?:export\s+)?interface\s+(\w+)`):                                   SymbolInterface,
		regexp.MustCompile(`(?:export\s+)?type\s+(\w+)`):                                        SymbolType,
		regexp.MustCompile(`(\w+)\s*:\s*(?:async\s+)?function`):                                 SymbolMethod,
		regexp.MustCompile(`(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{`):                               SymbolMethod,
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		for pattern, kind := range patterns {
			if matches := pattern.FindStringSubmatch(trimmed); len(matches) > 1 {
				symbols = append(symbols, Symbol{
					Name:      matches[1],
					Kind:      kind,
					File:      path,
					Line:      lineNum,
					Signature: trimmed,
				})
				break
			}
		}
	}

	return symbols, scanner.Err()
}

func (s *SymbolExtractor) extractPython(file *os.File, path string) ([]Symbol, error) {
	var symbols []Symbol
	scanner := bufio.NewScanner(file)
	lineNum := 0
	var currentClass string

	funcPattern := regexp.MustCompile(`^(\s*)def\s+(\w+)\s*\(`)
	classPattern := regexp.MustCompile(`^class\s+(\w+)`)
	varPattern := regexp.MustCompile(`^(\w+)\s*=\s*`)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if matches := classPattern.FindStringSubmatch(line); len(matches) > 1 {
			currentClass = matches[1]
			symbols = append(symbols, Symbol{
				Name:      matches[1],
				Kind:      SymbolClass,
				File:      path,
				Line:      lineNum,
				Signature: strings.TrimSpace(line),
			})
		} else if matches := funcPattern.FindStringSubmatch(line); len(matches) > 2 {
			indent := matches[1]
			kind := SymbolFunction
			parent := ""
			if len(indent) > 0 && currentClass != "" {
				kind = SymbolMethod
				parent = currentClass
			}
			symbols = append(symbols, Symbol{
				Name:      matches[2],
				Kind:      kind,
				File:      path,
				Line:      lineNum,
				Signature: strings.TrimSpace(line),
				Parent:    parent,
			})
		} else if matches := varPattern.FindStringSubmatch(line); len(matches) > 1 {
			// Only top-level variables
			if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				symbols = append(symbols, Symbol{
					Name:      matches[1],
					Kind:      SymbolVariable,
					File:      path,
					Line:      lineNum,
					Signature: strings.TrimSpace(line),
				})
			}
		}

		// Reset class context on unindented lines
		if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			if !classPattern.MatchString(line) {
				currentClass = ""
			}
		}
	}

	return symbols, scanner.Err()
}

func (s *SymbolExtractor) extractJava(file *os.File, path string) ([]Symbol, error) {
	var symbols []Symbol
	scanner := bufio.NewScanner(file)
	lineNum := 0

	classPattern := regexp.MustCompile(`(?:public|private|protected)?\s*(?:abstract|final)?\s*class\s+(\w+)`)
	interfacePattern := regexp.MustCompile(`(?:public|private|protected)?\s*interface\s+(\w+)`)
	methodPattern := regexp.MustCompile(`(?:public|private|protected)?\s*(?:static|final|abstract)?\s*(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\(`)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if matches := classPattern.FindStringSubmatch(line); len(matches) > 1 {
			symbols = append(symbols, Symbol{
				Name:      matches[1],
				Kind:      SymbolClass,
				File:      path,
				Line:      lineNum,
				Signature: line,
			})
		} else if matches := interfacePattern.FindStringSubmatch(line); len(matches) > 1 {
			symbols = append(symbols, Symbol{
				Name:      matches[1],
				Kind:      SymbolInterface,
				File:      path,
				Line:      lineNum,
				Signature: line,
			})
		} else if matches := methodPattern.FindStringSubmatch(line); len(matches) > 1 {
			// Skip constructors and common keywords
			name := matches[1]
			if name != "if" && name != "for" && name != "while" && name != "switch" && name != "catch" {
				symbols = append(symbols, Symbol{
					Name:      name,
					Kind:      SymbolMethod,
					File:      path,
					Line:      lineNum,
					Signature: line,
				})
			}
		}
	}

	return symbols, scanner.Err()
}

func (s *SymbolExtractor) extractRuby(file *os.File, path string) ([]Symbol, error) {
	var symbols []Symbol
	scanner := bufio.NewScanner(file)
	lineNum := 0

	classPattern := regexp.MustCompile(`^class\s+(\w+)`)
	modulePattern := regexp.MustCompile(`^module\s+(\w+)`)
	methodPattern := regexp.MustCompile(`^\s*def\s+(?:self\.)?(\w+[?!]?)`)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if matches := classPattern.FindStringSubmatch(line); len(matches) > 1 {
			symbols = append(symbols, Symbol{
				Name:      matches[1],
				Kind:      SymbolClass,
				File:      path,
				Line:      lineNum,
				Signature: strings.TrimSpace(line),
			})
		} else if matches := modulePattern.FindStringSubmatch(line); len(matches) > 1 {
			symbols = append(symbols, Symbol{
				Name:      matches[1],
				Kind:      SymbolClass, // Module as class
				File:      path,
				Line:      lineNum,
				Signature: strings.TrimSpace(line),
			})
		} else if matches := methodPattern.FindStringSubmatch(line); len(matches) > 1 {
			symbols = append(symbols, Symbol{
				Name:      matches[1],
				Kind:      SymbolMethod,
				File:      path,
				Line:      lineNum,
				Signature: strings.TrimSpace(line),
			})
		}
	}

	return symbols, scanner.Err()
}

func (s *SymbolExtractor) extractRust(file *os.File, path string) ([]Symbol, error) {
	var symbols []Symbol
	scanner := bufio.NewScanner(file)
	lineNum := 0

	patterns := map[*regexp.Regexp]SymbolKind{
		regexp.MustCompile(`^(?:pub\s+)?fn\s+(\w+)`):          SymbolFunction,
		regexp.MustCompile(`^(?:pub\s+)?struct\s+(\w+)`):      SymbolStruct,
		regexp.MustCompile(`^(?:pub\s+)?enum\s+(\w+)`):        SymbolType,
		regexp.MustCompile(`^(?:pub\s+)?trait\s+(\w+)`):       SymbolInterface,
		regexp.MustCompile(`^(?:pub\s+)?type\s+(\w+)`):        SymbolType,
		regexp.MustCompile(`^(?:pub\s+)?const\s+(\w+)`):       SymbolConstant,
		regexp.MustCompile(`^(?:pub\s+)?static\s+(\w+)`):      SymbolVariable,
		regexp.MustCompile(`^\s+(?:pub\s+)?fn\s+(\w+)`):       SymbolMethod,
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for pattern, kind := range patterns {
			if matches := pattern.FindStringSubmatch(line); len(matches) > 1 {
				symbols = append(symbols, Symbol{
					Name:      matches[1],
					Kind:      kind,
					File:      path,
					Line:      lineNum,
					Signature: strings.TrimSpace(line),
				})
				break
			}
		}
	}

	return symbols, scanner.Err()
}

func (s *SymbolExtractor) extractC(file *os.File, path string) ([]Symbol, error) {
	var symbols []Symbol
	scanner := bufio.NewScanner(file)
	lineNum := 0

	// Simplified C/C++ patterns
	funcPattern := regexp.MustCompile(`^(?:static\s+)?(?:inline\s+)?(?:[\w:]+\s+)+(\w+)\s*\([^;]*$`)
	structPattern := regexp.MustCompile(`^(?:typedef\s+)?struct\s+(\w+)`)
	classPattern := regexp.MustCompile(`^class\s+(\w+)`)
	definePattern := regexp.MustCompile(`^#define\s+(\w+)`)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if matches := structPattern.FindStringSubmatch(line); len(matches) > 1 {
			symbols = append(symbols, Symbol{
				Name:      matches[1],
				Kind:      SymbolStruct,
				File:      path,
				Line:      lineNum,
				Signature: line,
			})
		} else if matches := classPattern.FindStringSubmatch(line); len(matches) > 1 {
			symbols = append(symbols, Symbol{
				Name:      matches[1],
				Kind:      SymbolClass,
				File:      path,
				Line:      lineNum,
				Signature: line,
			})
		} else if matches := funcPattern.FindStringSubmatch(line); len(matches) > 1 {
			name := matches[1]
			if name != "if" && name != "for" && name != "while" && name != "switch" {
				symbols = append(symbols, Symbol{
					Name:      name,
					Kind:      SymbolFunction,
					File:      path,
					Line:      lineNum,
					Signature: line,
				})
			}
		} else if matches := definePattern.FindStringSubmatch(line); len(matches) > 1 {
			symbols = append(symbols, Symbol{
				Name:      matches[1],
				Kind:      SymbolConstant,
				File:      path,
				Line:      lineNum,
				Signature: line,
			})
		}
	}

	return symbols, scanner.Err()
}

func (s *SymbolExtractor) resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(s.project.RootPath, path)
}

func (s *SymbolExtractor) shouldIgnore(name string) bool {
	ignorePatterns := []string{
		"node_modules", "vendor", ".git", ".zrok",
		"__pycache__", "target", "dist", "build",
	}
	for _, pattern := range ignorePatterns {
		if name == pattern {
			return true
		}
	}
	return false
}

// UnifiedExtractor provides symbol extraction with configurable method
type UnifiedExtractor struct {
	project       *project.Project
	method        ExtractionMethod
	regexExtractor *SymbolExtractor
	lspExtractor   *LSPExtractor
}

// NewUnifiedExtractor creates a new unified symbol extractor
func NewUnifiedExtractor(p *project.Project, method ExtractionMethod) *UnifiedExtractor {
	return &UnifiedExtractor{
		project:       p,
		method:        method,
		regexExtractor: NewSymbolExtractor(p),
		lspExtractor:   NewLSPExtractor(p),
	}
}

// Extract extracts symbols from a file using the configured method
func (u *UnifiedExtractor) Extract(path string) (*SymbolResult, error) {
	return u.ExtractWithContext(context.Background(), path)
}

// ExtractWithContext extracts symbols from a file with a context
func (u *UnifiedExtractor) ExtractWithContext(ctx context.Context, path string) (*SymbolResult, error) {
	switch u.method {
	case MethodLSP:
		return u.lspExtractor.Extract(ctx, path)
	case MethodRegex:
		return u.regexExtractor.Extract(path)
	case MethodAuto:
		fallthrough
	default:
		// Try LSP first
		if u.lspExtractor.CanHandle(path) {
			result, err := u.lspExtractor.Extract(ctx, path)
			if err == nil {
				return result, nil
			}
			// Fall back to regex on error
		}
		return u.regexExtractor.Extract(path)
	}
}

// Find searches for symbols by name
func (u *UnifiedExtractor) Find(name string) (*SymbolResult, error) {
	return u.FindWithContext(context.Background(), name)
}

// FindWithContext searches for symbols by name with a context
func (u *UnifiedExtractor) FindWithContext(ctx context.Context, name string) (*SymbolResult, error) {
	switch u.method {
	case MethodLSP:
		return u.lspExtractor.Find(ctx, name)
	case MethodRegex:
		return u.regexExtractor.Find(name)
	case MethodAuto:
		fallthrough
	default:
		// For find, always use regex since it's faster for project-wide search
		// LSP would require opening every file
		return u.regexExtractor.Find(name)
	}
}

// FindReferences finds references to a symbol
func (u *UnifiedExtractor) FindReferences(symbol string) (*SearchResult, error) {
	return u.regexExtractor.FindReferences(symbol)
}

// Close closes all extractors and releases resources
func (u *UnifiedExtractor) Close() error {
	return u.lspExtractor.Close()
}

// Method returns the current extraction method
func (u *UnifiedExtractor) Method() ExtractionMethod {
	return u.method
}

// SetMethod sets the extraction method
func (u *UnifiedExtractor) SetMethod(method ExtractionMethod) {
	u.method = method
}
