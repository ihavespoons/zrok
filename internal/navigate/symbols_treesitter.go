package navigate

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ihavespoons/zrok/internal/project"
	"github.com/ihavespoons/zrok/internal/treesitter"
)

// TreeSitterExtractor extracts symbols using tree-sitter.
type TreeSitterExtractor struct {
	project *project.Project
	parser  *treesitter.Parser
}

// NewTreeSitterExtractor creates a new tree-sitter based symbol extractor.
func NewTreeSitterExtractor(p *project.Project) *TreeSitterExtractor {
	return &TreeSitterExtractor{
		project: p,
		parser:  treesitter.NewParser(),
	}
}

// Extract extracts symbols from a file using tree-sitter.
func (e *TreeSitterExtractor) Extract(_ context.Context, path string) (*SymbolResult, error) {
	fullPath := e.resolvePath(path)

	if !e.CanHandle(path) {
		return nil, ErrTreeSitterNotAvailable
	}

	tsSymbols, err := e.parser.ExtractSymbols(fullPath, path)
	if err != nil {
		return nil, err
	}

	symbols := make([]Symbol, len(tsSymbols))
	for i, ts := range tsSymbols {
		symbols[i] = Symbol{
			Name:      ts.Name,
			Kind:      mapTreeSitterKind(ts.Kind),
			File:      path,
			Line:      ts.Line,
			Signature: ts.Signature,
			Parent:    ts.Parent,
		}
	}

	return &SymbolResult{
		File:    path,
		Symbols: symbols,
		Total:   len(symbols),
	}, nil
}

// Find searches for symbols by name using tree-sitter.
func (e *TreeSitterExtractor) Find(ctx context.Context, name string) (*SymbolResult, error) {
	var allSymbols []Symbol

	err := filepath.Walk(e.project.RootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			dirName := info.Name()
			if strings.HasPrefix(dirName, ".") || e.shouldIgnore(dirName) {
				return filepath.SkipDir
			}
			return nil
		}

		if !e.parser.CanHandle(path) {
			return nil
		}

		relPath, _ := filepath.Rel(e.project.RootPath, path)
		result, err := e.Extract(ctx, relPath)
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

// Close is a no-op for tree-sitter (no external processes).
func (e *TreeSitterExtractor) Close() error {
	return nil
}

// CanHandle returns whether tree-sitter can handle the given file.
func (e *TreeSitterExtractor) CanHandle(path string) bool {
	fullPath := e.resolvePath(path)
	return e.parser.CanHandle(fullPath)
}

func (e *TreeSitterExtractor) resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(e.project.RootPath, path)
}

func (e *TreeSitterExtractor) shouldIgnore(name string) bool {
	ignorePatterns := []string{
		"node_modules", "vendor", ".git", ".zrok",
		"__pycache__", "target", "dist", "build",
	}
	return slices.Contains(ignorePatterns, name)
}

// mapTreeSitterKind maps a treesitter.SymbolKind to navigate.SymbolKind.
func mapTreeSitterKind(k treesitter.SymbolKind) SymbolKind {
	switch k {
	case treesitter.KindFunction:
		return SymbolFunction
	case treesitter.KindMethod:
		return SymbolMethod
	case treesitter.KindClass:
		return SymbolClass
	case treesitter.KindStruct:
		return SymbolStruct
	case treesitter.KindInterface:
		return SymbolInterface
	case treesitter.KindVariable:
		return SymbolVariable
	case treesitter.KindConstant:
		return SymbolConstant
	case treesitter.KindType:
		return SymbolType
	case treesitter.KindModule:
		return SymbolType
	default:
		return SymbolType
	}
}
