package navigate

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/ihavespoons/zrok/internal/navigate/lsp"
	"github.com/ihavespoons/zrok/internal/project"
)

// LSPExtractor extracts symbols using language servers
type LSPExtractor struct {
	project *project.Project
	manager *lsp.Manager
}

// NewLSPExtractor creates a new LSP-based symbol extractor
func NewLSPExtractor(p *project.Project) *LSPExtractor {
	return &LSPExtractor{
		project: p,
		manager: lsp.NewManager(p.RootPath),
	}
}

// Extract extracts symbols from a file using LSP
func (e *LSPExtractor) Extract(ctx context.Context, path string) (*SymbolResult, error) {
	fullPath := e.resolvePath(path)

	// Check if we can handle this file
	if !e.manager.CanHandle(fullPath) {
		return nil, ErrLSPNotAvailable
	}

	// Get client for this file
	client, err := e.manager.GetClient(ctx, fullPath)
	if err != nil {
		return nil, err
	}

	// Read file content
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}

	// Create file URI
	uri := "file://" + fullPath

	// Get language ID from extension
	ext := filepath.Ext(fullPath)
	languageID := lsp.GetLanguageID(ext)

	// Open the document
	if err := client.DidOpen(ctx, uri, languageID, string(content)); err != nil {
		return nil, err
	}
	defer client.DidClose(ctx, uri)

	// Get document symbols
	lspSymbols, err := client.DocumentSymbols(ctx, uri)
	if err != nil {
		return nil, err
	}

	// Convert LSP symbols to our format
	symbols := e.convertSymbols(lspSymbols, path, "")

	return &SymbolResult{
		File:    path,
		Symbols: symbols,
		Total:   len(symbols),
	}, nil
}

// Find searches for symbols by name using LSP
func (e *LSPExtractor) Find(ctx context.Context, name string) (*SymbolResult, error) {
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

		// Skip if we can't handle this file
		if !e.manager.CanHandle(path) {
			return nil
		}

		relPath, _ := filepath.Rel(e.project.RootPath, path)
		result, err := e.Extract(ctx, relPath)
		if err != nil {
			// Skip files that fail
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

// Close closes all LSP clients
func (e *LSPExtractor) Close() error {
	return e.manager.CloseAll(context.Background())
}

// CanHandle returns whether LSP can handle the given file
func (e *LSPExtractor) CanHandle(path string) bool {
	fullPath := e.resolvePath(path)
	return e.manager.CanHandle(fullPath)
}

// convertSymbols converts LSP DocumentSymbols to our Symbol format
func (e *LSPExtractor) convertSymbols(lspSymbols []lsp.DocumentSymbol, file, parent string) []Symbol {
	var symbols []Symbol

	for _, ls := range lspSymbols {
		sym := Symbol{
			Name:   ls.Name,
			Kind:   mapLSPKind(ls.Kind),
			File:   file,
			Line:   ls.Range.Start.Line + 1, // LSP lines are 0-indexed
			Parent: parent,
		}

		if ls.Detail != "" {
			sym.Signature = ls.Name + " " + ls.Detail
		} else {
			sym.Signature = ls.Name
		}

		symbols = append(symbols, sym)

		// Recursively process children
		if len(ls.Children) > 0 {
			childParent := ls.Name
			if parent != "" {
				childParent = parent + "." + ls.Name
			}
			children := e.convertSymbols(ls.Children, file, childParent)
			symbols = append(symbols, children...)
		}
	}

	return symbols
}

// mapLSPKind maps LSP SymbolKind to our SymbolKind
func mapLSPKind(lspKind lsp.SymbolKind) SymbolKind {
	switch lspKind {
	case lsp.SymbolKindFunction:
		return SymbolFunction
	case lsp.SymbolKindMethod:
		return SymbolMethod
	case lsp.SymbolKindClass:
		return SymbolClass
	case lsp.SymbolKindStruct:
		return SymbolStruct
	case lsp.SymbolKindInterface:
		return SymbolInterface
	case lsp.SymbolKindVariable:
		return SymbolVariable
	case lsp.SymbolKindConstant:
		return SymbolConstant
	case lsp.SymbolKindConstructor:
		return SymbolFunction
	case lsp.SymbolKindEnum:
		return SymbolType
	case lsp.SymbolKindModule:
		return SymbolType
	case lsp.SymbolKindNamespace:
		return SymbolType
	case lsp.SymbolKindPackage:
		return SymbolType
	case lsp.SymbolKindProperty:
		return SymbolVariable
	case lsp.SymbolKindField:
		return SymbolVariable
	case lsp.SymbolKindEnumMember:
		return SymbolConstant
	default:
		return SymbolType
	}
}

func (e *LSPExtractor) resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(e.project.RootPath, path)
}

func (e *LSPExtractor) shouldIgnore(name string) bool {
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
