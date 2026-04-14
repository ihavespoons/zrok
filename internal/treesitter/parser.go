package treesitter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

// Parser wraps gotreesitter for symbol extraction.
// Uses pooled parsing for thread-safety and efficiency.
type Parser struct{}

// NewParser creates a new tree-sitter parser.
func NewParser() *Parser {
	return &Parser{}
}

// CanHandle returns whether tree-sitter supports the given file path.
func (p *Parser) CanHandle(path string) bool {
	entry := grammars.DetectLanguage(filepath.Base(path))
	if entry == nil {
		return false
	}
	// Accept if we have a custom query or the library can infer one
	if GetQuery(DetectLanguageName(path)) != "" {
		return true
	}
	return grammars.ResolveTagsQuery(*entry) != ""
}

// ExtractSymbols extracts symbols from a file on disk.
func (p *Parser) ExtractSymbols(filePath, relPath string) ([]Symbol, error) {
	source, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return p.ExtractSymbolsFromSource(source, relPath)
}

// ExtractSymbolsFromSource extracts symbols from source bytes.
func (p *Parser) ExtractSymbolsFromSource(source []byte, relPath string) ([]Symbol, error) {
	entry := grammars.DetectLanguage(filepath.Base(relPath))
	if entry == nil {
		return nil, fmt.Errorf("tree-sitter does not support: %s", relPath)
	}

	// Use pooled parsing — thread-safe, reuses parsers, and automatically
	// uses hand-written token sources for languages that have them (e.g. Go).
	bt, err := grammars.ParseFilePooled(relPath, source)
	if err != nil {
		return nil, fmt.Errorf("failed to parse: %w", err)
	}
	defer bt.Release()

	root := bt.RootNode()
	lang := bt.Language()

	rootType := bt.NodeType(root)
	if rootType == "" || root.ChildCount() == 0 {
		return nil, fmt.Errorf("tree-sitter failed to parse %s", relPath)
	}
	if strings.HasPrefix(rootType, "_") {
		return nil, fmt.Errorf("tree-sitter produced invalid AST for %s (root: %s)", relPath, rootType)
	}

	// Prefer our custom query, fall back to library-inferred tags query
	query := GetQuery(DetectLanguageName(relPath))
	if query == "" {
		query = grammars.ResolveTagsQuery(*entry)
	}
	if query == "" {
		return nil, fmt.Errorf("no tree-sitter query for: %s", relPath)
	}

	q, err := gotreesitter.NewQuery(query, lang)
	if err != nil {
		return nil, fmt.Errorf("failed to compile query: %w", err)
	}

	lines := strings.Split(string(source), "\n")
	cursor := q.Exec(root, lang, source)
	var symbols []Symbol

	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}

		var name string
		var kind SymbolKind
		var line, endLine int
		var signature string

		for _, cap := range match.Captures {
			switch cap.Name {
			case "name":
				name = cap.Text(source)
			default:
				k := mapCaptureToKind(cap.Name)
				if k != "" {
					kind = k
					line = int(cap.Node.StartPoint().Row) + 1
					endLine = int(cap.Node.EndPoint().Row) + 1
					startByte := cap.Node.StartByte()
					endByte := cap.Node.EndByte()
					text := string(source[startByte:endByte])
					if idx := strings.IndexByte(text, '\n'); idx >= 0 {
						signature = strings.TrimSpace(text[:idx])
					} else {
						signature = strings.TrimSpace(text)
					}
				}
			}
		}

		if name == "" || kind == "" {
			continue
		}

		parent := findParentSymbol(match, bt)
		content := extractContent(lines, line, endLine)

		symbols = append(symbols, Symbol{
			Name:      name,
			Kind:      kind,
			Line:      line,
			EndLine:   endLine,
			Signature: signature,
			Parent:    parent,
			Content:   content,
		})
	}

	return symbols, nil
}

// findParentSymbol walks the AST parent chain of the outer capture node
// to find an enclosing named symbol (class, struct, impl, etc.).
func findParentSymbol(match gotreesitter.QueryMatch, bt *gotreesitter.BoundTree) string {
	var outerNode *gotreesitter.Node
	for _, cap := range match.Captures {
		if cap.Name != "name" {
			outerNode = cap.Node
			break
		}
	}
	if outerNode == nil {
		return ""
	}

	parentTypes := map[string]bool{
		"class_declaration":     true,
		"class_definition":      true,
		"class":                 true,
		"struct_item":           true,
		"impl_item":             true,
		"interface_declaration": true,
		"module":                true,
		"type_declaration":      true,
		"type_spec":             true,
	}

	node := outerNode.Parent()
	for node != nil {
		nodeType := bt.NodeType(node)
		if parentTypes[nodeType] {
			nameChild := bt.ChildByField(node, "name")
			if nameChild != nil {
				return bt.NodeText(nameChild)
			}
		}
		node = node.Parent()
	}

	return ""
}

// DetectLanguageName returns the language name for a file path based on extension.
func DetectLanguageName(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".jsx":
		return "javascriptreact"
	case ".tsx":
		return "typescriptreact"
	case ".java":
		return "java"
	case ".rs":
		return "rust"
	case ".rb":
		return "ruby"
	case ".c":
		return "c"
	case ".cpp", ".cc":
		return "cpp"
	case ".h", ".hpp":
		return "c"
	default:
		return ""
	}
}

// extractContent extracts lines from a slice (1-indexed start/end, inclusive).
func extractContent(lines []string, startLine, endLine int) string {
	if startLine < 1 || endLine > len(lines) || startLine > endLine {
		return ""
	}
	return strings.Join(lines[startLine-1:endLine], "\n")
}
