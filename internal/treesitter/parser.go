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
// Each instance is cheap and stateless; create one per goroutine.
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
	return GetQuery(DetectLanguageName(path)) != ""
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
	langName := DetectLanguageName(relPath)
	query := GetQuery(langName)
	if query == "" {
		return nil, fmt.Errorf("no tree-sitter query for language: %s", langName)
	}

	entry := grammars.DetectLanguage(filepath.Base(relPath))
	if entry == nil {
		return nil, fmt.Errorf("tree-sitter does not support: %s", relPath)
	}

	lang := entry.Language()
	tsParser := gotreesitter.NewParser(lang)
	tree, err := tsParser.Parse(source)
	if err != nil {
		return nil, fmt.Errorf("failed to parse: %w", err)
	}
	defer tree.Release()

	root := tree.RootNode()
	rootType := root.Type(lang)
	if rootType == "" || root.ChildCount() == 0 {
		return nil, fmt.Errorf("tree-sitter failed to parse %s", relPath)
	}
	// Internal node types (prefixed with "_") as root indicate a garbled parse
	if strings.HasPrefix(rootType, "_") {
		return nil, fmt.Errorf("tree-sitter produced invalid AST for %s (root: %s)", relPath, rootType)
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
					// First line as signature
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

		parent := findParentSymbol(match, source, lang)

		// Extract content
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
func findParentSymbol(match gotreesitter.QueryMatch, source []byte, lang *gotreesitter.Language) string {
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
		nodeType := node.Type(lang)
		if parentTypes[nodeType] {
			nameChild := node.ChildByFieldName("name", lang)
			if nameChild != nil {
				return nameChild.Text(source)
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
