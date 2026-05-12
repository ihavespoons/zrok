package treesitter

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

// DefaultMaxFileSize is the default cap on source files passed to tree-sitter.
// Files larger than this are skipped to avoid ballooning memory on
// pathologically-large or generated/minified inputs. Override per-parser via
// Parser.SetMaxFileSize, or globally via ZROK_TREESITTER_MAX_FILE_SIZE
// (bytes). 10 MB comfortably exceeds any reasonable hand-written source file.
const DefaultMaxFileSize int64 = 10 * 1024 * 1024

// SkippedFileError is returned by ExtractSymbols when a file is intentionally
// skipped (e.g. exceeds max size). Callers should treat this as non-fatal.
type SkippedFileError struct {
	Path   string
	Size   int64
	Reason string
}

func (e *SkippedFileError) Error() string {
	return fmt.Sprintf("tree-sitter skipped %s: %s (size=%d)", e.Path, e.Reason, e.Size)
}

// Parser wraps gotreesitter for symbol extraction.
// Uses pooled parsing for thread-safety and efficiency.
type Parser struct {
	maxFileSize int64
}

// NewParser creates a new tree-sitter parser with default limits.
func NewParser() *Parser {
	return &Parser{maxFileSize: getMaxFileSize()}
}

// SetMaxFileSize overrides the per-file byte cap. Values <= 0 disable the cap.
func (p *Parser) SetMaxFileSize(n int64) {
	p.maxFileSize = n
}

// getMaxFileSize reads ZROK_TREESITTER_MAX_FILE_SIZE (bytes) or falls back to
// DefaultMaxFileSize. Set to 0 or negative to disable the cap.
func getMaxFileSize() int64 {
	if v := os.Getenv("ZROK_TREESITTER_MAX_FILE_SIZE"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return DefaultMaxFileSize
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
//
// If the file exceeds the configured max size, it is skipped and a
// *SkippedFileError is returned. Callers (e.g. the indexer) should treat
// that error as non-fatal.
func (p *Parser) ExtractSymbols(filePath, relPath string) ([]Symbol, error) {
	if p.maxFileSize > 0 {
		info, err := os.Stat(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to stat file: %w", err)
		}
		if info.Size() > p.maxFileSize {
			fmt.Fprintf(os.Stderr,
				"warning: tree-sitter skipping %s: file size %d exceeds max %d bytes\n",
				relPath, info.Size(), p.maxFileSize)
			return nil, &SkippedFileError{
				Path:   relPath,
				Size:   info.Size(),
				Reason: fmt.Sprintf("exceeds max size %d", p.maxFileSize),
			}
		}
	}

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
