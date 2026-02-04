package chunk

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ihavespoons/zrok/internal/navigate/lsp"
	"github.com/ihavespoons/zrok/internal/project"
)

// ExtractionMethod specifies how to extract chunks
type ExtractionMethod string

const (
	// MethodAuto tries LSP first, falls back to regex
	MethodAuto ExtractionMethod = "auto"
	// MethodLSP uses only LSP
	MethodLSP ExtractionMethod = "lsp"
	// MethodRegex uses only regex
	MethodRegex ExtractionMethod = "regex"
)

// MaxChunkLines is the default maximum lines per chunk
const MaxChunkLines = 100

// Extractor extracts semantic code chunks from source files
type Extractor struct {
	project       *project.Project
	method        ExtractionMethod
	maxChunkLines int
	manager       *lsp.Manager
}

// NewExtractor creates a new chunk extractor
func NewExtractor(p *project.Project) *Extractor {
	return &Extractor{
		project:       p,
		method:        MethodAuto,
		maxChunkLines: MaxChunkLines,
		manager:       lsp.NewManager(p.RootPath),
	}
}

// SetMethod sets the extraction method
func (e *Extractor) SetMethod(method ExtractionMethod) {
	e.method = method
}

// SetMaxChunkLines sets the maximum lines per chunk
func (e *Extractor) SetMaxChunkLines(max int) {
	if max > 0 {
		e.maxChunkLines = max
	}
}

// Close releases resources
func (e *Extractor) Close() error {
	if e.manager != nil {
		return e.manager.CloseAll(context.Background())
	}
	return nil
}

// Extract extracts chunks from a file
func (e *Extractor) Extract(ctx context.Context, path string) (*ChunkList, error) {
	fullPath := e.resolvePath(path)

	switch e.method {
	case MethodLSP:
		return e.extractLSP(ctx, path, fullPath)
	case MethodRegex:
		return e.extractRegex(path, fullPath)
	case MethodAuto:
		fallthrough
	default:
		// Try LSP first
		if e.manager.CanHandle(fullPath) {
			result, err := e.extractLSP(ctx, path, fullPath)
			if err == nil && len(result.Chunks) > 0 {
				return result, nil
			}
		}
		return e.extractRegex(path, fullPath)
	}
}

// ExtractAll extracts chunks from all supported files in the project
func (e *Extractor) ExtractAll(ctx context.Context) (*ChunkList, error) {
	var allChunks []*Chunk

	err := filepath.Walk(e.project.RootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			if e.shouldIgnoreDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip unsupported files
		ext := strings.ToLower(filepath.Ext(path))
		if !e.isSupportedExtension(ext) {
			return nil
		}

		relPath, _ := filepath.Rel(e.project.RootPath, path)
		result, err := e.Extract(ctx, relPath)
		if err != nil {
			// Skip files that fail
			return nil
		}

		allChunks = append(allChunks, result.Chunks...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return &ChunkList{
		Chunks: allChunks,
		Total:  len(allChunks),
	}, nil
}

// extractLSP extracts chunks using LSP document symbols
func (e *Extractor) extractLSP(ctx context.Context, relPath, fullPath string) (*ChunkList, error) {
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

	lines := strings.Split(string(content), "\n")
	language := e.getLanguage(fullPath)

	// Create file URI and open document
	uri := "file://" + fullPath
	ext := filepath.Ext(fullPath)
	languageID := lsp.GetLanguageID(ext)

	if err := client.DidOpen(ctx, uri, languageID, string(content)); err != nil {
		return nil, err
	}
	defer func() { _ = client.DidClose(ctx, uri) }()

	// Get document symbols
	symbols, err := client.DocumentSymbols(ctx, uri)
	if err != nil {
		return nil, err
	}

	// Convert symbols to chunks
	chunks := e.convertSymbolsToChunks(symbols, relPath, language, lines, "")

	// Split large chunks
	chunks = e.splitLargeChunks(chunks, lines, language)

	return &ChunkList{
		Chunks: chunks,
		File:   relPath,
		Total:  len(chunks),
	}, nil
}

// convertSymbolsToChunks converts LSP DocumentSymbols to Chunks
func (e *Extractor) convertSymbolsToChunks(symbols []lsp.DocumentSymbol, file, language string, lines []string, parentName string) []*Chunk {
	var chunks []*Chunk

	for _, sym := range symbols {
		chunkType := mapLSPKindToChunkType(sym.Kind)
		if chunkType == "" {
			// Skip unsupported symbol types but process children
			if len(sym.Children) > 0 {
				childChunks := e.convertSymbolsToChunks(sym.Children, file, language, lines, sym.Name)
				chunks = append(chunks, childChunks...)
			}
			continue
		}

		// LSP lines are 0-indexed, convert to 1-indexed
		startLine := sym.Range.Start.Line + 1
		endLine := sym.Range.End.Line + 1

		// Extract content from lines
		content := e.extractContent(lines, startLine, endLine)

		chunk := NewChunk(file, language, chunkType, sym.Name, content, startLine, endLine)
		if sym.Detail != "" {
			chunk.Signature = sym.Name + " " + sym.Detail
		} else {
			chunk.Signature = e.extractSignature(lines, startLine)
		}

		if parentName != "" {
			chunk.ParentName = parentName
		}

		chunks = append(chunks, chunk)

		// Process children with this chunk as parent
		if len(sym.Children) > 0 {
			childChunks := e.convertSymbolsToChunks(sym.Children, file, language, lines, sym.Name)
			for _, child := range childChunks {
				child.ParentID = chunk.ID
				if child.ParentName == "" {
					child.ParentName = sym.Name
				}
			}
			chunks = append(chunks, childChunks...)
		}
	}

	return chunks
}

// extractRegex extracts chunks using regex patterns
func (e *Extractor) extractRegex(relPath, fullPath string) (*ChunkList, error) {
	ext := strings.ToLower(filepath.Ext(fullPath))
	language := e.getLanguage(fullPath)

	file, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	// Read all lines first
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var chunks []*Chunk

	switch ext {
	case ".go":
		chunks = e.extractGoChunks(lines, relPath, language)
	case ".py":
		chunks = e.extractPythonChunks(lines, relPath, language)
	case ".js", ".ts", ".jsx", ".tsx":
		chunks = e.extractJavaScriptChunks(lines, relPath, language)
	case ".java":
		chunks = e.extractJavaChunks(lines, relPath, language)
	case ".rs":
		chunks = e.extractRustChunks(lines, relPath, language)
	case ".rb":
		chunks = e.extractRubyChunks(lines, relPath, language)
	case ".c", ".cpp", ".cc", ".h", ".hpp":
		chunks = e.extractCChunks(lines, relPath, language)
	}

	// Split large chunks
	chunks = e.splitLargeChunks(chunks, lines, language)

	return &ChunkList{
		Chunks: chunks,
		File:   relPath,
		Total:  len(chunks),
	}, nil
}

// extractGoChunks extracts chunks from Go source files
func (e *Extractor) extractGoChunks(lines []string, file, language string) []*Chunk {
	var chunks []*Chunk
	var currentClass string

	patterns := map[*regexp.Regexp]ChunkType{
		regexp.MustCompile(`^func\s+\(([^)]+)\)\s+(\w+)\s*\(`): ChunkMethod,
		regexp.MustCompile(`^func\s+(\w+)\s*\(`):               ChunkFunction,
		regexp.MustCompile(`^type\s+(\w+)\s+struct`):           ChunkStruct,
		regexp.MustCompile(`^type\s+(\w+)\s+interface`):        ChunkInterface,
	}

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		for pattern, chunkType := range patterns {
			if matches := pattern.FindStringSubmatch(trimmed); len(matches) > 0 {
				var name string
				var parent string

				if chunkType == ChunkMethod {
					// Extract receiver type and method name
					receiver := strings.TrimSpace(matches[1])
					if idx := strings.LastIndex(receiver, " "); idx >= 0 {
						parent = strings.TrimPrefix(receiver[idx+1:], "*")
					}
					name = matches[2]
				} else {
					name = matches[1]
					if chunkType == ChunkStruct || chunkType == ChunkInterface {
						currentClass = name
					}
				}

				// Find end of block
				startLine := lineNum + 1
				endLine := e.findBlockEnd(lines, lineNum, "{", "}")
				content := e.extractContent(lines, startLine, endLine)

				chunk := NewChunk(file, language, chunkType, name, content, startLine, endLine)
				chunk.Signature = trimmed
				if parent != "" {
					chunk.ParentName = parent
				} else if chunkType == ChunkMethod && currentClass != "" {
					chunk.ParentName = currentClass
				}

				chunks = append(chunks, chunk)
				break
			}
		}
	}

	return chunks
}

// extractPythonChunks extracts chunks from Python source files
func (e *Extractor) extractPythonChunks(lines []string, file, language string) []*Chunk {
	var chunks []*Chunk
	var currentClass string
	var classIndent int

	classPattern := regexp.MustCompile(`^class\s+(\w+)`)
	funcPattern := regexp.MustCompile(`^(\s*)def\s+(\w+)\s*\(`)

	for lineNum, line := range lines {
		// Check for class definition
		if matches := classPattern.FindStringSubmatch(line); len(matches) > 1 {
			currentClass = matches[1]
			classIndent = len(line) - len(strings.TrimLeft(line, " \t"))

			startLine := lineNum + 1
			endLine := e.findPythonBlockEnd(lines, lineNum)
			content := e.extractContent(lines, startLine, endLine)

			chunk := NewChunk(file, language, ChunkClass, matches[1], content, startLine, endLine)
			chunk.Signature = strings.TrimSpace(line)
			chunks = append(chunks, chunk)
			continue
		}

		// Check for function/method definition
		if matches := funcPattern.FindStringSubmatch(line); len(matches) > 2 {
			indent := len(matches[1])
			name := matches[2]
			chunkType := ChunkFunction
			var parent string

			// If indented more than class, it's a method
			if currentClass != "" && indent > classIndent {
				chunkType = ChunkMethod
				parent = currentClass
			} else {
				// Reset class context when at module level
				currentClass = ""
			}

			startLine := lineNum + 1
			endLine := e.findPythonBlockEnd(lines, lineNum)
			content := e.extractContent(lines, startLine, endLine)

			chunk := NewChunk(file, language, chunkType, name, content, startLine, endLine)
			chunk.Signature = strings.TrimSpace(line)
			chunk.ParentName = parent
			chunks = append(chunks, chunk)
		}
	}

	return chunks
}

// extractJavaScriptChunks extracts chunks from JavaScript/TypeScript files
func (e *Extractor) extractJavaScriptChunks(lines []string, file, language string) []*Chunk {
	var chunks []*Chunk

	patterns := map[*regexp.Regexp]ChunkType{
		regexp.MustCompile(`(?:export\s+)?(?:async\s+)?function\s+(\w+)`):    ChunkFunction,
		regexp.MustCompile(`(?:export\s+)?class\s+(\w+)`):                     ChunkClass,
		regexp.MustCompile(`(?:export\s+)?interface\s+(\w+)`):                 ChunkInterface,
		regexp.MustCompile(`(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(`): ChunkFunction,
	}

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		for pattern, chunkType := range patterns {
			if matches := pattern.FindStringSubmatch(trimmed); len(matches) > 1 {
				name := matches[1]

				startLine := lineNum + 1
				endLine := e.findBlockEnd(lines, lineNum, "{", "}")
				content := e.extractContent(lines, startLine, endLine)

				chunk := NewChunk(file, language, chunkType, name, content, startLine, endLine)
				chunk.Signature = trimmed
				chunks = append(chunks, chunk)
				break
			}
		}
	}

	return chunks
}

// extractJavaChunks extracts chunks from Java files
func (e *Extractor) extractJavaChunks(lines []string, file, language string) []*Chunk {
	var chunks []*Chunk
	var currentClass string

	classPattern := regexp.MustCompile(`(?:public|private|protected)?\s*(?:abstract|final)?\s*class\s+(\w+)`)
	interfacePattern := regexp.MustCompile(`(?:public|private|protected)?\s*interface\s+(\w+)`)
	methodPattern := regexp.MustCompile(`(?:public|private|protected)?\s*(?:static|final|abstract)?\s*(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\(`)

	skipKeywords := map[string]bool{"if": true, "for": true, "while": true, "switch": true, "catch": true}

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check class
		if matches := classPattern.FindStringSubmatch(trimmed); len(matches) > 1 {
			currentClass = matches[1]

			startLine := lineNum + 1
			endLine := e.findBlockEnd(lines, lineNum, "{", "}")
			content := e.extractContent(lines, startLine, endLine)

			chunk := NewChunk(file, language, ChunkClass, matches[1], content, startLine, endLine)
			chunk.Signature = trimmed
			chunks = append(chunks, chunk)
			continue
		}

		// Check interface
		if matches := interfacePattern.FindStringSubmatch(trimmed); len(matches) > 1 {
			startLine := lineNum + 1
			endLine := e.findBlockEnd(lines, lineNum, "{", "}")
			content := e.extractContent(lines, startLine, endLine)

			chunk := NewChunk(file, language, ChunkInterface, matches[1], content, startLine, endLine)
			chunk.Signature = trimmed
			chunks = append(chunks, chunk)
			continue
		}

		// Check method
		if matches := methodPattern.FindStringSubmatch(trimmed); len(matches) > 1 {
			name := matches[1]
			if skipKeywords[name] {
				continue
			}

			startLine := lineNum + 1
			endLine := e.findBlockEnd(lines, lineNum, "{", "}")
			content := e.extractContent(lines, startLine, endLine)

			chunk := NewChunk(file, language, ChunkMethod, name, content, startLine, endLine)
			chunk.Signature = trimmed
			chunk.ParentName = currentClass
			chunks = append(chunks, chunk)
		}
	}

	return chunks
}

// extractRustChunks extracts chunks from Rust files
func (e *Extractor) extractRustChunks(lines []string, file, language string) []*Chunk {
	var chunks []*Chunk

	patterns := map[*regexp.Regexp]ChunkType{
		regexp.MustCompile(`^(?:pub\s+)?fn\s+(\w+)`):     ChunkFunction,
		regexp.MustCompile(`^(?:pub\s+)?struct\s+(\w+)`): ChunkStruct,
		regexp.MustCompile(`^(?:pub\s+)?enum\s+(\w+)`):   ChunkEnum,
		regexp.MustCompile(`^(?:pub\s+)?trait\s+(\w+)`):  ChunkInterface,
		regexp.MustCompile(`^\s+(?:pub\s+)?fn\s+(\w+)`):  ChunkMethod,
	}

	for lineNum, line := range lines {
		for pattern, chunkType := range patterns {
			if matches := pattern.FindStringSubmatch(line); len(matches) > 1 {
				name := matches[1]

				startLine := lineNum + 1
				endLine := e.findBlockEnd(lines, lineNum, "{", "}")
				content := e.extractContent(lines, startLine, endLine)

				chunk := NewChunk(file, language, chunkType, name, content, startLine, endLine)
				chunk.Signature = strings.TrimSpace(line)
				chunks = append(chunks, chunk)
				break
			}
		}
	}

	return chunks
}

// extractRubyChunks extracts chunks from Ruby files
func (e *Extractor) extractRubyChunks(lines []string, file, language string) []*Chunk {
	var chunks []*Chunk
	var currentClass string

	classPattern := regexp.MustCompile(`^class\s+(\w+)`)
	modulePattern := regexp.MustCompile(`^module\s+(\w+)`)
	methodPattern := regexp.MustCompile(`^\s*def\s+(?:self\.)?(\w+[?!]?)`)

	for lineNum, line := range lines {
		// Check class
		if matches := classPattern.FindStringSubmatch(line); len(matches) > 1 {
			currentClass = matches[1]

			startLine := lineNum + 1
			endLine := e.findRubyBlockEnd(lines, lineNum)
			content := e.extractContent(lines, startLine, endLine)

			chunk := NewChunk(file, language, ChunkClass, matches[1], content, startLine, endLine)
			chunk.Signature = strings.TrimSpace(line)
			chunks = append(chunks, chunk)
			continue
		}

		// Check module
		if matches := modulePattern.FindStringSubmatch(line); len(matches) > 1 {
			startLine := lineNum + 1
			endLine := e.findRubyBlockEnd(lines, lineNum)
			content := e.extractContent(lines, startLine, endLine)

			chunk := NewChunk(file, language, ChunkModule, matches[1], content, startLine, endLine)
			chunk.Signature = strings.TrimSpace(line)
			chunks = append(chunks, chunk)
			continue
		}

		// Check method
		if matches := methodPattern.FindStringSubmatch(line); len(matches) > 1 {
			name := matches[1]
			chunkType := ChunkMethod

			startLine := lineNum + 1
			endLine := e.findRubyBlockEnd(lines, lineNum)
			content := e.extractContent(lines, startLine, endLine)

			chunk := NewChunk(file, language, chunkType, name, content, startLine, endLine)
			chunk.Signature = strings.TrimSpace(line)
			chunk.ParentName = currentClass
			chunks = append(chunks, chunk)
		}
	}

	return chunks
}

// extractCChunks extracts chunks from C/C++ files
func (e *Extractor) extractCChunks(lines []string, file, language string) []*Chunk {
	var chunks []*Chunk

	structPattern := regexp.MustCompile(`^(?:typedef\s+)?struct\s+(\w+)`)
	classPattern := regexp.MustCompile(`^class\s+(\w+)`)
	funcPattern := regexp.MustCompile(`^(?:static\s+)?(?:inline\s+)?(?:[\w:*&]+\s+)+(\w+)\s*\([^;]*$`)

	skipKeywords := map[string]bool{"if": true, "for": true, "while": true, "switch": true}

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check struct
		if matches := structPattern.FindStringSubmatch(trimmed); len(matches) > 1 {
			startLine := lineNum + 1
			endLine := e.findBlockEnd(lines, lineNum, "{", "}")
			content := e.extractContent(lines, startLine, endLine)

			chunk := NewChunk(file, language, ChunkStruct, matches[1], content, startLine, endLine)
			chunk.Signature = trimmed
			chunks = append(chunks, chunk)
			continue
		}

		// Check class
		if matches := classPattern.FindStringSubmatch(trimmed); len(matches) > 1 {
			startLine := lineNum + 1
			endLine := e.findBlockEnd(lines, lineNum, "{", "}")
			content := e.extractContent(lines, startLine, endLine)

			chunk := NewChunk(file, language, ChunkClass, matches[1], content, startLine, endLine)
			chunk.Signature = trimmed
			chunks = append(chunks, chunk)
			continue
		}

		// Check function
		if matches := funcPattern.FindStringSubmatch(trimmed); len(matches) > 1 {
			name := matches[1]
			if skipKeywords[name] {
				continue
			}

			startLine := lineNum + 1
			endLine := e.findBlockEnd(lines, lineNum, "{", "}")
			content := e.extractContent(lines, startLine, endLine)

			chunk := NewChunk(file, language, ChunkFunction, name, content, startLine, endLine)
			chunk.Signature = trimmed
			chunks = append(chunks, chunk)
		}
	}

	return chunks
}

// Helper methods

func (e *Extractor) resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(e.project.RootPath, path)
}

func (e *Extractor) getLanguage(path string) string {
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
		return "unknown"
	}
}

func (e *Extractor) isSupportedExtension(ext string) bool {
	supported := []string{".go", ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rs", ".rb", ".c", ".cpp", ".cc", ".h", ".hpp"}
	for _, s := range supported {
		if ext == s {
			return true
		}
	}
	return false
}

func (e *Extractor) shouldIgnoreDir(name string) bool {
	ignorePatterns := []string{
		"node_modules", "vendor", ".git", ".zrok",
		"__pycache__", "target", "dist", "build",
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

func (e *Extractor) extractContent(lines []string, startLine, endLine int) string {
	if startLine < 1 || endLine > len(lines) || startLine > endLine {
		return ""
	}
	return strings.Join(lines[startLine-1:endLine], "\n")
}

func (e *Extractor) extractSignature(lines []string, startLine int) string {
	if startLine < 1 || startLine > len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[startLine-1])
}

func (e *Extractor) findBlockEnd(lines []string, startIdx int, open, close string) int {
	depth := 0
	for i := startIdx; i < len(lines); i++ {
		line := lines[i]
		depth += strings.Count(line, open) - strings.Count(line, close)
		if depth <= 0 && i > startIdx {
			return i + 1 // Convert to 1-indexed
		}
	}
	return len(lines) // End of file
}

func (e *Extractor) findPythonBlockEnd(lines []string, startIdx int) int {
	if startIdx >= len(lines) {
		return startIdx + 1
	}

	startIndent := len(lines[startIdx]) - len(strings.TrimLeft(lines[startIdx], " \t"))

	for i := startIdx + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		currentIndent := len(line) - len(strings.TrimLeft(line, " \t"))
		if currentIndent <= startIndent {
			return i // Return 1-indexed
		}
	}

	return len(lines) // End of file
}

func (e *Extractor) findRubyBlockEnd(lines []string, startIdx int) int {
	depth := 1
	blockKeywords := regexp.MustCompile(`\b(class|module|def|do|if|unless|case|while|until|for|begin)\b`)
	endKeyword := regexp.MustCompile(`\bend\b`)

	for i := startIdx + 1; i < len(lines); i++ {
		line := lines[i]

		// Count block starts
		depth += len(blockKeywords.FindAllString(line, -1))
		// Count block ends
		depth -= len(endKeyword.FindAllString(line, -1))

		if depth <= 0 {
			return i + 1 // Convert to 1-indexed
		}
	}

	return len(lines) // End of file
}

// splitLargeChunks splits chunks that exceed maxChunkLines into smaller pieces
func (e *Extractor) splitLargeChunks(chunks []*Chunk, lines []string, language string) []*Chunk {
	var result []*Chunk

	for _, chunk := range chunks {
		if chunk.LineCount() <= e.maxChunkLines {
			result = append(result, chunk)
			continue
		}

		// Split into smaller chunks with overlap
		overlap := 5
		chunkSize := e.maxChunkLines - overlap

		for start := chunk.StartLine; start <= chunk.EndLine; {
			end := start + chunkSize - 1
			if end > chunk.EndLine {
				end = chunk.EndLine
			}

			content := e.extractContent(lines, start, end)
			part := NewChunk(chunk.File, language, ChunkBlock, chunk.Name, content, start, end)
			part.ParentID = chunk.ID
			part.ParentName = chunk.Name
			part.Signature = chunk.Signature

			result = append(result, part)

			start = end - overlap + 1
			if start >= chunk.EndLine {
				break
			}
		}
	}

	return result
}

// mapLSPKindToChunkType maps LSP SymbolKind to ChunkType
func mapLSPKindToChunkType(kind lsp.SymbolKind) ChunkType {
	switch kind {
	case lsp.SymbolKindFunction:
		return ChunkFunction
	case lsp.SymbolKindMethod, lsp.SymbolKindConstructor:
		return ChunkMethod
	case lsp.SymbolKindClass:
		return ChunkClass
	case lsp.SymbolKindStruct:
		return ChunkStruct
	case lsp.SymbolKindInterface:
		return ChunkInterface
	case lsp.SymbolKindModule, lsp.SymbolKindNamespace, lsp.SymbolKindPackage:
		return ChunkModule
	case lsp.SymbolKindEnum:
		return ChunkEnum
	case lsp.SymbolKindConstant, lsp.SymbolKindEnumMember:
		return ChunkConstant
	case lsp.SymbolKindVariable, lsp.SymbolKindProperty, lsp.SymbolKindField:
		return ChunkVariable
	default:
		return "" // Skip unsupported types
	}
}
