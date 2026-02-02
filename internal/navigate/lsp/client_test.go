package lsp

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestPathToURI(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/Users/test/project/main.go", "file:///Users/test/project/main.go"},
		{"/tmp/test.py", "file:///tmp/test.py"},
		{"relative/path.js", "file://relative/path.js"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := pathToURI(tt.path)
			if got != tt.want {
				t.Errorf("pathToURI(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestURIToPath(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"file:///Users/test/project/main.go", "/Users/test/project/main.go"},
		{"file:///tmp/test.py", "/tmp/test.py"},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			got := URIToPath(tt.uri)
			if got != tt.want {
				t.Errorf("URIToPath(%q) = %q, want %q", tt.uri, got, tt.want)
			}
		})
	}
}

func TestGetServerForFile(t *testing.T) {
	tests := []struct {
		filename string
		wantLang string
		wantOK   bool
	}{
		{"main.go", "go", true},
		{"app.py", "python", true},
		{"index.ts", "typescript", true},
		{"index.tsx", "typescript", true},
		{"app.js", "javascript", true},
		{"app.jsx", "javascript", true},
		{"lib.rs", "rust", true},
		{"Main.java", "java", true},
		{"app.rb", "ruby", true},
		{"main.c", "c", true},
		{"main.cpp", "cpp", true},
		{"unknown.xyz", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			config, ok := GetServerForFile(tt.filename)
			if ok != tt.wantOK {
				t.Errorf("GetServerForFile(%q) ok = %v, want %v", tt.filename, ok, tt.wantOK)
				return
			}
			if ok && config.Language != tt.wantLang {
				t.Errorf("GetServerForFile(%q) language = %q, want %q", tt.filename, config.Language, tt.wantLang)
			}
		})
	}
}

func TestGetLanguageID(t *testing.T) {
	tests := []struct {
		ext  string
		want string
	}{
		{".go", "go"},
		{".py", "python"},
		{".ts", "typescript"},
		{".tsx", "typescriptreact"},
		{".js", "javascript"},
		{".jsx", "javascriptreact"},
		{".rs", "rust"},
		{".java", "java"},
		{".rb", "ruby"},
		{".c", "c"},
		{".cpp", "cpp"},
		{".unknown", "plaintext"},
	}

	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			got := GetLanguageID(tt.ext)
			if got != tt.want {
				t.Errorf("GetLanguageID(%q) = %q, want %q", tt.ext, got, tt.want)
			}
		})
	}
}

func TestSymbolKindName(t *testing.T) {
	tests := []struct {
		kind SymbolKind
		want string
	}{
		{SymbolKindFunction, "Function"},
		{SymbolKindMethod, "Method"},
		{SymbolKindClass, "Class"},
		{SymbolKindStruct, "Struct"},
		{SymbolKindInterface, "Interface"},
		{SymbolKindVariable, "Variable"},
		{SymbolKindConstant, "Constant"},
		{SymbolKind(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := SymbolKindName(tt.kind)
			if got != tt.want {
				t.Errorf("SymbolKindName(%d) = %q, want %q", tt.kind, got, tt.want)
			}
		})
	}
}

func TestJSONRPCMessageSerialization(t *testing.T) {
	t.Run("Request", func(t *testing.T) {
		req := Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "textDocument/documentSymbol",
			Params: DocumentSymbolParams{
				TextDocument: TextDocumentIdentifier{
					URI: "file:///test.go",
				},
			},
		}

		data, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("Failed to marshal request: %v", err)
		}

		var decoded Request
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Failed to unmarshal request: %v", err)
		}

		if decoded.Method != req.Method {
			t.Errorf("Method mismatch: got %q, want %q", decoded.Method, req.Method)
		}
	})

	t.Run("Response", func(t *testing.T) {
		resp := Response{
			JSONRPC: "2.0",
			ID:      1,
			Result:  json.RawMessage(`[]`),
		}

		data, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Failed to marshal response: %v", err)
		}

		var decoded Response
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if decoded.ID != resp.ID {
			t.Errorf("ID mismatch: got %d, want %d", decoded.ID, resp.ID)
		}
	})

	t.Run("DocumentSymbol", func(t *testing.T) {
		symbol := DocumentSymbol{
			Name:   "TestFunction",
			Kind:   SymbolKindFunction,
			Detail: "func TestFunction()",
			Range: Range{
				Start: Position{Line: 10, Character: 0},
				End:   Position{Line: 15, Character: 1},
			},
			SelectionRange: Range{
				Start: Position{Line: 10, Character: 5},
				End:   Position{Line: 10, Character: 17},
			},
			Children: []DocumentSymbol{
				{
					Name: "localVar",
					Kind: SymbolKindVariable,
					Range: Range{
						Start: Position{Line: 11, Character: 1},
						End:   Position{Line: 11, Character: 20},
					},
					SelectionRange: Range{
						Start: Position{Line: 11, Character: 5},
						End:   Position{Line: 11, Character: 13},
					},
				},
			},
		}

		data, err := json.Marshal(symbol)
		if err != nil {
			t.Fatalf("Failed to marshal DocumentSymbol: %v", err)
		}

		var decoded DocumentSymbol
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Failed to unmarshal DocumentSymbol: %v", err)
		}

		if decoded.Name != symbol.Name {
			t.Errorf("Name mismatch: got %q, want %q", decoded.Name, symbol.Name)
		}
		if decoded.Kind != symbol.Kind {
			t.Errorf("Kind mismatch: got %d, want %d", decoded.Kind, symbol.Kind)
		}
		if len(decoded.Children) != 1 {
			t.Errorf("Children length mismatch: got %d, want 1", len(decoded.Children))
		}
	})
}

func TestManagerNewManager(t *testing.T) {
	m := NewManager("/test/path")
	if m.RootPath() != "/test/path" {
		t.Errorf("RootPath() = %q, want %q", m.RootPath(), "/test/path")
	}

	clients := m.ActiveClients()
	if len(clients) != 0 {
		t.Errorf("ActiveClients() = %d, want 0", len(clients))
	}
}

func TestManagerCanHandle(t *testing.T) {
	m := NewManager("/test/path")

	// These depend on whether servers are actually installed
	// Just test that the function doesn't panic
	_ = m.CanHandle("test.go")
	_ = m.CanHandle("test.py")
	_ = m.CanHandle("test.unknown")
}

func TestManagerCloseAllEmpty(t *testing.T) {
	m := NewManager("/test/path")
	err := m.CloseAll(context.Background())
	if err != nil {
		t.Errorf("CloseAll() on empty manager returned error: %v", err)
	}
}

func TestInitializeParams(t *testing.T) {
	params := InitializeParams{
		ProcessID: 12345,
		RootURI:   "file:///test/project",
		Capabilities: ClientCapabilities{
			TextDocument: TextDocumentClientCapabilities{
				DocumentSymbol: DocumentSymbolClientCapabilities{
					HierarchicalDocumentSymbolSupport: true,
				},
			},
		},
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("Failed to marshal InitializeParams: %v", err)
	}

	var decoded InitializeParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal InitializeParams: %v", err)
	}

	if decoded.ProcessID != params.ProcessID {
		t.Errorf("ProcessID mismatch: got %d, want %d", decoded.ProcessID, params.ProcessID)
	}
	if decoded.RootURI != params.RootURI {
		t.Errorf("RootURI mismatch: got %q, want %q", decoded.RootURI, params.RootURI)
	}
	if !decoded.Capabilities.TextDocument.DocumentSymbol.HierarchicalDocumentSymbolSupport {
		t.Error("HierarchicalDocumentSymbolSupport should be true")
	}
}

func TestTimeoutConstants(t *testing.T) {
	if DefaultInitializeTimeout != 60*time.Second {
		t.Errorf("DefaultInitializeTimeout = %v, want 60s", DefaultInitializeTimeout)
	}
	if DefaultRequestTimeout != 10*time.Second {
		t.Errorf("DefaultRequestTimeout = %v, want 10s", DefaultRequestTimeout)
	}
}
