package lsp

import "encoding/json"

// JSON-RPC 2.0 types

// Request represents a JSON-RPC request
type Request struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// Response represents a JSON-RPC response
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *ResponseError  `json:"error,omitempty"`
}

// ResponseError represents a JSON-RPC error
type ResponseError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Notification represents a JSON-RPC notification (no ID)
type Notification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// LSP Initialize types

// InitializeParams is sent to the server during initialization
type InitializeParams struct {
	ProcessID    int                `json:"processId"`
	RootURI      string             `json:"rootUri"`
	Capabilities ClientCapabilities `json:"capabilities"`
}

// ClientCapabilities describes the capabilities the client supports
type ClientCapabilities struct {
	TextDocument TextDocumentClientCapabilities `json:"textDocument,omitempty"`
}

// TextDocumentClientCapabilities describes text document specific capabilities
type TextDocumentClientCapabilities struct {
	DocumentSymbol DocumentSymbolClientCapabilities `json:"documentSymbol,omitempty"`
}

// DocumentSymbolClientCapabilities describes document symbol specific capabilities
type DocumentSymbolClientCapabilities struct {
	HierarchicalDocumentSymbolSupport bool `json:"hierarchicalDocumentSymbolSupport,omitempty"`
}

// InitializeResult is the response from the initialize request
type InitializeResult struct {
	Capabilities ServerCapabilities `json:"capabilities"`
}

// ServerCapabilities describes what the server can do
type ServerCapabilities struct {
	DocumentSymbolProvider bool `json:"documentSymbolProvider,omitempty"`
	TextDocumentSync       int  `json:"textDocumentSync,omitempty"`
}

// Text Document types

// TextDocumentIdentifier identifies a text document
type TextDocumentIdentifier struct {
	URI string `json:"uri"`
}

// TextDocumentItem is an item passed to textDocument/didOpen
type TextDocumentItem struct {
	URI        string `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
	Text       string `json:"text"`
}

// DidOpenTextDocumentParams is sent when a document is opened
type DidOpenTextDocumentParams struct {
	TextDocument TextDocumentItem `json:"textDocument"`
}

// DidCloseTextDocumentParams is sent when a document is closed
type DidCloseTextDocumentParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

// Document Symbol types

// DocumentSymbolParams is sent to request document symbols
type DocumentSymbolParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

// Position represents a position in a text document
type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// Range represents a range in a text document
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// DocumentSymbol represents programming constructs like functions or classes
type DocumentSymbol struct {
	Name           string           `json:"name"`
	Detail         string           `json:"detail,omitempty"`
	Kind           SymbolKind       `json:"kind"`
	Tags           []int            `json:"tags,omitempty"`
	Deprecated     bool             `json:"deprecated,omitempty"`
	Range          Range            `json:"range"`
	SelectionRange Range            `json:"selectionRange"`
	Children       []DocumentSymbol `json:"children,omitempty"`
}

// SymbolInformation represents symbol information (flat list format)
type SymbolInformation struct {
	Name          string   `json:"name"`
	Kind          SymbolKind `json:"kind"`
	Deprecated    bool       `json:"deprecated,omitempty"`
	Location      Location   `json:"location"`
	ContainerName string     `json:"containerName,omitempty"`
}

// Location represents a location inside a resource
type Location struct {
	URI   string `json:"uri"`
	Range Range  `json:"range"`
}

// SymbolKind represents the kind of symbol
type SymbolKind int

// LSP Symbol Kinds
const (
	SymbolKindFile          SymbolKind = 1
	SymbolKindModule        SymbolKind = 2
	SymbolKindNamespace     SymbolKind = 3
	SymbolKindPackage       SymbolKind = 4
	SymbolKindClass         SymbolKind = 5
	SymbolKindMethod        SymbolKind = 6
	SymbolKindProperty      SymbolKind = 7
	SymbolKindField         SymbolKind = 8
	SymbolKindConstructor   SymbolKind = 9
	SymbolKindEnum          SymbolKind = 10
	SymbolKindInterface     SymbolKind = 11
	SymbolKindFunction      SymbolKind = 12
	SymbolKindVariable      SymbolKind = 13
	SymbolKindConstant      SymbolKind = 14
	SymbolKindString        SymbolKind = 15
	SymbolKindNumber        SymbolKind = 16
	SymbolKindBoolean       SymbolKind = 17
	SymbolKindArray         SymbolKind = 18
	SymbolKindObject        SymbolKind = 19
	SymbolKindKey           SymbolKind = 20
	SymbolKindNull          SymbolKind = 21
	SymbolKindEnumMember    SymbolKind = 22
	SymbolKindStruct        SymbolKind = 23
	SymbolKindEvent         SymbolKind = 24
	SymbolKindOperator      SymbolKind = 25
	SymbolKindTypeParameter SymbolKind = 26
)

// SymbolKindName returns the string name for a symbol kind
func SymbolKindName(k SymbolKind) string {
	names := map[SymbolKind]string{
		SymbolKindFile:          "File",
		SymbolKindModule:        "Module",
		SymbolKindNamespace:     "Namespace",
		SymbolKindPackage:       "Package",
		SymbolKindClass:         "Class",
		SymbolKindMethod:        "Method",
		SymbolKindProperty:      "Property",
		SymbolKindField:         "Field",
		SymbolKindConstructor:   "Constructor",
		SymbolKindEnum:          "Enum",
		SymbolKindInterface:     "Interface",
		SymbolKindFunction:      "Function",
		SymbolKindVariable:      "Variable",
		SymbolKindConstant:      "Constant",
		SymbolKindString:        "String",
		SymbolKindNumber:        "Number",
		SymbolKindBoolean:       "Boolean",
		SymbolKindArray:         "Array",
		SymbolKindObject:        "Object",
		SymbolKindKey:           "Key",
		SymbolKindNull:          "Null",
		SymbolKindEnumMember:    "EnumMember",
		SymbolKindStruct:        "Struct",
		SymbolKindEvent:         "Event",
		SymbolKindOperator:      "Operator",
		SymbolKindTypeParameter: "TypeParameter",
	}
	if name, ok := names[k]; ok {
		return name
	}
	return "Unknown"
}
