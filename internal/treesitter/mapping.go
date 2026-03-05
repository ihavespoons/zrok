package treesitter

// SymbolKind represents a kind of code symbol extracted by tree-sitter.
type SymbolKind string

const (
	KindFunction  SymbolKind = "function"
	KindMethod    SymbolKind = "method"
	KindClass     SymbolKind = "class"
	KindStruct    SymbolKind = "struct"
	KindInterface SymbolKind = "interface"
	KindVariable  SymbolKind = "variable"
	KindConstant  SymbolKind = "constant"
	KindType      SymbolKind = "type"
	KindModule    SymbolKind = "module"
)

// Symbol represents a code symbol extracted by tree-sitter.
type Symbol struct {
	Name      string
	Kind      SymbolKind
	Line      int
	EndLine   int
	Signature string
	Parent    string
	Content   string
}

// mapCaptureToKind maps a tree-sitter capture name to a SymbolKind.
func mapCaptureToKind(capture string) SymbolKind {
	switch capture {
	case "function":
		return KindFunction
	case "method":
		return KindMethod
	case "class":
		return KindClass
	case "struct":
		return KindStruct
	case "interface":
		return KindInterface
	case "variable":
		return KindVariable
	case "constant":
		return KindConstant
	case "type":
		return KindType
	case "module":
		return KindModule
	default:
		return ""
	}
}
