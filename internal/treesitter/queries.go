package treesitter

// GetQuery returns the tree-sitter S-expression query for symbol extraction
// in the given language. Returns empty string if no query is available.
func GetQuery(language string) string {
	switch language {
	case "go":
		return goQuery
	case "python":
		return pythonQuery
	case "javascript", "javascriptreact":
		return javascriptQuery
	case "typescript", "typescriptreact":
		return typescriptQuery
	case "rust":
		return rustQuery
	case "java":
		return javaQuery
	case "ruby":
		return rubyQuery
	case "c", "cpp":
		return cQuery
	default:
		return ""
	}
}

// SupportedLanguages returns the list of languages with tree-sitter queries.
func SupportedLanguages() []string {
	return []string{
		"go", "python", "javascript", "typescript",
		"rust", "java", "ruby", "c", "cpp",
	}
}
