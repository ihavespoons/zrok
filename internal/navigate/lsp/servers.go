package lsp

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// ServerConfig describes a language server
type ServerConfig struct {
	Language   string   // Language identifier (e.g., "go", "python")
	Name       string   // Server name (e.g., "gopls", "pyright")
	Command    string   // Command to run
	Args       []string // Command arguments
	Extensions []string // File extensions this server handles
}

// DefaultServers contains configurations for common language servers
var DefaultServers = []ServerConfig{
	{
		Language:   "go",
		Name:       "gopls",
		Command:    "gopls",
		Args:       []string{"serve"},
		Extensions: []string{".go"},
	},
	{
		Language:   "python",
		Name:       "pyright",
		Command:    "pyright-langserver",
		Args:       []string{"--stdio"},
		Extensions: []string{".py"},
	},
	{
		Language:   "typescript",
		Name:       "typescript-language-server",
		Command:    "typescript-language-server",
		Args:       []string{"--stdio"},
		Extensions: []string{".ts", ".tsx"},
	},
	{
		Language:   "javascript",
		Name:       "typescript-language-server",
		Command:    "typescript-language-server",
		Args:       []string{"--stdio"},
		Extensions: []string{".js", ".jsx"},
	},
	{
		Language:   "rust",
		Name:       "rust-analyzer",
		Command:    "rust-analyzer",
		Args:       []string{},
		Extensions: []string{".rs"},
	},
	{
		Language:   "java",
		Name:       "jdtls",
		Command:    "jdtls",
		Args:       []string{},
		Extensions: []string{".java"},
	},
	{
		Language:   "ruby",
		Name:       "solargraph",
		Command:    "solargraph",
		Args:       []string{"stdio"},
		Extensions: []string{".rb"},
	},
	{
		Language:   "c",
		Name:       "clangd",
		Command:    "clangd",
		Args:       []string{},
		Extensions: []string{".c", ".h"},
	},
	{
		Language:   "cpp",
		Name:       "clangd",
		Command:    "clangd",
		Args:       []string{},
		Extensions: []string{".cpp", ".cc", ".hpp", ".cxx"},
	},
}

// GetServerForFile returns the server config for a given filename
func GetServerForFile(filename string) (*ServerConfig, bool) {
	ext := strings.ToLower(filepath.Ext(filename))
	for i := range DefaultServers {
		for _, serverExt := range DefaultServers[i].Extensions {
			if ext == serverExt {
				return &DefaultServers[i], true
			}
		}
	}
	return nil, false
}

// GetServerForLanguage returns the server config for a given language
func GetServerForLanguage(language string) (*ServerConfig, bool) {
	lang := strings.ToLower(language)
	for i := range DefaultServers {
		if DefaultServers[i].Language == lang {
			return &DefaultServers[i], true
		}
	}
	return nil, false
}

// IsServerAvailable checks if a language server is available on the system
func IsServerAvailable(config *ServerConfig) bool {
	_, err := exec.LookPath(config.Command)
	return err == nil
}

// GetLanguageID returns the LSP language identifier for a file extension
func GetLanguageID(ext string) string {
	ext = strings.ToLower(ext)
	languageIDs := map[string]string{
		".go":   "go",
		".py":   "python",
		".ts":   "typescript",
		".tsx":  "typescriptreact",
		".js":   "javascript",
		".jsx":  "javascriptreact",
		".rs":   "rust",
		".java": "java",
		".rb":   "ruby",
		".c":    "c",
		".h":    "c",
		".cpp":  "cpp",
		".cc":   "cpp",
		".hpp":  "cpp",
		".cxx":  "cpp",
	}
	if id, ok := languageIDs[ext]; ok {
		return id
	}
	return "plaintext"
}
