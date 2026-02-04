package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/ihavespoons/zrok/internal/navigate/lsp"
	"github.com/spf13/cobra"
)

type lspServerInfo struct {
	Language    string
	Server      string
	InstallCmd  string
	InstallNote string
}

var lspServers = []lspServerInfo{
	{
		Language:   "go",
		Server:     "gopls",
		InstallCmd: "go install golang.org/x/tools/gopls@latest",
	},
	{
		Language:   "python",
		Server:     "pyright-langserver",
		InstallCmd: "npm install -g pyright",
	},
	{
		Language:   "typescript",
		Server:     "typescript-language-server",
		InstallCmd: "npm install -g typescript-language-server typescript",
	},
	{
		Language:   "javascript",
		Server:     "typescript-language-server",
		InstallCmd: "npm install -g typescript-language-server typescript",
	},
	{
		Language:    "rust",
		Server:      "rust-analyzer",
		InstallCmd:  "rustup component add rust-analyzer",
		InstallNote: "Requires rustup to be installed",
	},
	{
		Language:    "java",
		Server:      "jdtls",
		InstallCmd:  "",
		InstallNote: "Download from https://projects.eclipse.org/projects/eclipse.jdt.ls",
	},
	{
		Language:   "ruby",
		Server:     "solargraph",
		InstallCmd: "gem install solargraph",
	},
	{
		Language:    "c",
		Server:      "clangd",
		InstallCmd:  getClangdInstallCmd(),
		InstallNote: "Install via system package manager",
	},
	{
		Language:    "cpp",
		Server:      "clangd",
		InstallCmd:  getClangdInstallCmd(),
		InstallNote: "Install via system package manager",
	},
}

func getClangdInstallCmd() string {
	switch runtime.GOOS {
	case "darwin":
		return "brew install llvm"
	case "linux":
		return "apt install clangd || yum install clang-tools-extra"
	default:
		return ""
	}
}

var lspCmd = &cobra.Command{
	Use:   "lsp",
	Short: "Manage LSP language servers",
	Long: `Manage Language Server Protocol (LSP) servers for symbol extraction.

LSP servers provide accurate code analysis for the 'symbols' command.
Use 'zrok lsp status' to see which servers are installed.
Use 'zrok lsp install <language>' to install a server.`,
}

var lspStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show LSP server status",
	Long:  "Show which LSP servers are installed and available.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("LSP Server Status:")
		fmt.Println()

		installed := 0
		seen := make(map[string]bool)

		for _, info := range lspServers {
			// Skip duplicates (typescript/javascript share same server)
			if seen[info.Server] {
				continue
			}
			seen[info.Server] = true

			config, ok := lsp.GetServerForLanguage(info.Language)
			if !ok {
				continue
			}

			status := "not installed"
			statusIcon := "✗"
			if lsp.IsServerAvailable(config) {
				status = "installed"
				statusIcon = "✓"
				installed++
			}

			languages := info.Language
			if info.Language == "typescript" {
				languages = "typescript, javascript"
			}
			if info.Language == "c" {
				languages = "c, c++"
			}

			fmt.Printf("  %s %-12s %-30s %s\n", statusIcon, info.Server, "("+languages+")", status)
		}

		fmt.Println()
		fmt.Printf("Installed: %d/%d servers\n", installed, len(seen))

		if installed < len(seen) {
			fmt.Println("\nRun 'zrok lsp install <language>' to install a server.")
			fmt.Println("Run 'zrok lsp install --all' to install all servers.")
		}
	},
}

var lspListCmd = &cobra.Command{
	Use:   "list",
	Short: "List supported languages and install commands",
	Long:  "List all supported languages and their LSP server install commands.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Supported LSP Servers:")
		fmt.Println()

		seen := make(map[string]bool)
		for _, info := range lspServers {
			if seen[info.Server] {
				continue
			}
			seen[info.Server] = true

			languages := info.Language
			if info.Language == "typescript" {
				languages = "typescript, javascript"
			}
			if info.Language == "c" {
				languages = "c, c++"
			}

			fmt.Printf("%-12s (%s)\n", info.Server, languages)
			if info.InstallCmd != "" {
				fmt.Printf("  Install: %s\n", info.InstallCmd)
			}
			if info.InstallNote != "" {
				fmt.Printf("  Note: %s\n", info.InstallNote)
			}
			fmt.Println()
		}
	},
}

var lspInstallCmd = &cobra.Command{
	Use:   "install [language]",
	Short: "Install LSP server for a language",
	Long: `Install an LSP server for symbol extraction.

Examples:
  zrok lsp install go
  zrok lsp install python
  zrok lsp install typescript
  zrok lsp install --all`,
	Run: func(cmd *cobra.Command, args []string) {
		all, _ := cmd.Flags().GetBool("all")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		if !all && len(args) == 0 {
			exitError("specify a language or use --all\n\nSupported languages: go, python, typescript, javascript, rust, ruby, c, cpp")
		}

		var toInstall []lspServerInfo
		seen := make(map[string]bool)

		if all {
			for _, info := range lspServers {
				if seen[info.Server] {
					continue
				}
				seen[info.Server] = true

				config, ok := lsp.GetServerForLanguage(info.Language)
				if !ok || lsp.IsServerAvailable(config) {
					continue
				}
				if info.InstallCmd == "" {
					fmt.Printf("Skipping %s: manual installation required\n", info.Server)
					if info.InstallNote != "" {
						fmt.Printf("  %s\n", info.InstallNote)
					}
					continue
				}
				toInstall = append(toInstall, info)
			}
		} else {
			lang := strings.ToLower(args[0])
			var info *lspServerInfo
			for i := range lspServers {
				if lspServers[i].Language == lang {
					info = &lspServers[i]
					break
				}
			}

			if info == nil {
				exitError("unknown language: %s\n\nSupported: go, python, typescript, javascript, rust, ruby, c, cpp", lang)
			}

			config, ok := lsp.GetServerForLanguage(lang)
			if ok && lsp.IsServerAvailable(config) {
				fmt.Printf("%s is already installed\n", info.Server)
				return
			}

			if info.InstallCmd == "" {
				exitError("%s requires manual installation\n  %s", info.Server, info.InstallNote)
			}

			toInstall = append(toInstall, *info)
		}

		if len(toInstall) == 0 {
			fmt.Println("All requested servers are already installed.")
			return
		}

		for _, info := range toInstall {
			fmt.Printf("Installing %s...\n", info.Server)
			fmt.Printf("  Running: %s\n", info.InstallCmd)

			if dryRun {
				fmt.Println("  (dry-run, skipping)")
				continue
			}

			// Parse and execute the command
			parts := strings.Fields(info.InstallCmd)
			if len(parts) == 0 {
				continue
			}

			execCmd := exec.Command(parts[0], parts[1:]...)
			execCmd.Stdout = os.Stdout
			execCmd.Stderr = os.Stderr

			if err := execCmd.Run(); err != nil {
				fmt.Printf("  Error: %v\n", err)
				if info.InstallNote != "" {
					fmt.Printf("  Note: %s\n", info.InstallNote)
				}
			} else {
				fmt.Printf("  Done!\n")
			}
			fmt.Println()
		}
	},
}

func init() {
	rootCmd.AddCommand(lspCmd)
	lspCmd.AddCommand(lspStatusCmd)
	lspCmd.AddCommand(lspListCmd)
	lspCmd.AddCommand(lspInstallCmd)

	lspInstallCmd.Flags().Bool("all", false, "Install all available LSP servers")
	lspInstallCmd.Flags().Bool("dry-run", false, "Show what would be installed without installing")
}
