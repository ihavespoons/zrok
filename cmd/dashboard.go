package cmd

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/ihavespoons/quokka/internal/dashboard"
	"github.com/ihavespoons/quokka/internal/project"
	"github.com/spf13/cobra"
)

// dashboardCmd represents the dashboard command
var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Start the web dashboard",
	Long: `Start a local web dashboard for viewing and managing findings.

The dashboard provides:
- Overview of project status and findings
- Filterable findings list
- Memory browser
- Agent configuration viewer
- Report generation`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		port, _ := cmd.Flags().GetInt("port")
		noBrowser, _ := cmd.Flags().GetBool("no-browser")
		readHeaderTimeout, _ := cmd.Flags().GetDuration("read-header-timeout")
		readTimeout, _ := cmd.Flags().GetDuration("read-timeout")
		writeTimeout, _ := cmd.Flags().GetDuration("write-timeout")
		idleTimeout, _ := cmd.Flags().GetDuration("idle-timeout")

		server := dashboard.NewServer(p, port)
		server.SetTimeouts(readHeaderTimeout, readTimeout, writeTimeout, idleTimeout)

		url := fmt.Sprintf("http://localhost:%d", port)

		if jsonOutput {
			if err := outputJSON(map[string]interface{}{
				"url":     url,
				"port":    port,
				"project": p.Config.Name,
			}); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
		} else {
			fmt.Printf("Starting dashboard at %s\n", url)
			fmt.Printf("Project: %s\n", p.Config.Name)
			fmt.Println("\nPress Ctrl+C to stop")
		}

		// Open browser if not disabled
		if !noBrowser {
			go func() {
				openBrowser(url)
			}()
		}

		if err := server.Start(); err != nil {
			exitError("server error: %v", err)
		}
	},
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start() // Best effort to open browser
}

func init() {
	rootCmd.AddCommand(dashboardCmd)

	dashboardCmd.Flags().IntP("port", "p", 8080, "Port to run dashboard on")
	dashboardCmd.Flags().Bool("no-browser", false, "Don't automatically open browser")
	dashboardCmd.Flags().Duration("read-header-timeout", dashboard.DefaultReadHeaderTimeout, "HTTP read-header timeout (slowloris mitigation)")
	dashboardCmd.Flags().Duration("read-timeout", dashboard.DefaultReadTimeout, "HTTP read timeout for full request body")
	dashboardCmd.Flags().Duration("write-timeout", dashboard.DefaultWriteTimeout, "HTTP write timeout (0 = no limit, default; set >0 to bound slow-client-read attacks at cost of breaking long SSE sessions)")
	dashboardCmd.Flags().Duration("idle-timeout", dashboard.DefaultIdleTimeout, "HTTP idle (keep-alive) timeout")
}
