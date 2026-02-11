//go:build windows

package lsp

import (
	"os"
	"os/exec"
)

func setSysProcAttr(cmd *exec.Cmd) {
	// No process group setup needed on Windows
}

func killProcessGroup(process *os.Process) {
	_ = process.Kill()
}
