//go:build !windows

package lsp

import (
	"os"
	"os/exec"
	"syscall"
)

func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killProcessGroup(process *os.Process) {
	_ = syscall.Kill(-process.Pid, syscall.SIGKILL)
}
