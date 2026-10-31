//go:build !windows

package cmd

import (
	"os/exec"
	"syscall"
)

// detachProcess configures cmd to run in a new session so that it is immune
// to SIGINT/SIGHUP delivered to the parent's terminal process group.
func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
