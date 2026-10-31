//go:build windows

package cmd

import (
	"os/exec"
	"syscall"
)

// detachedProcess is the Windows DETACHED_PROCESS creation flag.
// It is not exported by the standard syscall package so we define it locally.
const detachedProcess = 0x00000008

// detachProcess configures cmd to run detached from the parent's console so
// that it is not terminated when the user presses Ctrl+C.
func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess,
	}
}
