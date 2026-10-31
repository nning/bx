package cmd

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"
)

// clipboardHistoryNote reminds the user that clearing the clipboard does not
// reach copies made by other processes, such as clipboard history managers.
const clipboardHistoryNote = "Note: any process running as your user can read the clipboard, and clipboard managers (Klipper, GNOME clipboard history, Alfred, …) may keep a copy that bx cannot clear."

// copySecret copies value to the clipboard, schedules it to be cleared and
// tells the user what happened.  label names the copied value in messages,
// e.g. "Password".  withNote adds clipboardHistoryNote; it is left out for
// short-lived values such as TOTP codes.
func copySecret(label, value string, withNote bool) error {
	if err := clipboard.WriteAll(value); err != nil {
		return fmt.Errorf("failed to copy %s to clipboard: %w", label, err)
	}
	secs := clipboardClearTimeoutSeconds()
	if secs > 0 {
		if err := spawnClipboardClear(time.Duration(secs)*time.Second, value); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not schedule clipboard clear: %v\n", err)
		} else {
			fmt.Printf("%s copied to clipboard. Clearing in %d seconds...\n", label, secs)
		}
	} else {
		fmt.Printf("%s copied to clipboard.\n", label)
	}
	if withNote {
		fmt.Println(clipboardHistoryNote)
	}
	return nil
}

// clipboardDigest returns the hex SHA-256 of s.  The clear helper is given
// only this digest, never the secret itself.
func clipboardDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// spawnClipboardClear launches a detached background process that clears the
// clipboard after duration. The background process is immune to SIGINT so that
// Ctrl+C in the terminal does not prevent the clipboard from being wiped.
//
// The digest of value is passed on the helper's stdin (not in argv, where
// other processes could read it).  The helper clears the clipboard only if it
// still holds value, so it neither wipes something the user copied in the
// meantime nor can be abused to clear arbitrary clipboard contents.
// Returns an error if the helper process could not be started.
func spawnClipboardClear(duration time.Duration, value string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine executable path: %w", err)
	}
	secs := int(duration.Seconds())
	if secs <= 0 {
		secs = defaultClipboardClearTimeout
	}
	cmd := exec.Command(exe, "__clipboardclear", strconv.Itoa(secs)) //nolint:gosec
	detachProcess(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_, werr := io.WriteString(stdin, clipboardDigest(value))
	cerr := stdin.Close()
	if cmd.Process != nil {
		if err := cmd.Process.Release(); err != nil {
			return fmt.Errorf("failed to release clipboard clear process: %w", err)
		}
	}
	if werr != nil {
		return werr
	}
	return cerr
}

// shouldClearClipboard reports whether the clear helper should wipe the
// clipboard.  It clears only when the clipboard still holds the secret whose
// digest is want.  If the clipboard cannot be read it clears anyway, because
// leaving a secret behind is the worse failure.
func shouldClearClipboard(current string, readErr error, want string) bool {
	if readErr != nil {
		return true
	}
	got := clipboardDigest(current)
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// clipboardClearCmd is a hidden internal command used to clear the clipboard
// after a delay. It is spawned as a detached background process by
// spawnClipboardClear so that it survives Ctrl+C in the parent terminal.  It
// expects the digest of the copied secret on stdin and does nothing without
// it.
var clipboardClearCmd = &cobra.Command{
	Use:    "__clipboardclear <seconds>",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		secs, err := strconv.Atoi(args[0])
		if err != nil || secs <= 0 {
			os.Exit(1)
		}
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 2*sha256.Size+1))
		want := strings.TrimSpace(string(b))
		if err != nil || len(want) != 2*sha256.Size {
			os.Exit(1)
		}
		time.Sleep(time.Duration(secs) * time.Second)
		current, readErr := clipboard.ReadAll()
		if shouldClearClipboard(current, readErr, want) {
			_ = clipboard.WriteAll("")
		}
	},
}

func init() {
	rootCmd.AddCommand(clipboardClearCmd)
}
