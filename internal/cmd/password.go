package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

// promptSecure reads a value securely (no echo) from /dev/tty (or stdin as a
// fallback), printing prompt before reading. Returns the typed value.
func promptSecure(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		// Fallback to stdin if /dev/tty is unavailable
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	defer func() { _ = tty.Close() }()
	_, _ = fmt.Fprint(tty, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	return string(b), err
}

// masterPasswordPrompt returns the prompt used when asking for the master
// password.  It names the account being unlocked so that users with several
// accounts can tell which vault the password is for.  Single-account configs
// that predate named accounts have no name, so they fall back to the email.
func masterPasswordPrompt() string {
	label := activeAccountName
	if label == "" {
		label = accountSetting("email")
	}
	if label == "" {
		return "Master Password: "
	}
	return fmt.Sprintf("Master Password (%s): ", label)
}

// readPassword prompts for the master password on /dev/tty so that stdout
// remains clean and the output of commands can be piped to other tools.
func readPassword() (string, error) {
	return promptSecure(masterPasswordPrompt())
}

// stdinLines buffers stdin for promptLine and readSecretLineStdin.  A single
// reader must be shared: a bufio.Reader reads ahead, so a second reader on
// the same stdin would miss input the first one already buffered.  It is
// rebuilt whenever os.Stdin is replaced (as tests do).
var stdinLines struct {
	file   *os.File
	reader *bufio.Reader
}

// readStdinLine returns the next line of stdin without its line ending.  A
// final line without a newline is returned with a nil error; io.EOF is only
// returned when nothing was left to read.
func readStdinLine() (string, error) {
	if stdinLines.file != os.Stdin {
		stdinLines.file, stdinLines.reader = os.Stdin, bufio.NewReader(os.Stdin)
	}
	line, err := stdinLines.reader.ReadString('\n')
	if errors.Is(err, io.EOF) && line != "" {
		err = nil
	}
	return strings.TrimRight(line, "\r\n"), err
}

// promptLine prints prompt and reads one line of input, trimmed of
// surrounding whitespace.  Unlike fmt.Scanln it keeps input that contains
// spaces and accepts an empty line, which callers treat as "keep the
// default".
func promptLine(prompt string) (string, error) {
	fmt.Print(prompt)
	line, err := readStdinLine()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// readSecretLineStdin reads a single secret from stdin and returns its first
// line with the line ending stripped.  It backs the --password-stdin flags,
// which let a secret be piped in from another password manager without ever
// appearing in argv (and thus in `ps` output or the shell history).
//
// Only the first line is used, matching the convention of pass(1), where the
// password is the first line and any following lines carry metadata.  This
// keeps `pass show <entry> | bx create --password-stdin` working without an
// intermediate `head -1`.  Note that the master password is unaffected: it is
// always read from /dev/tty by promptSecure.
func readSecretLineStdin(what string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("--%s-stdin expects %s on stdin, but stdin is a terminal", what, what)
	}
	line, err := readStdinLine()
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("failed to read %s from stdin: %w", what, err)
	}
	if line == "" {
		return "", fmt.Errorf("no %s read from stdin", what)
	}
	return line, nil
}

// argvSecretFlags are flags whose value is a secret.  Given on the command
// line, it is readable by other processes through ps(1) or /proc/<pid>/cmdline
// and is likely to end up in the shell history.
var argvSecretFlags = map[string]string{
	"password": "use the prompt or --password-stdin instead",
	"totp":     "use 'bx edit -i' to set it in your editor instead",
}

// warnArgvSecrets prints a warning to stderr for every secret flag that was
// given a value on the command line.
func warnArgvSecrets(cmd *cobra.Command) {
	for _, name := range []string{"password", "totp"} {
		f := cmd.Flags().Lookup(name)
		if f == nil || !f.Changed || f.Value.String() == "" {
			continue
		}
		fmt.Fprintf(os.Stderr, "warning: --%s is visible to other processes and may be saved in your shell history; %s\n", name, argvSecretFlags[name])
	}
}

// announceGeneratedPassword hands a newly generated item password to the user.
// It is copied to the clipboard rather than printed, so that it does not end
// up in the terminal scrollback or in a log that captures stderr.  If no
// clipboard is available the user is told how to retrieve it instead.
func announceGeneratedPassword(itemName, password string) {
	if err := copySecret("Generated password", password, true); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		fmt.Fprintf(os.Stderr, "The generated password is saved; run 'bx get %q --print' to see it.\n", itemName)
	}
}

// unlockTimeoutMinutes returns the configured vault unlock timeout in minutes.
// A value of 0 disables session caching (always prompt for password).
// Defaults to vault.DefaultUnlockTimeoutMinutes when not explicitly configured.
func unlockTimeoutMinutes() int {
	if viper.IsSet("unlock_timeout") {
		t := viper.GetInt("unlock_timeout")
		if t < 0 {
			fmt.Fprintln(os.Stderr, "warning: unlock_timeout is negative, treating as 0 (session caching disabled)")
			return 0
		}
		return t
	}
	return vault.DefaultUnlockTimeoutMinutes
}

// defaultClipboardClearTimeout is the number of seconds after which the
// clipboard is automatically cleared when a password or TOTP code is copied.
const defaultClipboardClearTimeout = 30

// clipboardClearTimeoutSeconds returns the configured clipboard clear timeout
// in seconds. A value of 0 disables automatic clipboard clearing.
// Defaults to defaultClipboardClearTimeout when not explicitly configured.
func clipboardClearTimeoutSeconds() int {
	if viper.IsSet("clipboard_clear_timeout") {
		t := viper.GetInt("clipboard_clear_timeout")
		if t < 0 {
			fmt.Fprintf(os.Stderr, "warning: clipboard_clear_timeout is negative, using default %d seconds\n", defaultClipboardClearTimeout)
			return defaultClipboardClearTimeout
		}
		return t
	}
	return defaultClipboardClearTimeout
}
