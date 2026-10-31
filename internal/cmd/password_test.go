package cmd

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// withStdin replaces os.Stdin with a pipe carrying content for the duration of
// the test, so that readSecretLineStdin can be exercised without a terminal.
func withStdin(t *testing.T, content string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = orig
		_ = r.Close()
	})
	go func() {
		defer func() { _ = w.Close() }()
		_, _ = w.WriteString(content)
	}()
}

// TestReadSecretLineStdin_FirstLineOnly verifies that only the first line is
// taken, so that a full `pass show` entry (password plus metadata lines) can be
// piped in unmodified.
func TestReadSecretLineStdin_FirstLineOnly(t *testing.T) {
	withStdin(t, "s3cr3t\nlogin: alice\nurl: https://example.com\n")
	got, err := readSecretLineStdin("password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "s3cr3t" {
		t.Errorf("got %q, want %q", got, "s3cr3t")
	}
}

// TestReadSecretLineStdin_NoTrailingNewline verifies that input without a final
// newline is accepted (io.EOF is not an error here).
func TestReadSecretLineStdin_NoTrailingNewline(t *testing.T) {
	withStdin(t, "s3cr3t")
	got, err := readSecretLineStdin("password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "s3cr3t" {
		t.Errorf("got %q, want %q", got, "s3cr3t")
	}
}

// TestReadSecretLineStdin_CRLF verifies that a Windows line ending is stripped
// rather than becoming part of the secret.
func TestReadSecretLineStdin_CRLF(t *testing.T) {
	withStdin(t, "s3cr3t\r\nlogin: alice\r\n")
	got, err := readSecretLineStdin("password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "s3cr3t" {
		t.Errorf("got %q, want %q", got, "s3cr3t")
	}
}

// TestReadSecretLineStdin_Empty verifies that empty input is rejected instead of
// silently storing an empty password.
func TestReadSecretLineStdin_Empty(t *testing.T) {
	withStdin(t, "")
	if _, err := readSecretLineStdin("password"); err == nil {
		t.Error("expected an error for empty stdin, got nil")
	}
}

// TestReadSecretLineStdin_EmptyFirstLine verifies that a leading blank line is
// rejected rather than treated as a valid secret.
func TestReadSecretLineStdin_EmptyFirstLine(t *testing.T) {
	withStdin(t, "\nlogin: alice\n")
	if _, err := readSecretLineStdin("password"); err == nil {
		t.Error("expected an error for a blank first line, got nil")
	}
}

// TestReadSecretLineStdin_PreservesInnerWhitespace verifies that only the line
// ending is trimmed — spaces are legitimate password characters.
func TestReadSecretLineStdin_PreservesInnerWhitespace(t *testing.T) {
	withStdin(t, "  pass word  \n")
	got, err := readSecretLineStdin("password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "  pass word  " {
		t.Errorf("got %q, want %q", got, "  pass word  ")
	}
}

// resetViper clears all viper settings so tests do not interfere with each other.
func resetViper(t *testing.T) {
	t.Helper()
	viper.Reset()
}

// TestUnlockTimeoutMinutes_NotSet verifies that the default value is returned
// when unlock_timeout is not configured.
func TestUnlockTimeoutMinutes_NotSet(t *testing.T) {
	resetViper(t)
	got := unlockTimeoutMinutes()
	if got != vault.DefaultUnlockTimeoutMinutes {
		t.Errorf("got %d, want default %d", got, vault.DefaultUnlockTimeoutMinutes)
	}
}

// TestUnlockTimeoutMinutes_Positive verifies that a configured positive value
// is returned as-is.
func TestUnlockTimeoutMinutes_Positive(t *testing.T) {
	resetViper(t)
	viper.Set("unlock_timeout", 30)
	got := unlockTimeoutMinutes()
	if got != 30 {
		t.Errorf("got %d, want 30", got)
	}
}

// TestUnlockTimeoutMinutes_Zero verifies that zero disables session caching.
func TestUnlockTimeoutMinutes_Zero(t *testing.T) {
	resetViper(t)
	viper.Set("unlock_timeout", 0)
	got := unlockTimeoutMinutes()
	if got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

// TestUnlockTimeoutMinutes_Negative verifies that a negative configured value
// is clamped to 0 (session caching disabled).
func TestUnlockTimeoutMinutes_Negative(t *testing.T) {
	resetViper(t)
	viper.Set("unlock_timeout", -5)
	got := unlockTimeoutMinutes()
	if got != 0 {
		t.Errorf("got %d, want 0 for negative value", got)
	}
}

// TestClipboardClearTimeoutSeconds_NotSet verifies that the default value is
// returned when clipboard_clear_timeout is not configured.
func TestClipboardClearTimeoutSeconds_NotSet(t *testing.T) {
	resetViper(t)
	got := clipboardClearTimeoutSeconds()
	if got != defaultClipboardClearTimeout {
		t.Errorf("got %d, want default %d", got, defaultClipboardClearTimeout)
	}
}

// TestClipboardClearTimeoutSeconds_Positive verifies that a configured positive
// value is returned as-is.
func TestClipboardClearTimeoutSeconds_Positive(t *testing.T) {
	resetViper(t)
	viper.Set("clipboard_clear_timeout", 60)
	got := clipboardClearTimeoutSeconds()
	if got != 60 {
		t.Errorf("got %d, want 60", got)
	}
}

// TestClipboardClearTimeoutSeconds_Zero verifies that zero disables clipboard
// clearing.
func TestClipboardClearTimeoutSeconds_Zero(t *testing.T) {
	resetViper(t)
	viper.Set("clipboard_clear_timeout", 0)
	got := clipboardClearTimeoutSeconds()
	if got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

// TestClipboardClearTimeoutSeconds_Negative verifies that a negative configured
// value falls back to the default.
func TestClipboardClearTimeoutSeconds_Negative(t *testing.T) {
	resetViper(t)
	viper.Set("clipboard_clear_timeout", -5)
	got := clipboardClearTimeoutSeconds()
	if got != defaultClipboardClearTimeout {
		t.Errorf("got %d, want default %d for negative value", got, defaultClipboardClearTimeout)
	}
}

// TestMasterPasswordPrompt verifies that the prompt names the account whose
// vault is about to be unlocked, so that users with several accounts can tell
// which password is being asked for.
func TestMasterPasswordPrompt(t *testing.T) {
	tests := []struct {
		name    string
		account string
		setup   func()
		want    string
	}{
		{
			name:    "named account",
			account: "default",
			want:    "Master Password (default): ",
		},
		{
			name:    "no account falls back to email",
			account: "",
			setup:   func() { viper.Set("email", "user@example.com") },
			want:    "Master Password (user@example.com): ",
		},
		{
			name:    "nothing configured",
			account: "",
			want:    "Master Password: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetViperAndAccount(t)
			if tt.setup != nil {
				tt.setup()
			}
			activeAccountName = tt.account
			if got := masterPasswordPrompt(); got != tt.want {
				t.Errorf("masterPasswordPrompt() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWarnArgvSecrets(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"no secret flags", []string{"--name", "x"}, nil},
		{"password on argv", []string{"--password", "hunter2"}, []string{"--password is visible"}},
		{"empty password", []string{"--password", ""}, nil},
		{"totp on argv", []string{"--totp", "JBSWY3DP"}, []string{"--totp is visible"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "test", Run: func(*cobra.Command, []string) {}}
			cmd.Flags().String("name", "", "")
			cmd.Flags().String("password", "", "")
			cmd.Flags().String("totp", "", "")
			if err := cmd.ParseFlags(tt.args); err != nil {
				t.Fatal(err)
			}

			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			orig := os.Stderr
			os.Stderr = w
			warnArgvSecrets(cmd)
			os.Stderr = orig
			_ = w.Close()
			out, _ := io.ReadAll(r)

			if len(tt.want) == 0 && len(out) != 0 {
				t.Errorf("unexpected warning: %q", out)
			}
			for _, want := range tt.want {
				if !strings.Contains(string(out), want) {
					t.Errorf("warning %q missing from %q", want, out)
				}
			}
			if strings.Contains(string(out), "hunter2") {
				t.Error("warning must not echo the secret")
			}
		})
	}
}

// TestPromptLine_SequentialPrompts verifies that consecutive prompts share
// one buffered reader (so the second answer is not lost to read-ahead), that
// input containing spaces is kept whole, and that an empty line is accepted.
func TestPromptLine_SequentialPrompts(t *testing.T) {
	withStdin(t, "  https://vault.example.com \n\nAlice Example\nlast")
	want := []string{"https://vault.example.com", "", "Alice Example", "last"}
	for i, w := range want {
		got, err := promptLine("")
		if err != nil {
			t.Fatalf("prompt %d: unexpected error: %v", i, err)
		}
		if got != w {
			t.Errorf("prompt %d: got %q, want %q", i, got, w)
		}
	}
	if _, err := promptLine(""); !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF once input is exhausted, got %v", err)
	}
}
