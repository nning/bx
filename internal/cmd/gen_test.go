package cmd

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// captureStdout redirects os.Stdout to a pipe for the duration of fn and
// returns what was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// newGenCmd builds a fresh gen command with its flags registered, so that
// tests do not share flag state.
func newGenCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "gen", RunE: runGen}
	addGenFlags(cmd)
	return cmd
}

func TestRunGen_WordsRejectsLengthArg(t *testing.T) {
	cmd := newGenCmd(t)
	if err := cmd.Flags().Set("words", "5"); err != nil {
		t.Fatal(err)
	}
	if err := runGen(cmd, []string{"32"}); err == nil {
		t.Fatal("expected an error when a length is passed with --words, got nil")
	}
}

func TestRunGen_WordsRejectsPasswordFlags(t *testing.T) {
	cmd := newGenCmd(t)
	if err := cmd.Flags().Set("words", "5"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("upper", "false"); err != nil {
		t.Fatal(err)
	}
	if err := runGen(cmd, nil); err == nil {
		t.Fatal("expected an error when password flags are passed with --words, got nil")
	}
}

func TestRunGen_WordsTooFew(t *testing.T) {
	cmd := newGenCmd(t)
	if err := cmd.Flags().Set("words", "2"); err != nil {
		t.Fatal(err)
	}
	if err := runGen(cmd, nil); err == nil {
		t.Fatal("expected an error for 2 words, got nil")
	}
}

func TestRunGen_WordsZero(t *testing.T) {
	cmd := newGenCmd(t)
	if err := cmd.Flags().Set("words", "0"); err != nil {
		t.Fatal(err)
	}
	if err := runGen(cmd, nil); err == nil {
		t.Fatal("expected an error for --words 0, got nil")
	}
}

func TestRunGen_WordsGeneratesPassphrase(t *testing.T) {
	cmd := newGenCmd(t)
	if err := cmd.Flags().Set("words", "6"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("separator", "."); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("capitalize", "true"); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runGen(cmd, nil); err != nil {
			t.Errorf("runGen: %v", err)
		}
	})
	out = strings.TrimSpace(out)
	parts := strings.Split(out, ".")
	if len(parts) != 6 {
		t.Fatalf("got %d words, want 6: %q", len(parts), out)
	}
	for _, w := range parts {
		if w == "" || w[0] < 'A' || w[0] > 'Z' {
			t.Errorf("word %q must be capitalized and non-empty", w)
		}
	}
}

func TestRunGen_PasswordStillWorks(t *testing.T) {
	cmd := newGenCmd(t)
	out := captureStdout(t, func() {
		if err := runGen(cmd, nil); err != nil {
			t.Errorf("runGen: %v", err)
		}
	})
	if len(strings.TrimSpace(out)) != 32 {
		t.Errorf("default password length: %q", out)
	}
}
