package crypto

import (
	"strings"
	"testing"
)

func TestParseEFFWordlist(t *testing.T) {
	if len(effWords) != 7776 {
		t.Fatalf("parsed %d words, want 7776", len(effWords))
	}
	if effWords[0] != "abacus" {
		t.Errorf("first word: %q, want %q", effWords[0], "abacus")
	}
	if effWords[len(effWords)-1] != "zoom" {
		t.Errorf("last word: %q, want %q", effWords[len(effWords)-1], "zoom")
	}
	for _, w := range effWords {
		if strings.ContainsAny(w, " \t\n") {
			t.Errorf("word %q contains whitespace", w)
		}
	}
}

func TestGeneratePassphrase_WordCountAndSeparator(t *testing.T) {
	for _, words := range []int{3, 5, 12} {
		p, err := GeneratePassphrase(words, "-", false, false)
		if err != nil {
			t.Fatalf("GeneratePassphrase(%d): %v", words, err)
		}
		parts := strings.Split(p, "-")
		if len(parts) != words {
			t.Errorf("got %d words, want %d", len(parts), words)
		}
		for _, w := range parts {
			if !effWordSet()[w] {
				t.Errorf("word %q is not in the EFF list", w)
			}
		}
	}
}

func TestGeneratePassphrase_Capitalize(t *testing.T) {
	p, err := GeneratePassphrase(6, " ", true, false)
	if err != nil {
		t.Fatalf("GeneratePassphrase: %v", err)
	}
	for _, w := range strings.Split(p, " ") {
		if w[0] < 'A' || w[0] > 'Z' {
			t.Errorf("word %q is not capitalized", w)
		}
	}
}

func TestGeneratePassphrase_IncludeNumber(t *testing.T) {
	for i := 0; i < 200; i++ {
		p, err := GeneratePassphrase(3, "-", false, true)
		if err != nil {
			t.Fatalf("GeneratePassphrase: %v", err)
		}
		parts := strings.Split(p, "-")
		numbered := 0
		for _, w := range parts {
			if len(w) > 0 && w[len(w)-1] >= '0' && w[len(w)-1] <= '9' {
				numbered++
				// The word without its digit must still come from the list.
				if !effWordSet()[w[:len(w)-1]] {
					t.Errorf("numbered word %q is not a list word with a digit", w)
				}
			}
		}
		if numbered != 1 {
			t.Errorf("got %d numbered words, want exactly 1 (%q)", numbered, p)
		}
	}
}

func TestGeneratePassphrase_Entropy(t *testing.T) {
	// Every word must come from the EFF list.
	p, err := GeneratePassphrase(12, "-", false, false)
	if err != nil {
		t.Fatalf("GeneratePassphrase: %v", err)
	}
	for _, w := range strings.Split(p, "-") {
		if !effWordSet()[w] {
			t.Errorf("word %q is not in the EFF list", w)
		}
	}

	// Two consecutive calls must differ.
	a, _ := GeneratePassphrase(5, "-", false, false)
	b, _ := GeneratePassphrase(5, "-", false, false)
	if a == b {
		t.Error("two consecutive passphrases are identical")
	}
}

func TestGeneratePassphrase_Errors(t *testing.T) {
	if _, err := GeneratePassphrase(2, "-", false, false); err == nil {
		t.Error("expected error for 2 words, got nil")
	}
	if _, err := GeneratePassphrase(65, "-", false, false); err == nil {
		t.Error("expected error for 65 words, got nil")
	}
}

// effWordSet lazily builds a set of the EFF words for membership checks.
func effWordSet() map[string]bool {
	if effWordsSet == nil {
		effWordsSet = make(map[string]bool, len(effWords))
		for _, w := range effWords {
			effWordsSet[w] = true
		}
	}
	return effWordsSet
}

var effWordsSet map[string]bool
