package crypto

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed eff_large_wordlist.txt
var effLargeWordlist string

// effWords holds the EFF large wordlist (7776 words, about 12.9 bits of
// entropy per word), parsed once at startup.
//
// The list is the EFF Diceware list, distributed by the Electronic Frontier
// Foundation under the Creative Commons Attribution 3.0 license:
// https://www.eff.org/dice
var effWords = parseEFFWordlist(effLargeWordlist)

// parseEFFWordlist parses the "dice number<TAB>word" format and returns the
// words in file order.
func parseEFFWordlist(s string) []string {
	lines := strings.Split(s, "\n")
	words := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		_, word, found := strings.Cut(line, "\t")
		if !found || word == "" {
			continue
		}
		words = append(words, word)
	}
	if len(words) < 7776 {
		// A truncated wordlist would silently weaken every generated
		// passphrase; the file is embedded at compile time, so this can only
		// mean the source file was damaged.
		panic("crypto: EFF wordlist is truncated or missing")
	}
	return words
}

// GeneratePassphrase builds a passphrase from the EFF large wordlist: words
// words joined by separator, each capitalized when capitalize is set, with a
// random digit appended to one random word when includeNumber is set.  All
// choices are made with crypto/rand.
//
// At least 3 words are required (roughly 38 bits of entropy with the 7776-word
// list, before capitalization and the digit); at most 64 are allowed.
func GeneratePassphrase(words int, separator string, capitalize, includeNumber bool) (string, error) {
	const (
		minWords = 3
		maxWords = 64
	)
	if words < minWords {
		return "", fmt.Errorf("passphrases need at least %d words, got %d", minWords, words)
	}
	if words > maxWords {
		return "", fmt.Errorf("passphrases are limited to %d words, got %d", maxWords, words)
	}

	numberWord := -1
	if includeNumber {
		i, err := randIndex(words)
		if err != nil {
			return "", err
		}
		numberWord = i
	}

	parts := make([]string, words)
	for i := range parts {
		idx, err := randIndex(len(effWords))
		if err != nil {
			return "", err
		}
		w := effWords[idx]
		if capitalize {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		if i == numberWord {
			d, err := randIndex(10)
			if err != nil {
				return "", err
			}
			w += string(rune('0' + d))
		}
		parts[i] = w
	}
	return strings.Join(parts, separator), nil
}
