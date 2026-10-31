package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
	uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars     = "0123456789"
	symbolChars    = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// randIndex returns a cryptographically random index in [0, n).
func randIndex(n int) (int, error) {
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random index: %w", err)
	}
	return int(idx.Int64()), nil
}

// GeneratePassword creates a random password with configurable character types.
// It guarantees that at least one character from each enabled type is present.
func GeneratePassword(length int, useUpper, useLower, useDigits, useSymbols bool) (string, error) {
	if length < 4 {
		return "", fmt.Errorf("length must be at least 4 characters")
	}

	var chars string
	var required []string
	if useUpper {
		chars += uppercaseChars
		required = append(required, uppercaseChars)
	}
	if useLower {
		chars += lowercaseChars
		required = append(required, lowercaseChars)
	}
	if useDigits {
		chars += digitChars
		required = append(required, digitChars)
	}
	if useSymbols {
		chars += symbolChars
		required = append(required, symbolChars)
	}
	if chars == "" {
		return "", fmt.Errorf("at least one character type must be enabled")
	}

	if len(required) > length {
		return "", fmt.Errorf("length must be at least %d when %d character types are enabled", len(required), len(required))
	}

	result := make([]byte, length)

	// Guarantee at least one character from each enabled type.
	for i, charset := range required {
		idx, err := randIndex(len(charset))
		if err != nil {
			return "", err
		}
		result[i] = charset[idx]
	}

	// Fill the rest from the combined charset.
	for i := len(required); i < length; i++ {
		idx, err := randIndex(len(chars))
		if err != nil {
			return "", err
		}
		result[i] = chars[idx]
	}

	// Shuffle using Fisher-Yates to avoid predictable positions for required chars.
	for i := length - 1; i > 0; i-- {
		j, err := randIndex(i + 1)
		if err != nil {
			return "", err
		}
		result[i], result[j] = result[j], result[i]
	}

	return string(result), nil
}
