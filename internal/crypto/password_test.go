package crypto

import (
	"strings"
	"testing"
)

func TestGeneratePassword_LengthTooShort(t *testing.T) {
	_, err := GeneratePassword(3, true, true, true, true)
	if err == nil {
		t.Fatal("expected error for length < 4, got nil")
	}
}

func TestGeneratePassword_NoCharTypes(t *testing.T) {
	_, err := GeneratePassword(16, false, false, false, false)
	if err == nil {
		t.Fatal("expected error for no character types enabled, got nil")
	}
}

func TestGeneratePassword_CorrectLength(t *testing.T) {
	for _, length := range []int{4, 16, 32, 64} {
		pw, err := GeneratePassword(length, true, true, true, true)
		if err != nil {
			t.Fatalf("length=%d: unexpected error: %v", length, err)
		}
		if len(pw) != length {
			t.Fatalf("length=%d: got password of length %d", length, len(pw))
		}
	}
}

// containsAny returns true if s contains at least one character from chars.
func containsAny(s, chars string) bool {
	for _, c := range chars {
		if strings.ContainsRune(s, c) {
			return true
		}
	}
	return false
}

// TestGeneratePassword_AllTypesPresent verifies that when all character types
// are enabled, the generated password contains at least one character from each
// type.
func TestGeneratePassword_AllTypesPresent(t *testing.T) {
	for i := 0; i < 20; i++ {
		pw, err := GeneratePassword(16, true, true, true, true)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		if !containsAny(pw, uppercaseChars) {
			t.Errorf("iteration %d: password %q contains no uppercase letter", i, pw)
		}
		if !containsAny(pw, lowercaseChars) {
			t.Errorf("iteration %d: password %q contains no lowercase letter", i, pw)
		}
		if !containsAny(pw, digitChars) {
			t.Errorf("iteration %d: password %q contains no digit", i, pw)
		}
		if !containsAny(pw, symbolChars) {
			t.Errorf("iteration %d: password %q contains no symbol", i, pw)
		}
	}
}

func TestGeneratePassword_OnlyLowercase(t *testing.T) {
	pw, err := GeneratePassword(8, false, true, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range pw {
		if !strings.ContainsRune(lowercaseChars, c) {
			t.Errorf("password %q contains non-lowercase character %q", pw, c)
		}
	}
}

func TestGeneratePassword_OnlyDigits(t *testing.T) {
	pw, err := GeneratePassword(8, false, false, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range pw {
		if !strings.ContainsRune(digitChars, c) {
			t.Errorf("password %q contains non-digit character %q", pw, c)
		}
	}
}

func TestGeneratePassword_UpperAndDigits(t *testing.T) {
	for i := 0; i < 10; i++ {
		pw, err := GeneratePassword(8, true, false, true, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !containsAny(pw, uppercaseChars) {
			t.Errorf("password %q contains no uppercase letter", pw)
		}
		if !containsAny(pw, digitChars) {
			t.Errorf("password %q contains no digit", pw)
		}
		for _, c := range pw {
			if !strings.ContainsRune(uppercaseChars+digitChars, c) {
				t.Errorf("password %q contains unexpected character %q", pw, c)
			}
		}
	}
}
