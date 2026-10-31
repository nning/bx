package cmd

import "testing"

func TestValidateTOTPCode_Valid(t *testing.T) {
	got, err := validateTOTPCode("123456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "123456" {
		t.Errorf("got %q, want \"123456\"", got)
	}
}

func TestValidateTOTPCode_ValidWithSpace(t *testing.T) {
	// Some authenticator apps display codes as "123 456".
	got, err := validateTOTPCode("123 456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "123456" {
		t.Errorf("got %q, want \"123456\"", got)
	}
}

func TestValidateTOTPCode_ValidAllZeros(t *testing.T) {
	got, err := validateTOTPCode("000000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "000000" {
		t.Errorf("got %q, want \"000000\"", got)
	}
}

func TestValidateTOTPCode_TooShort(t *testing.T) {
	_, err := validateTOTPCode("12345")
	if err == nil {
		t.Fatal("expected error for 5-digit code, got nil")
	}
}

func TestValidateTOTPCode_SevenAndEightDigits(t *testing.T) {
	for _, code := range []string{"1234567", "1234 5678"} {
		if _, err := validateTOTPCode(code); err != nil {
			t.Errorf("validateTOTPCode(%q): unexpected error: %v", code, err)
		}
	}
}

func TestValidateTOTPCode_TooLong(t *testing.T) {
	_, err := validateTOTPCode("123456789")
	if err == nil {
		t.Fatal("expected error for 9-digit code, got nil")
	}
}

func TestValidateTOTPCode_Empty(t *testing.T) {
	_, err := validateTOTPCode("")
	if err == nil {
		t.Fatal("expected error for empty code, got nil")
	}
}

func TestValidateTOTPCode_ContainsLetters(t *testing.T) {
	_, err := validateTOTPCode("12345a")
	if err == nil {
		t.Fatal("expected error for code with letters, got nil")
	}
}

func TestValidateTOTPCode_OnlySpaces(t *testing.T) {
	_, err := validateTOTPCode("      ")
	if err == nil {
		t.Fatal("expected error for code of only spaces, got nil")
	}
}

func TestValidateTOTPCode_LeadingTrailingSpaces(t *testing.T) {
	// Pasted codes may have surrounding whitespace; spaces are stripped.
	got, err := validateTOTPCode(" 123456 ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "123456" {
		t.Errorf("got %q, want \"123456\"", got)
	}
}
