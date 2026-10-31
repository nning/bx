package cmd

import "testing"

func TestParseIntFlag_Valid(t *testing.T) {
	got, err := parseIntFlag("32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 32 {
		t.Errorf("got %d, want 32", got)
	}
}

func TestParseIntFlag_Zero(t *testing.T) {
	got, err := parseIntFlag("0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestParseIntFlag_Negative(t *testing.T) {
	_, err := parseIntFlag("-1")
	if err == nil {
		t.Fatal("expected error for negative value, got nil")
	}
}

func TestParseIntFlag_PartialString(t *testing.T) {
	// "32abc" is not a valid integer and must be rejected.
	_, err := parseIntFlag("32abc")
	if err == nil {
		t.Fatal("expected error for partial string \"32abc\", got nil")
	}
}

func TestParseIntFlag_Empty(t *testing.T) {
	_, err := parseIntFlag("")
	if err == nil {
		t.Fatal("expected error for empty string, got nil")
	}
}

func TestParseIntFlag_NonNumeric(t *testing.T) {
	_, err := parseIntFlag("abc")
	if err == nil {
		t.Fatal("expected error for non-numeric string, got nil")
	}
}
