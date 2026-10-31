package cmd

import (
	"strings"
	"testing"

	"github.com/nning/bx/internal/crypto"
)

func TestEncryptField_WithinLimit(t *testing.T) {
	key := make([]byte, 64)
	enc, err := encryptField("notes", strings.Repeat("x", 7000), key)
	if err != nil {
		t.Fatalf("encryptField: %v", err)
	}
	got, err := crypto.Decrypt(enc, key)
	if err != nil || len(got) != 7000 {
		t.Fatalf("round trip failed: %v (len %d)", err, len(got))
	}
}

func TestEncryptField_OverLimit(t *testing.T) {
	key := make([]byte, 64)
	_, err := encryptField("notes", strings.Repeat("x", 8000), key)
	if err == nil || !strings.Contains(err.Error(), "notes is too long") {
		t.Fatalf("expected a notes length error, got %v", err)
	}
}

func TestEncryptField_UnknownFieldUnlimited(t *testing.T) {
	key := make([]byte, 64)
	if _, err := encryptField("something else", strings.Repeat("x", 20000), key); err != nil {
		t.Fatalf("encryptField: %v", err)
	}
}
