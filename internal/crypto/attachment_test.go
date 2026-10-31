package crypto

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestAttachmentRoundTrip(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i + 1)
	}

	tests := []string{"", "short", "hello world", string(make([]byte, 4096))}
	for _, plaintext := range tests {
		data, err := EncryptAttachment([]byte(plaintext), key)
		if err != nil {
			t.Fatalf("EncryptAttachment(%d bytes): %v", len(plaintext), err)
		}
		if len(data) < 16+32 {
			t.Fatalf("attachment data too short: %d", len(data))
		}
		got, err := DecryptAttachment(data, key)
		if err != nil {
			t.Fatalf("DecryptAttachment: %v", err)
		}
		if string(got) != plaintext {
			t.Errorf("round trip failed for %d bytes", len(plaintext))
		}
	}
}

func TestDecryptAttachment_TamperDetection(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i + 1)
	}

	data, err := EncryptAttachment([]byte("secret file"), key)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a bit in the ciphertext; the MAC must catch it.
	tampered := bytes.Clone(data)
	tampered[49] ^= 0xff
	if _, err := DecryptAttachment(tampered, key); err == nil {
		t.Error("expected HMAC verification failure for a tampered attachment")
	}

	// Flip a bit in the MAC itself.
	tampered = bytes.Clone(data)
	tampered[17] ^= 0xff
	if _, err := DecryptAttachment(tampered, key); err == nil {
		t.Error("expected HMAC verification failure for a tampered MAC")
	}

	// Truncated data is rejected.
	if _, err := DecryptAttachment(data[:20], key); err == nil {
		t.Error("expected an error for a truncated attachment")
	}

	// A wrong key must fail.
	wrong := make([]byte, 64)
	for i := range wrong {
		wrong[i] = byte(255 - i)
	}
	if _, err := DecryptAttachment(data, wrong); err == nil {
		t.Error("expected HMAC verification failure for a wrong key")
	}
}

// This vector composes the binary layout independently from EncryptAttachment,
// using the type-2 string representation and the official SDK field order.
func TestAttachmentOfficialBinaryFormat(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 64)
	plaintext := []byte("synthetic attachment")
	value, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimPrefix(value, "2."), "|")
	iv, _ := base64.StdEncoding.DecodeString(parts[0])
	ciphertext, _ := base64.StdEncoding.DecodeString(parts[1])
	mac, _ := base64.StdEncoding.DecodeString(parts[2])
	official := append([]byte{2}, iv...)
	official = append(official, mac...)
	official = append(official, ciphertext...)
	got, err := DecryptAttachment(official, key)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("official buffer rejected: %q, %v", got, err)
	}
	output, err := EncryptAttachment(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	if output[0] != 2 || (len(output)-49)%16 != 0 {
		t.Fatal("invalid official attachment layout")
	}
	encoded := "2." + base64.StdEncoding.EncodeToString(output[1:17]) + "|" +
		base64.StdEncoding.EncodeToString(output[49:]) + "|" + base64.StdEncoding.EncodeToString(output[17:49])
	got, err = Decrypt(encoded, key)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("output cannot be decoded as official type 2: %q, %v", got, err)
	}
	output[0] = 0
	if _, err := DecryptAttachment(output, key); err == nil {
		t.Fatal("unauthenticated attachment type accepted")
	}
}

func TestDecryptAttachment_KeyLengthErrors(t *testing.T) {
	if _, err := DecryptAttachment(make([]byte, 100), make([]byte, 32)); err == nil {
		t.Error("expected an error for a 32-byte key")
	}
	if _, err := EncryptAttachment([]byte("x"), make([]byte, 32)); err == nil {
		t.Error("expected an error for a 32-byte key")
	}
}
