package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// Decrypt decrypts a Bitwarden cipher string using the given key.
func Decrypt(cipherString string, key []byte) ([]byte, error) {
	if cipherString == "" {
		return nil, nil
	}

	parts := strings.SplitN(cipherString, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid cipher string format")
	}

	encType := parts[0]
	data := parts[1]

	switch encType {
	case "2": // AesCbc256_HmacSha256_B64
		return decryptType2(data, key)
	case "0": // AesCbc256_B64
		// Type 0 carries no MAC.  It is only legitimate for legacy accounts
		// whose symmetric key is a bare 32-byte AES key.  Every key bx holds
		// is a 64-byte enc+mac key, and accepting type 0 under such a key
		// would let anyone who can edit the vault cache strip the MAC from a
		// type-2 value and tamper with the ciphertext undetected.
		if len(key) != 32 {
			return nil, fmt.Errorf("refusing unauthenticated type 0 cipher string for a %d-byte key", len(key))
		}
		return decryptType0(data, key)
	default:
		return nil, fmt.Errorf("unsupported encryption type: %s", encType)
	}
}

// ExpandKey expands a 32-byte master key into a 64-byte key (32 bytes enc, 32 bytes mac).
func ExpandKey(key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	expanded := make([]byte, 64)

	// Bitwarden uses the Master Key directly as the PRK for HKDF-Expand.
	_, err := io.ReadFull(hkdf.Expand(sha256.New, key, []byte("enc")), expanded[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to expand encryption key: %w", err)
	}
	_, err = io.ReadFull(hkdf.Expand(sha256.New, key, []byte("mac")), expanded[32:])
	if err != nil {
		return nil, fmt.Errorf("failed to expand MAC key: %w", err)
	}

	return expanded, nil
}

func decryptType2(data string, key []byte) ([]byte, error) {
	// Bitwarden uses either '|' or '.' as separators in cipher strings.
	var parts []string
	if strings.Contains(data, "|") {
		parts = strings.Split(data, "|")
	} else {
		parts = strings.Split(data, ".")
	}

	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid type 2 data format: expected 3 parts, got %d", len(parts))
	}

	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}
	mac, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode MAC: %w", err)
	}

	if len(key) != 64 {
		return nil, fmt.Errorf("key must be 64 bytes for type 2 (32 enc + 32 mac), got %d", len(key))
	}
	encKey := key[:32]
	macKey := key[32:]

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV length: got %d, want %d", len(iv), aes.BlockSize)
	}

	// Verify HMAC
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ciphertext)
	if !hmac.Equal(mac, h.Sum(nil)) {
		return nil, errors.New("HMAC verification failed")
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext block size invalid")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext)
}

func decryptType0(data string, key []byte) ([]byte, error) {
	var parts []string
	if strings.Contains(data, "|") {
		parts = strings.Split(data, "|")
	} else {
		parts = strings.Split(data, ".")
	}

	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid type 0 data format")
	}

	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV length: got %d, want %d", len(iv), aes.BlockSize)
	}

	// CryptBlocks panics on a partial block, so a malformed cache value
	// must be rejected here rather than crash the process.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext block size invalid")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext)
}

// Wipe overwrites b with zeros.  Go's garbage collector may already have
// copied the backing array, so this only narrows the window in which key
// material stays readable in memory; it is not a guarantee.
func Wipe(b []byte) {
	clear(b)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("unpad error: data empty")
	}
	padding := int(data[length-1])
	if padding < 1 || padding > aes.BlockSize {
		return nil, errors.New("unpad error: invalid padding")
	}
	if padding > length {
		return nil, errors.New("unpad error: padding exceeds data length")
	}
	for i := 0; i < padding; i++ {
		if int(data[length-1-i]) != padding {
			return nil, errors.New("unpad error: invalid padding bytes")
		}
	}
	return data[:length-padding], nil
}

// pkcs7Pad returns a new slice containing data padded to a multiple of the AES
// block size using PKCS7. A fresh allocation is always made so that the
// caller's original slice is never mutated.
func pkcs7Pad(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

// EncryptAttachment encrypts plaintext for an attachment file with AES-256-CBC
// and HMAC-SHA256, returning the raw bytes in the form
//
//	0x02 || IV || MAC || ciphertext
//
// which is how Bitwarden stores attachment files.  key must be exactly 64
// bytes: key[:32] is the AES encryption key and key[32:] is the HMAC key.
func EncryptAttachment(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != 64 {
		return nil, fmt.Errorf("key must be 64 bytes for attachments (32 enc + 32 mac), got %d", len(key))
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	padded := pkcs7Pad(plaintext)

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	h := hmac.New(sha256.New, key[32:])
	h.Write(iv)
	h.Write(ciphertext)

	out := make([]byte, 1, 1+len(iv)+len(ciphertext)+sha256.Size)
	out[0] = 2
	out = append(out, iv...)
	out = append(out, h.Sum(nil)...)
	return append(out, ciphertext...), nil
}

// DecryptAttachment decrypts an attachment file: raw bytes in the form
// 0x02 || IV || MAC || ciphertext (AES-256-CBC + HMAC-SHA256), as Bitwarden stores
// attachment files.  The MAC is verified before anything is decrypted.
func DecryptAttachment(data []byte, key []byte) ([]byte, error) {
	if len(key) != 64 {
		return nil, fmt.Errorf("key must be 64 bytes for attachments (32 enc + 32 mac), got %d", len(key))
	}
	if len(data) < 1+2*aes.BlockSize+sha256.Size {
		return nil, fmt.Errorf("attachment file is too short: %d bytes", len(data))
	}

	if data[0] != 2 {
		return nil, fmt.Errorf("unsupported attachment encryption type: %d", data[0])
	}
	iv := data[1 : 1+aes.BlockSize]
	mac := data[1+aes.BlockSize : 1+aes.BlockSize+sha256.Size]
	ciphertext := data[1+aes.BlockSize+sha256.Size:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("attachment ciphertext block size invalid")
	}

	h := hmac.New(sha256.New, key[32:])
	h.Write(iv)
	h.Write(ciphertext)
	if !hmac.Equal(mac, h.Sum(nil)) {
		return nil, errors.New("HMAC verification failed")
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext)
}

// Encrypt encrypts plaintext with AES-256-CBC and authenticates with HMAC-SHA256.
// key must be exactly 64 bytes: key[:32] is the AES encryption key and key[32:]
// is the HMAC-SHA256 key. Returns a Bitwarden type-2 cipher string:
//
//	"2.<base64(IV)>|<base64(ciphertext)>|<base64(MAC)>"
func Encrypt(plaintext []byte, key []byte) (string, error) {
	if len(key) != 64 {
		return "", fmt.Errorf("key must be 64 bytes for type 2 (32 enc + 32 mac), got %d", len(key))
	}
	encKey := key[:32]
	macKey := key[32:]

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}

	padded := pkcs7Pad(plaintext)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ciphertext)
	mac := h.Sum(nil)

	return "2." +
		base64.StdEncoding.EncodeToString(iv) + "|" +
		base64.StdEncoding.EncodeToString(ciphertext) + "|" +
		base64.StdEncoding.EncodeToString(mac), nil
}
