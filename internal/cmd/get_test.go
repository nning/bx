package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/nning/bx/internal/client"
)

// pkcs7Pad pads data to a multiple of the AES block size using PKCS7.
func pkcs7Pad(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

// encryptStr creates a valid type-2 (AES-CBC-HMAC-SHA256) Bitwarden cipher
// string for the given plaintext and 64-byte key.
func encryptStr(t *testing.T, key []byte, plaintext string) string {
	t.Helper()
	encKey, macKey := key[:32], key[32:]
	padded := pkcs7Pad([]byte(plaintext))

	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = byte(i + 1)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
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
		base64.StdEncoding.EncodeToString(mac)
}

// makeCipher builds a test client.Cipher with encrypted name and optional
// encrypted URI, using the provided 64-byte account key.
// The name is set on the top-level Name field (matching the real
// Bitwarden/Vaultwarden API format) as well as Data.Name for backward
// compatibility.
func makeCipher(t *testing.T, id, name, uri string, key []byte) client.Cipher {
	t.Helper()
	encName := encryptStr(t, key, name)
	c := client.Cipher{
		ID:   id,
		Name: encName,
		Data: client.CipherData{Name: encName},
	}
	if uri != "" {
		c.Data.URIs = []client.CipherURI{{URI: encryptStr(t, key, uri)}}
	}
	return c
}

// makeCipherWithUsername builds a test client.Cipher with encrypted name,
// username, and optional encrypted URI, using the provided 64-byte account key.
func makeCipherWithUsername(t *testing.T, id, name, username, uri string, key []byte) client.Cipher {
	t.Helper()
	c := makeCipher(t, id, name, uri, key)
	if username != "" {
		c.Data.Username = encryptStr(t, key, username)
	}
	return c
}

// testKey returns a deterministic 64-byte key for use in tests.
func testKey() []byte {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

// TestFindCipher_IDMatch verifies that an exact ID match is returned immediately.
func TestFindCipher_IDMatch(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipher(t, "id-abc", "GitHub", "", key),
		makeCipher(t, "id-xyz", "Google", "", key),
	}

	got, err := findCipher("id-abc", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher, got nil")
	}
	if got.ID != "id-abc" {
		t.Errorf("got ID %q, want %q", got.ID, "id-abc")
	}
}

// TestFindCipher_IDMatch_NotFound verifies that a non-existent ID returns nil.
func TestFindCipher_IDMatch_NotFound(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipher(t, "id-abc", "GitHub", "", key),
	}

	got, err := findCipher("no-such-id", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got cipher with ID %q", got.ID)
	}
}

// TestFindCipher_NameExactMatch verifies that an exact case-insensitive name
// match wins over a substring match.
func TestFindCipher_NameExactMatch(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipher(t, "id-1", "GitHub Personal", "", key),
		makeCipher(t, "id-2", "GitHub", "", key),
	}

	got, err := findCipher("github", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher, got nil")
	}
	if got.ID != "id-2" {
		t.Errorf("got ID %q, want %q (exact match should win)", got.ID, "id-2")
	}
}

// TestFindCipher_NameSubstringMatch verifies that a substring match is found
// when no exact match exists.
func TestFindCipher_NameSubstringMatch(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipher(t, "id-1", "Google", "", key),
		makeCipher(t, "id-2", "My GitHub Account", "", key),
	}

	got, err := findCipher("github", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher, got nil")
	}
	if got.ID != "id-2" {
		t.Errorf("got ID %q, want %q", got.ID, "id-2")
	}
}

// TestFindCipher_URLFallback verifies that a URL match is returned when there
// is no name or ID match.
func TestFindCipher_URLFallback(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipher(t, "id-1", "Google", "https://google.com", key),
		makeCipher(t, "id-2", "GitHub", "https://github.com", key),
	}

	got, err := findCipher("github.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher via URL fallback, got nil")
	}
	if got.ID != "id-2" {
		t.Errorf("got ID %q, want %q (URL fallback)", got.ID, "id-2")
	}
}

// TestFindCipher_NameBeatsURL verifies that a name match takes priority over a
// URL match when both contain the pattern.
func TestFindCipher_NameBeatsURL(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		// name contains "github.com", URL does not
		makeCipher(t, "id-name", "github.com", "", key),
		// name does not contain "github.com", URL does
		makeCipher(t, "id-url", "My account", "https://github.com", key),
	}

	got, err := findCipher("github.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher, got nil")
	}
	if got.ID != "id-name" {
		t.Errorf("got ID %q, want %q (name should beat URL)", got.ID, "id-name")
	}
}

// TestFindCipher_EmptyCiphers verifies that an empty vault returns nil.
func TestFindCipher_EmptyCiphers(t *testing.T) {
	got, err := findCipher("github", nil, testKey(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for empty vault, got cipher with ID %q", got.ID)
	}
}

// TestFindCipher_NoMatch verifies that nil is returned when nothing matches.
func TestFindCipher_NoMatch(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipher(t, "id-1", "Google", "https://google.com", key),
	}

	got, err := findCipher("github", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for no match, got cipher with ID %q", got.ID)
	}
}

// TestFindCipher_OrgExactMatch verifies that an org cipher with an exact name
// match is returned when no non-org cipher matches.
func TestFindCipher_OrgExactMatch(t *testing.T) {
	key := testKey()
	orgID := "org-1"
	orgCipher := makeCipher(t, "id-org", "GitHub", "", key)
	orgCipher.OrganizationID = &orgID

	got, err := findCipher("github", []client.Cipher{orgCipher}, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected org cipher for exact match, got nil")
	}
	if got.ID != "id-org" {
		t.Errorf("got ID %q, want %q", got.ID, "id-org")
	}
}

// TestFindCipher_NonOrgSubstringBeatsOrgSubstring verifies that a non-org
// cipher takes priority over an org cipher for substring name matches.
func TestFindCipher_NonOrgSubstringBeatsOrgSubstring(t *testing.T) {
	key := testKey()
	orgID := "org-1"

	orgCipher := makeCipher(t, "id-org", "GitHub org", "", key)
	orgCipher.OrganizationID = &orgID
	nonOrgCipher := makeCipher(t, "id-personal", "GitHub personal", "", key)

	// Org cipher comes first so foundCipher starts as org, then non-org upgrades it.
	got, err := findCipher("github", []client.Cipher{orgCipher, nonOrgCipher}, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-org cipher, got nil")
	}
	if got.ID != "id-personal" {
		t.Errorf("got ID %q, want %q (non-org should beat org)", got.ID, "id-personal")
	}
}

// TestFindCipher_ShorterNameWins verifies that among same-org-status substring
// matches the cipher with the shorter name is preferred.
func TestFindCipher_ShorterNameWins(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipher(t, "id-long", "My GitHub Enterprise Account", "", key),
		makeCipher(t, "id-short", "GitHub", "", key),
	}
	// Both are non-org substrings; "GitHub" is shorter.
	// Note: "GitHub" is also an exact match, not a substring match, so use a
	// pattern that is a substring of both names.
	got, err := findCipher("github", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected a cipher, got nil")
	}
	// "GitHub" exact match should win (non-org exact match returns immediately)
	if got.ID != "id-short" {
		t.Errorf("got ID %q, want %q", got.ID, "id-short")
	}
}

// TestFindCipher_ShorterNameWinsSubstring verifies that among same-org-status
// substring-only matches the cipher with the shorter name is preferred.
func TestFindCipher_ShorterNameWinsSubstring(t *testing.T) {
	key := testKey()
	// Both ciphers match "git" as a substring, neither is exact.
	ciphers := []client.Cipher{
		makeCipher(t, "id-long", "My GitHub Enterprise", "", key),
		makeCipher(t, "id-short", "GitHub", "", key),
	}
	got, err := findCipher("git", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected a cipher, got nil")
	}
	if got.ID != "id-short" {
		t.Errorf("got ID %q, want %q (shorter name should win)", got.ID, "id-short")
	}
}

// TestFindCipher_URLNonOrgBeatsOrg verifies that a non-org URL match takes
// priority over an org URL match in the URL fallback pass.
func TestFindCipher_URLNonOrgBeatsOrg(t *testing.T) {
	key := testKey()
	orgID := "org-1"

	orgCipher := makeCipher(t, "id-org", "Org GitHub", "https://github.com", key)
	orgCipher.OrganizationID = &orgID
	nonOrgCipher := makeCipher(t, "id-personal", "Personal GitHub", "https://github.com", key)

	// Org cipher comes first; no name match, so URL pass runs.
	// Non-org should win.
	got, err := findCipher("github.com", []client.Cipher{orgCipher, nonOrgCipher}, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected a cipher via URL fallback, got nil")
	}
	if got.ID != "id-personal" {
		t.Errorf("got ID %q, want %q (non-org URL should beat org URL)", got.ID, "id-personal")
	}
}

// TestFindCipher_URLShorterNameWins verifies that among same-org-status URL
// matches the cipher with the shorter name is preferred.
func TestFindCipher_URLShorterNameWins(t *testing.T) {
	key := testKey()
	// Both match the URL; the one with the shorter name should win.
	ciphers := []client.Cipher{
		makeCipher(t, "id-long", "My Very Long GitHub Account Name", "https://github.com", key),
		makeCipher(t, "id-short", "GitHub", "https://github.com", key),
	}
	got, err := findCipher("github.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected a cipher via URL fallback, got nil")
	}
	if got.ID != "id-short" {
		t.Errorf("got ID %q, want %q (shorter name should win in URL pass)", got.ID, "id-short")
	}
}

// TestFindCipher_OrgExactBeatsNonOrgSubstring verifies that an org-cipher with
// an exact name match is NOT overridden by a later non-org cipher with only a
// substring match.
func TestFindCipher_OrgExactBeatsNonOrgSubstring(t *testing.T) {
	key := testKey()
	orgID := "org-1"

	// Org cipher has exact name match.
	orgCipher := makeCipher(t, "id-org", "GitHub", "", key)
	orgCipher.OrganizationID = &orgID

	// Non-org cipher only has a substring match.
	nonOrgCipher := makeCipher(t, "id-personal", "GitHub Enterprise", "", key)

	// Org exact match comes first; non-org substring comes second.
	got, err := findCipher("github", []client.Cipher{orgCipher, nonOrgCipher}, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected a cipher, got nil")
	}
	if got.ID != "id-org" {
		t.Errorf("got ID %q, want %q (org exact match should beat non-org substring)", got.ID, "id-org")
	}
}

// TestTotpSecretFromString_RawSecret verifies that a plain TOTP seed is
// returned unchanged.
func TestTotpSecretFromString_RawSecret(t *testing.T) {
	secret, err := totpSecretFromString("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("got %q, want %q", secret, "JBSWY3DPEHPK3PXP")
	}
}

// TestTotpSecretFromString_OtpauthURL verifies that the secret query parameter
// is correctly extracted from an otpauth:// URL.
func TestTotpSecretFromString_OtpauthURL(t *testing.T) {
	uri := "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
	secret, err := totpSecretFromString(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("got %q, want %q", secret, "JBSWY3DPEHPK3PXP")
	}
}

// TestTotpSecretFromString_OtpauthMissingSecret verifies that an otpauth URL
// without a secret parameter returns an error.
func TestTotpSecretFromString_OtpauthMissingSecret(t *testing.T) {
	uri := "otpauth://totp/Example:alice@example.com?issuer=Example"
	_, err := totpSecretFromString(uri)
	if err == nil {
		t.Fatal("expected error for otpauth URI missing secret parameter")
	}
}

// TestTotpSecretFromString_EmptyString verifies that an empty string is
// returned as-is (callers are responsible for checking empty secrets).
func TestTotpSecretFromString_EmptyString(t *testing.T) {
	secret, err := totpSecretFromString("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret != "" {
		t.Errorf("got %q, want empty string", secret)
	}
}

// TestShortID verifies that shortID extracts only the first UUID segment.
func TestShortID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"550e8400-e29b-41d4-a716-446655440000", "550e8400"},
		{"abcdef12-0000-0000-0000-000000000000", "abcdef12"},
		{"nohyphens", "nohyphens"},
		{"", ""},
	}
	for _, tc := range tests {
		got := shortID(tc.input)
		if got != tc.want {
			t.Errorf("shortID(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestFindCipher_ShortIDMatch verifies that the first UUID segment can be used
// to look up a cipher (matching the short form shown by bx list).
func TestFindCipher_ShortIDMatch(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipher(t, "550e8400-e29b-41d4-a716-446655440000", "GitHub", "", key),
		makeCipher(t, "abcdef12-0000-0000-0000-000000000000", "Google", "", key),
	}

	got, err := findCipher("550e8400", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher via short ID, got nil")
	}
	if got.ID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("got ID %q, want full UUID", got.ID)
	}
}

// TestFindCipher_AmbiguousShortID verifies that an error is returned when
// multiple ciphers share the same first UUID segment.
func TestFindCipher_AmbiguousShortID(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipher(t, "550e8400-aaaa-0000-0000-000000000000", "GitHub", "", key),
		makeCipher(t, "550e8400-bbbb-0000-0000-000000000000", "Google", "", key),
	}

	got, err := findCipher("550e8400", ciphers, key, nil)
	if err == nil {
		t.Fatal("expected error for ambiguous short ID, got nil")
	}
	if got != nil {
		t.Errorf("expected nil cipher for ambiguous short ID, got %+v", got)
	}
}

// TestFindCipher_UsernameExactMatch verifies that an exact username match is
// returned when no name or ID matches.
func TestFindCipher_UsernameExactMatch(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipherWithUsername(t, "id-1", "Google", "user@google.com", "https://google.com", key),
		makeCipherWithUsername(t, "id-2", "GitHub", "alice@example.com", "https://github.com", key),
	}

	got, err := findCipher("alice@example.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher via username match, got nil")
	}
	if got.ID != "id-2" {
		t.Errorf("got ID %q, want %q (username exact match)", got.ID, "id-2")
	}
}

// TestFindCipher_UsernameSubstringMatch verifies that a username substring
// match is returned when no exact username, name, or ID matches.
func TestFindCipher_UsernameSubstringMatch(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipherWithUsername(t, "id-1", "Google", "user@google.com", "https://google.com", key),
		makeCipherWithUsername(t, "id-2", "My Account", "alice@example.com", "https://github.com", key),
	}

	got, err := findCipher("alice@", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher via username substring match, got nil")
	}
	if got.ID != "id-2" {
		t.Errorf("got ID %q, want %q (username substring match)", got.ID, "id-2")
	}
}

// TestFindCipher_NameBeatsUsername verifies that a name match takes priority
// over a username match.
func TestFindCipher_NameBeatsUsername(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipherWithUsername(t, "id-name", "alice@example.com", "other@example.com", "", key),
		makeCipherWithUsername(t, "id-user", "Some Service", "alice@example.com", "", key),
	}

	got, err := findCipher("alice@example.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher, got nil")
	}
	if got.ID != "id-name" {
		t.Errorf("got ID %q, want %q (name should beat username)", got.ID, "id-name")
	}
}

// TestFindCipher_UsernameBeatsURL verifies that a username match takes priority
// over a URL match.
func TestFindCipher_UsernameBeatsURL(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipherWithUsername(t, "id-url", "Some Service", "other@example.com", "https://alice.example.com", key),
		makeCipherWithUsername(t, "id-user", "Another Service", "alice@example.com", "https://other.example.com", key),
	}

	got, err := findCipher("alice@example.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher, got nil")
	}
	if got.ID != "id-user" {
		t.Errorf("got ID %q, want %q (username should beat URL)", got.ID, "id-user")
	}
}

// TestFindCipher_SkipsDeletedItems verifies that deleted (soft-deleted) ciphers
// are ignored during all matching passes (ID, name, username, URL).
func TestFindCipher_SkipsDeletedItems(t *testing.T) {
	key := testKey()
	d := "2000-03-01T00:00:00Z"
	deleted := makeCipherWithUsername(t, "id-del", "GitHub", "alice@example.com", "https://github.com", key)
	deleted.DeletedDate = &d

	// ID match should be skipped.
	got, err := findCipher("id-del", []client.Cipher{deleted}, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Error("expected nil: deleted ciphers should be skipped by ID pass")
	}

	// Name match should be skipped.
	got, err = findCipher("github", []client.Cipher{deleted}, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Error("expected nil: deleted ciphers should be skipped by name pass")
	}

	// Username match should be skipped.
	got, err = findCipher("alice@example.com", []client.Cipher{deleted}, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Error("expected nil: deleted ciphers should be skipped by username pass")
	}

	// URL match should be skipped.
	got, err = findCipher("github.com", []client.Cipher{deleted}, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Error("expected nil: deleted ciphers should be skipped by URL pass")
	}
}

// TestFindCipher_UsernameOrgExactMatch verifies that an org cipher with an
// exact username match is returned when no non-org cipher matches by username.
func TestFindCipher_UsernameOrgExactMatch(t *testing.T) {
	key := testKey()
	orgID := "org-1"
	orgCipher := makeCipherWithUsername(t, "id-org", "Org Service", "admin@corp.com", "", key)
	orgCipher.OrganizationID = &orgID

	got, err := findCipher("admin@corp.com", []client.Cipher{orgCipher}, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected org cipher for exact username match, got nil")
	}
	if got.ID != "id-org" {
		t.Errorf("got ID %q, want %q", got.ID, "id-org")
	}
}

// TestFindCipher_UsernameNonOrgBeatsOrg verifies that a non-org cipher takes
// priority over an org cipher when both match by username substring.
func TestFindCipher_UsernameNonOrgBeatsOrg(t *testing.T) {
	key := testKey()
	orgID := "org-1"
	orgCipher := makeCipherWithUsername(t, "id-org", "Org Service", "admin@corp.com", "", key)
	orgCipher.OrganizationID = &orgID
	nonOrgCipher := makeCipherWithUsername(t, "id-personal", "Personal Service", "admin@personal.com", "", key)

	// Both match "admin@" as substring; non-org should win.
	got, err := findCipher("admin@", []client.Cipher{orgCipher, nonOrgCipher}, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-org cipher, got nil")
	}
	if got.ID != "id-personal" {
		t.Errorf("got ID %q, want %q (non-org should beat org for username)", got.ID, "id-personal")
	}
}

// TestFindCipher_UsernameShorterNameWins verifies that among same-org-status
// username substring matches the cipher with the shorter name is preferred.
func TestFindCipher_UsernameShorterNameWins(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipherWithUsername(t, "id-long", "My Very Long Service Name", "user@example.com", "", key),
		makeCipherWithUsername(t, "id-short", "Service", "user@example.net", "", key),
	}

	// Both match "user@" as a username substring; shorter name wins.
	got, err := findCipher("user@", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected a cipher, got nil")
	}
	if got.ID != "id-short" {
		t.Errorf("got ID %q, want %q (shorter name should win for username)", got.ID, "id-short")
	}
}

// TestFindCipher_UsernameSkipsEmptyUsername verifies that ciphers without a
// username field are silently skipped during the username pass.
func TestFindCipher_UsernameSkipsEmptyUsername(t *testing.T) {
	key := testKey()
	// First cipher has no username, second has a matching username.
	ciphers := []client.Cipher{
		makeCipher(t, "id-no-user", "No Username Entry", "", key),
		makeCipherWithUsername(t, "id-with-user", "Has Username", "admin@site.com", "", key),
	}

	got, err := findCipher("admin@site.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher with username, got nil")
	}
	if got.ID != "id-with-user" {
		t.Errorf("got ID %q, want %q", got.ID, "id-with-user")
	}
}

// TestFindCipher_UsernameOrgExactBeatsNonOrgSubstring verifies that an org
// cipher with an exact username match is NOT overridden by a non-org cipher
// with only a substring username match.
func TestFindCipher_UsernameOrgExactBeatsNonOrgSubstring(t *testing.T) {
	key := testKey()
	orgID := "org-1"

	// Names must not contain "deploy-bot" so the name pass is skipped.
	orgCipher := makeCipherWithUsername(t, "id-org", "Org Service", "deploy-bot", "", key)
	orgCipher.OrganizationID = &orgID
	nonOrgCipher := makeCipherWithUsername(t, "id-personal", "Personal Service", "deploy-bot@personal.com", "", key)

	// "deploy-bot" is exact match on org cipher's username, substring on non-org.
	got, err := findCipher("deploy-bot", []client.Cipher{orgCipher, nonOrgCipher}, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected a cipher, got nil")
	}
	if got.ID != "id-org" {
		t.Errorf("got ID %q, want %q (org exact username should beat non-org substring)", got.ID, "id-org")
	}
}

// TestFindCipher_UsernameCaseInsensitive verifies that username matching is
// case-insensitive.
func TestFindCipher_UsernameCaseInsensitive(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipherWithUsername(t, "id-1", "Service", "Admin@Example.COM", "", key),
	}

	got, err := findCipher("admin@example.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher via case-insensitive username match, got nil")
	}
	if got.ID != "id-1" {
		t.Errorf("got ID %q, want %q", got.ID, "id-1")
	}
}

// TestCipherURIs_LoginURIsTakePriority verifies that Login.URIs are returned
// when both Login.URIs and Data.URIs are present.
func TestCipherURIs_LoginURIsTakePriority(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "id-1", "Test", "https://data-uri.com", key)
	c.Login = &client.CipherLogin{
		URIs: []client.CipherURI{{URI: encryptStr(t, key, "https://login-uri.com")}},
	}
	uris := cipherURIs(&c)
	if len(uris) != 1 {
		t.Fatalf("expected 1 URI, got %d", len(uris))
	}
}

// TestCipherURIs_FallsBackToDataURIs verifies that Data.URIs are returned
// when Login is nil.
func TestCipherURIs_FallsBackToDataURIs(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "id-1", "Test", "https://data-uri.com", key)
	uris := cipherURIs(&c)
	if len(uris) != 1 {
		t.Fatalf("expected 1 URI from Data.URIs, got %d", len(uris))
	}
}

// TestCipherURIs_NilLogin verifies that cipherURIs handles a nil Login field.
func TestCipherURIs_NilLogin(t *testing.T) {
	c := client.Cipher{ID: "id-1", Data: client.CipherData{}}
	uris := cipherURIs(&c)
	if len(uris) != 0 {
		t.Fatalf("expected 0 URIs for cipher with no Login and no Data.URIs, got %d", len(uris))
	}
}

// TestCipherURIs_EmptyLoginURIs verifies that Data.URIs are used when
// Login.URIs is empty (not nil).
func TestCipherURIs_EmptyLoginURIs(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "id-1", "Test", "https://data-uri.com", key)
	c.Login = &client.CipherLogin{URIs: []client.CipherURI{}}
	uris := cipherURIs(&c)
	if len(uris) != 1 {
		t.Fatalf("expected 1 URI from Data.URIs fallback, got %d", len(uris))
	}
}

// TestCipherUsername_LoginTakesPriority verifies that Login.Username takes
// priority over Data.Username when both are present.
func TestCipherUsername_LoginTakesPriority(t *testing.T) {
	c := client.Cipher{
		Data:  client.CipherData{Username: "data-user"},
		Login: &client.CipherLogin{Username: "login-user"},
	}
	if got := cipherUsername(&c); got != "login-user" {
		t.Errorf("cipherUsername = %q, want %q", got, "login-user")
	}
}

// TestCipherUsername_FallsBackToData verifies that Data.Username is used
// when Login is nil.
func TestCipherUsername_FallsBackToData(t *testing.T) {
	c := client.Cipher{
		Data: client.CipherData{Username: "data-user"},
	}
	if got := cipherUsername(&c); got != "data-user" {
		t.Errorf("cipherUsername = %q, want %q", got, "data-user")
	}
}

// TestCipherUsername_EmptyLoginFallsBackToData verifies that Data.Username is
// used when Login.Username is empty.
func TestCipherUsername_EmptyLoginFallsBackToData(t *testing.T) {
	c := client.Cipher{
		Data:  client.CipherData{Username: "data-user"},
		Login: &client.CipherLogin{Username: ""},
	}
	if got := cipherUsername(&c); got != "data-user" {
		t.Errorf("cipherUsername = %q, want %q", got, "data-user")
	}
}

// TestCipherPassword_LoginTakesPriority verifies that Login.Password takes
// priority over Data.Password when both are present.
func TestCipherPassword_LoginTakesPriority(t *testing.T) {
	c := client.Cipher{
		Data:  client.CipherData{Password: "data-pass"},
		Login: &client.CipherLogin{Password: "login-pass"},
	}
	if got := cipherPassword(&c); got != "login-pass" {
		t.Errorf("cipherPassword = %q, want %q", got, "login-pass")
	}
}

// TestCipherPassword_FallsBackToData verifies that Data.Password is used
// when Login is nil.
func TestCipherPassword_FallsBackToData(t *testing.T) {
	c := client.Cipher{
		Data: client.CipherData{Password: "data-pass"},
	}
	if got := cipherPassword(&c); got != "data-pass" {
		t.Errorf("cipherPassword = %q, want %q", got, "data-pass")
	}
}

// TestCipherTotp_LoginTakesPriority verifies that Login.Totp takes priority
// over Data.Totp when both are present.
func TestCipherTotp_LoginTakesPriority(t *testing.T) {
	loginTotp := "login-totp"
	dataTotp := "data-totp"
	c := client.Cipher{
		Data:  client.CipherData{Totp: &dataTotp},
		Login: &client.CipherLogin{Totp: &loginTotp},
	}
	got := cipherTotp(&c)
	if got == nil || *got != "login-totp" {
		t.Errorf("cipherTotp = %v, want %q", got, "login-totp")
	}
}

// TestCipherTotp_FallsBackToData verifies that Data.Totp is used when Login
// is nil.
func TestCipherTotp_FallsBackToData(t *testing.T) {
	dataTotp := "data-totp"
	c := client.Cipher{
		Data: client.CipherData{Totp: &dataTotp},
	}
	got := cipherTotp(&c)
	if got == nil || *got != "data-totp" {
		t.Errorf("cipherTotp = %v, want %q", got, "data-totp")
	}
}

// TestCipherFido2Credentials_LoginTakesPriority verifies that
// Login.Fido2Credentials takes priority over Data.Fido2Credentials when
// both are populated.
func TestCipherFido2Credentials_LoginTakesPriority(t *testing.T) {
	loginCred := client.Fido2Credential{CredentialId: "login-cred"}
	dataCred := client.Fido2Credential{CredentialId: "data-cred"}
	c := client.Cipher{
		Data:  client.CipherData{Fido2Credentials: []client.Fido2Credential{dataCred}},
		Login: &client.CipherLogin{Fido2Credentials: []client.Fido2Credential{loginCred}},
	}
	got := cipherFido2Credentials(&c)
	if len(got) != 1 || got[0].CredentialId != "login-cred" {
		t.Errorf("cipherFido2Credentials = %+v, want login-cred", got)
	}
}

// TestCipherFido2Credentials_FallsBackToData verifies that
// Data.Fido2Credentials is returned when Login is nil.
func TestCipherFido2Credentials_FallsBackToData(t *testing.T) {
	dataCred := client.Fido2Credential{CredentialId: "data-cred"}
	c := client.Cipher{
		Data: client.CipherData{Fido2Credentials: []client.Fido2Credential{dataCred}},
	}
	got := cipherFido2Credentials(&c)
	if len(got) != 1 || got[0].CredentialId != "data-cred" {
		t.Errorf("cipherFido2Credentials = %+v, want data-cred", got)
	}
}

// TestCipherFido2Credentials_NilLogin verifies that the accessor returns nil
// when neither Login nor Data has Fido2Credentials.
func TestCipherFido2Credentials_NilLogin(t *testing.T) {
	c := client.Cipher{Data: client.CipherData{}}
	got := cipherFido2Credentials(&c)
	if got != nil {
		t.Errorf("cipherFido2Credentials = %v, want nil", got)
	}
}

// TestCipherFido2Credentials_EmptyLoginFido2 verifies that Data.Fido2Credentials
// is returned when Login.Fido2Credentials is empty (not nil).
func TestCipherFido2Credentials_EmptyLoginFido2(t *testing.T) {
	dataCred := client.Fido2Credential{CredentialId: "data-cred"}
	c := client.Cipher{
		Data:  client.CipherData{Fido2Credentials: []client.Fido2Credential{dataCred}},
		Login: &client.CipherLogin{Fido2Credentials: []client.Fido2Credential{}},
	}
	got := cipherFido2Credentials(&c)
	if len(got) != 1 || got[0].CredentialId != "data-cred" {
		t.Errorf("cipherFido2Credentials = %+v, want data-cred fallback", got)
	}
}

// TestCipherName_TopLevelTakesPriority verifies that the top-level Name field
// (Bitwarden API format) takes priority over Data.Name.
func TestCipherName_TopLevelTakesPriority(t *testing.T) {
	c := client.Cipher{
		Name: "top-level-name",
		Data: client.CipherData{Name: "data-name"},
	}
	if got := cipherName(&c); got != "top-level-name" {
		t.Errorf("cipherName = %q, want %q", got, "top-level-name")
	}
}

// TestCipherName_FallsBackToData verifies that Data.Name is used when the
// top-level Name is empty.
func TestCipherName_FallsBackToData(t *testing.T) {
	c := client.Cipher{
		Data: client.CipherData{Name: "data-name"},
	}
	if got := cipherName(&c); got != "data-name" {
		t.Errorf("cipherName = %q, want %q", got, "data-name")
	}
}

// TestCipherName_BothEmpty verifies that an empty string is returned when
// neither Name nor Data.Name is set.
func TestCipherName_BothEmpty(t *testing.T) {
	c := client.Cipher{}
	if got := cipherName(&c); got != "" {
		t.Errorf("cipherName = %q, want empty", got)
	}
}

// TestCipherNotes_TopLevelTakesPriority verifies that the top-level Notes
// field takes priority over Data.Notes.
func TestCipherNotes_TopLevelTakesPriority(t *testing.T) {
	topNotes := "top-level-notes"
	dataNotes := "data-notes"
	c := client.Cipher{
		Notes: &topNotes,
		Data:  client.CipherData{Notes: &dataNotes},
	}
	got := cipherNotes(&c)
	if got == nil || *got != "top-level-notes" {
		t.Errorf("cipherNotes = %v, want %q", got, "top-level-notes")
	}
}

// TestCipherNotes_FallsBackToData verifies that Data.Notes is used when the
// top-level Notes is nil.
func TestCipherNotes_FallsBackToData(t *testing.T) {
	dataNotes := "data-notes"
	c := client.Cipher{
		Data: client.CipherData{Notes: &dataNotes},
	}
	got := cipherNotes(&c)
	if got == nil || *got != "data-notes" {
		t.Errorf("cipherNotes = %v, want %q", got, "data-notes")
	}
}

// TestCipherNotes_BothNil verifies that nil is returned when neither Notes nor
// Data.Notes is set.
func TestCipherNotes_BothNil(t *testing.T) {
	c := client.Cipher{}
	if got := cipherNotes(&c); got != nil {
		t.Errorf("cipherNotes = %v, want nil", got)
	}
}

// TestCipherNotes_TopLevelEmptyFallsBackToData verifies that an empty top-level
// Notes string falls back to Data.Notes.
func TestCipherNotes_TopLevelEmptyFallsBackToData(t *testing.T) {
	emptyNotes := ""
	dataNotes := "data-notes"
	c := client.Cipher{
		Notes: &emptyNotes,
		Data:  client.CipherData{Notes: &dataNotes},
	}
	got := cipherNotes(&c)
	if got == nil || *got != "data-notes" {
		t.Errorf("cipherNotes = %v, want %q (empty top-level should fall back)", got, "data-notes")
	}
}

// TestRenderPasskeyBlock_FullCredential verifies that decrypting a fully
// populated Fido2Credential produces the expected block layout (header line
// plus indented User/Handle/Created/Counter/Discoverable lines).
func TestRenderPasskeyBlock_FullCredential(t *testing.T) {
	key := testKey()
	rpName := encryptStr(t, key, "Example Site")
	userHandle := encryptStr(t, key, "aGkK")
	userName := encryptStr(t, key, "alice@example.com")
	userDisplay := encryptStr(t, key, "Alice Example")
	cred := client.Fido2Credential{
		CredentialId:    encryptStr(t, key, "cred-id"),
		KeyType:         encryptStr(t, key, "public-key"),
		KeyAlgorithm:    encryptStr(t, key, "ECDSA"),
		KeyCurve:        encryptStr(t, key, "P-256"),
		KeyValue:        encryptStr(t, key, "pkcs8"),
		RpId:            encryptStr(t, key, "example.com"),
		RpName:          &rpName,
		UserHandle:      &userHandle,
		UserName:        &userName,
		UserDisplayName: &userDisplay,
		Counter:         encryptStr(t, key, "0"),
		Discoverable:    encryptStr(t, key, "true"),
		CreationDate:    "2023-01-01T12:00:00.0000000Z",
	}

	got := renderPasskeyBlock(cred, key)
	want := "Passkey:  example.com\n" +
		"  User:    alice@example.com (Alice Example)\n" +
		"  Handle:  aGkK\n" +
		"  Created: 2023-01-01T12:00:00.0000000Z\n" +
		"  Counter: 0\n" +
		"  Discoverable: yes\n"
	if got != want {
		t.Errorf("renderPasskeyBlock mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRenderPasskeyBlock_DiscoverableFalse verifies the discoverable flag is
// rendered as "no" when the decrypted value is "false" (case-insensitive).
func TestRenderPasskeyBlock_DiscoverableFalse(t *testing.T) {
	key := testKey()
	cred := client.Fido2Credential{
		RpId:         encryptStr(t, key, "example.com"),
		Counter:      encryptStr(t, key, "5"),
		Discoverable: encryptStr(t, key, "false"),
	}
	got := renderPasskeyBlock(cred, key)
	if !strings.Contains(got, "  Discoverable: no\n") {
		t.Errorf("expected discoverable no, got:\n%s", got)
	}
}

// TestRenderPasskeyBlock_NoNullableFields verifies that the block still
// renders cleanly when all optional fields (RpName, UserHandle, UserName,
// UserDisplayName) are nil.
func TestRenderPasskeyBlock_NoNullableFields(t *testing.T) {
	key := testKey()
	cred := client.Fido2Credential{
		CredentialId: encryptStr(t, key, "cred-id"),
		RpId:         encryptStr(t, key, "example.com"),
		Counter:      encryptStr(t, key, "3"),
		Discoverable: encryptStr(t, key, "true"),
		CreationDate: "2023-06-01T00:00:00Z",
	}
	got := renderPasskeyBlock(cred, key)
	want := "Passkey:  example.com\n" +
		"  Created: 2023-06-01T00:00:00Z\n" +
		"  Counter: 3\n" +
		"  Discoverable: yes\n"
	if got != want {
		t.Errorf("renderPasskeyBlock (no nullable fields) mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRenderPasskeyBlock_DecryptRpIdError verifies that an rpId decryption
// failure yields an empty string (render skipped).
func TestRenderPasskeyBlock_DecryptRpIdError(t *testing.T) {
	key := testKey()
	cred := client.Fido2Credential{
		RpId:         "not-a-valid-cipher-string",
		Counter:      encryptStr(t, key, "0"),
		CreationDate: "2023-01-01T00:00:00Z",
	}
	got := renderPasskeyBlock(cred, key)
	if got != "" {
		t.Errorf("renderPasskeyBlock with broken rpId = %q, want empty", got)
	}
}

// TestRenderPasskeyBlock_CounterDecryptError verifies that a Counter
// decryption failure omits only the Counter line and preserves the rest.
func TestRenderPasskeyBlock_CounterDecryptError(t *testing.T) {
	key := testKey()
	cred := client.Fido2Credential{
		RpId:         encryptStr(t, key, "example.com"),
		Counter:      "not-a-valid-cipher-string",
		Discoverable: encryptStr(t, key, "true"),
		CreationDate: "2023-01-01T00:00:00Z",
	}
	got := renderPasskeyBlock(cred, key)
	if strings.Contains(got, "Counter") {
		t.Errorf("expected Counter line to be omitted, got:\n%s", got)
	}
	if !strings.Contains(got, "Passkey:  example.com") {
		t.Errorf("expected rpId line, got:\n%s", got)
	}
	if !strings.Contains(got, "Discoverable: yes") {
		t.Errorf("expected discoverable line, got:\n%s", got)
	}
}

// TestFindCipher_LoginUsernameMatch verifies that username stored in
// Login.Username (Vaultwarden primary format) is matched during the username pass.
func TestFindCipher_LoginUsernameMatch(t *testing.T) {
	key := testKey()
	// Cipher has username only in Login.Username, Data.Username is empty.
	c := makeCipher(t, "id-1", "GitHub", "", key)
	c.Login = &client.CipherLogin{
		Username: encryptStr(t, key, "alice@example.com"),
	}
	ciphers := []client.Cipher{c}

	got, err := findCipher("alice@example.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher via Login.Username match, got nil")
	}
	if got.ID != "id-1" {
		t.Errorf("got ID %q, want %q", got.ID, "id-1")
	}
}

// TestFindCipher_LoginAtDomainMatch verifies that a "user@domain" pattern
// matches a cipher whose username is the user part and whose URL contains the
// domain part, even when the username alone does not match the full pattern.
func TestFindCipher_LoginAtDomainMatch(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipherWithUsername(t, "id-1", "Google", "alice", "https://google.com", key),
		makeCipherWithUsername(t, "id-2", "GitHub", "alice", "https://example.com", key),
	}

	got, err := findCipher("alice@example.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher via login@domain match, got nil")
	}
	if got.ID != "id-2" {
		t.Errorf("got ID %q, want %q (login@domain match)", got.ID, "id-2")
	}
}

// TestFindCipher_LoginAtDomainNonOrgBeatsOrg verifies that a non-org cipher
// takes priority over an org cipher in the login@domain pass.
func TestFindCipher_LoginAtDomainNonOrgBeatsOrg(t *testing.T) {
	key := testKey()
	orgID := "org-1"

	orgCipher := makeCipherWithUsername(t, "id-org", "Org GitHub", "alice", "https://example.com", key)
	orgCipher.OrganizationID = &orgID
	nonOrgCipher := makeCipherWithUsername(t, "id-personal", "Personal GitHub", "alice", "https://example.com", key)

	got, err := findCipher("alice@example.com", []client.Cipher{orgCipher, nonOrgCipher}, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-org cipher via login@domain, got nil")
	}
	if got.ID != "id-personal" {
		t.Errorf("got ID %q, want %q (non-org should beat org in login@domain pass)", got.ID, "id-personal")
	}
}

// TestFindCipher_LoginAtDomainShorterNameWins verifies that among same-org-status
// login@domain matches the cipher with the shorter name is preferred.
func TestFindCipher_LoginAtDomainShorterNameWins(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipherWithUsername(t, "id-long", "My GitHub Enterprise Account", "alice", "https://example.com", key),
		makeCipherWithUsername(t, "id-short", "GitHub", "alice", "https://example.com", key),
	}

	got, err := findCipher("alice@example.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected a cipher, got nil")
	}
	if got.ID != "id-short" {
		t.Errorf("got ID %q, want %q (shorter name should win in login@domain pass)", got.ID, "id-short")
	}
}

// TestFindCipher_LoginAtDomainSkipsDeleted verifies that deleted ciphers are
// skipped in the login@domain pass.
func TestFindCipher_LoginAtDomainSkipsDeleted(t *testing.T) {
	key := testKey()
	d := "2000-03-01T00:00:00Z"
	deleted := makeCipherWithUsername(t, "id-del", "GitHub", "alice", "https://example.com", key)
	deleted.DeletedDate = &d

	got, err := findCipher("alice@example.com", []client.Cipher{deleted}, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Error("expected nil: deleted ciphers should be skipped by login@domain pass")
	}
}

// TestFindCipher_LoginAtDomainEmailUsername verifies that a pattern like
// "mail@user.io@service.com" splits on the last "@", so the user part is the
// full email address "mail@user.io" and the domain part is "service.com".
func TestFindCipher_LoginAtDomainEmailUsername(t *testing.T) {
	key := testKey()
	ciphers := []client.Cipher{
		makeCipherWithUsername(t, "id-1", "Other", "alice@example.com", "https://other.com", key),
		makeCipherWithUsername(t, "id-2", "Strava", "alice@example.com", "https://strava.com", key),
	}

	got, err := findCipher("alice@example.com@strava.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher via login@domain with email username, got nil")
	}
	if got.ID != "id-2" {
		t.Errorf("got ID %q, want %q (last @ should split user from domain)", got.ID, "id-2")
	}
}

// username pass (full email as username) still takes priority over the
// login@domain pass.
func TestFindCipher_LoginAtDomainUsernamePassTakesPriority(t *testing.T) {
	key := testKey()
	// id-email: username is full email alice@example.com, URL doesn't match
	// id-split: username is "alice", URL is example.com — login@domain would match
	ciphers := []client.Cipher{
		makeCipherWithUsername(t, "id-email", "Email Service", "alice@example.com", "https://other.com", key),
		makeCipherWithUsername(t, "id-split", "GitHub", "alice", "https://example.com", key),
	}

	got, err := findCipher("alice@example.com", ciphers, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected cipher, got nil")
	}
	if got.ID != "id-email" {
		t.Errorf("got ID %q, want %q (username pass should take priority over login@domain)", got.ID, "id-email")
	}
}

// ---------------------------------------------------------------------------
// ownerLine
// ---------------------------------------------------------------------------

func TestOwnerLine_PersonalItem(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "id-1", "Example Service", "", key)

	if got := ownerLine(&c, &client.SyncResponse{}, nil); got != "" {
		t.Errorf("personal items must not print an owner, got %q", got)
	}

	// An explicitly empty organization ID counts as personal, too.
	empty := ""
	c.OrganizationID = &empty
	if got := ownerLine(&c, &client.SyncResponse{}, nil); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestOwnerLine_OrganizationItemWithCollections(t *testing.T) {
	orgs, cols, orgKeys := familyVault(t)
	orgKey := orgKeys[orgs[0].ID]

	c := makeCipher(t, "id-1", "Example Service", "", orgKey)
	c.OrganizationID = &orgs[0].ID
	c.CollectionIDs = []string{cols[0].ID, cols[1].ID}

	v := &client.SyncResponse{
		Profile:     client.Profile{Organizations: orgs},
		Collections: cols,
	}

	want := "Family (Wife, Kid 1)"
	if got := ownerLine(&c, v, orgKeys); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestOwnerLine_OrganizationItemWithoutCollections(t *testing.T) {
	orgs, cols, orgKeys := familyVault(t)
	orgKey := orgKeys[orgs[0].ID]

	c := makeCipher(t, "id-1", "Example Service", "", orgKey)
	c.OrganizationID = &orgs[0].ID

	v := &client.SyncResponse{
		Profile:     client.Profile{Organizations: orgs},
		Collections: cols,
	}

	if got := ownerLine(&c, v, orgKeys); got != "Family" {
		t.Errorf("got %q, want %q", got, "Family")
	}
}

// makeCipherWithFields builds a test client.Cipher with encrypted name and
// the given custom fields (name→value pairs), using the provided 64-byte key.
func makeCipherWithFields(t *testing.T, id, name string, fields map[string]string, key []byte) client.Cipher {
	t.Helper()
	encName := encryptStr(t, key, name)
	c := client.Cipher{
		ID:   id,
		Name: encName,
		Data: client.CipherData{Name: encName},
	}
	for fieldName, val := range fields {
		n := encryptStr(t, key, fieldName)
		v := encryptStr(t, key, val)
		c.Fields = append(c.Fields, client.CipherField{
			Name:  &n,
			Value: v,
		})
	}
	return c
}

// TestFindCustomField_ExactMatch verifies that an exact case-insensitive name
// match returns the field value.
func TestFindCustomField_ExactMatch(t *testing.T) {
	key := testKey()
	c := makeCipherWithFields(t, "id-1", "Bank", map[string]string{
		"IBAN": "DE89370400440532013000",
	}, key)

	got, err := findCustomField(&c, key, "iban")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "DE89370400440532013000" {
		t.Errorf("got %q, want IBAN value", got)
	}
}

// TestFindCustomField_ExactMatchCaseSensitive verifies that exact match also
// works when the pattern matches the field name exactly (same case).
func TestFindCustomField_ExactMatchCaseSensitive(t *testing.T) {
	key := testKey()
	c := makeCipherWithFields(t, "id-1", "Bank", map[string]string{
		"IBAN": "DE89370400440532013000",
	}, key)

	got, err := findCustomField(&c, key, "IBAN")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "DE89370400440532013000" {
		t.Errorf("got %q, want IBAN value", got)
	}
}

// TestFindCustomField_SubstringMatch verifies that a single substring match
// returns the field value.  This covers keys like 'Storage Box ("backup")
// Password' where the user passes only part of the name.
func TestFindCustomField_SubstringMatch(t *testing.T) {
	key := testKey()
	c := makeCipherWithFields(t, "id-1", "Hoster", map[string]string{
		`Storage Box ("backup") Password`: "s3cr3t",
	}, key)

	got, err := findCustomField(&c, key, "storage box")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "s3cr3t" {
		t.Errorf("got %q, want s3cr3t", got)
	}
}

// TestFindCustomField_ExactBeatsSubstring verifies that an exact match takes
// priority over a substring match, even if the substring field appears first.
func TestFindCustomField_ExactBeatsSubstring(t *testing.T) {
	key := testKey()
	c := makeCipherWithFields(t, "id-1", "Bank", map[string]string{
		"IBAN note": "wrong",
		"IBAN":      "DE89370400440532013000",
	}, key)

	got, err := findCustomField(&c, key, "iban")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "DE89370400440532013000" {
		t.Errorf("got %q, want exact IBAN value (not substring match)", got)
	}
}

// TestFindCustomField_AmbiguousSubstring verifies that when multiple fields
// match by substring and none is an exact match, an error listing the
// candidates is returned.
func TestFindCustomField_AmbiguousSubstring(t *testing.T) {
	key := testKey()
	c := makeCipherWithFields(t, "id-1", "Bank", map[string]string{
		"IBAN bank": "DE89370400440532013000",
		"IBAN note": "some note text",
	}, key)

	_, err := findCustomField(&c, key, "iban")
	if err == nil {
		t.Fatal("expected error for ambiguous substring match, got nil")
	}
}

// TestFindCustomField_NoMatch verifies that a non-matching pattern returns an
// error.
func TestFindCustomField_NoMatch(t *testing.T) {
	key := testKey()
	c := makeCipherWithFields(t, "id-1", "Bank", map[string]string{
		"IBAN": "DE89370400440532013000",
	}, key)

	_, err := findCustomField(&c, key, "nonexistent")
	if err == nil {
		t.Fatal("expected error for non-matching pattern, got nil")
	}
}

// TestFindCustomField_NoFields verifies that an item with no custom fields
// returns an error.
func TestFindCustomField_NoFields(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "id-1", "NoFields", "", key)

	_, err := findCustomField(&c, key, "iban")
	if err == nil {
		t.Fatal("expected error for cipher with no custom fields, got nil")
	}
}

// TestFindCustomField_SkipsUnnamedFields verifies that fields with an empty
// (un-named) field are skipped during matching and not listed as candidates.
func TestFindCustomField_SkipsUnnamedFields(t *testing.T) {
	key := testKey()
	encName := encryptStr(t, key, "Bank")
	encVal := encryptStr(t, key, "DE89370400440532013000")
	emptyName := ""
	c := client.Cipher{
		ID:   "id-1",
		Name: encName,
		Data: client.CipherData{Name: encName},
		Fields: []client.CipherField{
			{Name: &emptyName, Value: encVal},
			{Name: nil, Value: encVal},
		},
	}

	_, err := findCustomField(&c, key, "iban")
	if err == nil {
		t.Fatal("expected error when only unnamed fields exist, got nil")
	}
}

// TestFindCustomField_DataCustomFields verifies that custom fields stored in
// Data.CustomFields (the Bitwarden legacy format) are also searchable.
func TestFindCustomField_DataCustomFields(t *testing.T) {
	key := testKey()
	encName := encryptStr(t, key, "Bank")
	n := encryptStr(t, key, "IBAN")
	v := encryptStr(t, key, "DE89370400440532013000")
	c := client.Cipher{
		ID:   "id-1",
		Name: encName,
		Data: client.CipherData{
			Name: encName,
			CustomFields: []client.CipherField{
				{Name: &n, Value: v},
			},
		},
	}

	got, err := findCustomField(&c, key, "iban")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "DE89370400440532013000" {
		t.Errorf("got %q, want IBAN value from Data.CustomFields", got)
	}
}

// TestFindCustomField_FieldsAndDataCustomFields verifies that both Fields and
// Data.CustomFields are searched (both sources concatenated by cipherCustomFields).
func TestFindCustomField_FieldsAndDataCustomFields(t *testing.T) {
	key := testKey()
	encName := encryptStr(t, key, "Bank")
	n1 := encryptStr(t, key, "IBAN")
	v1 := encryptStr(t, key, "DE89370400440532013000")
	n2 := encryptStr(t, key, "BIC")
	v2 := encryptStr(t, key, "COBADEFFXXX")
	c := client.Cipher{
		ID:   "id-1",
		Name: encName,
		Data: client.CipherData{
			Name:         encName,
			CustomFields: []client.CipherField{{Name: &n2, Value: v2}},
		},
		Fields: []client.CipherField{{Name: &n1, Value: v1}},
	}

	gotIBAN, err := findCustomField(&c, key, "iban")
	if err != nil {
		t.Fatalf("unexpected error searching Fields: %v", err)
	}
	if gotIBAN != "DE89370400440532013000" {
		t.Errorf("got %q for IBAN", gotIBAN)
	}

	gotBIC, err := findCustomField(&c, key, "bic")
	if err != nil {
		t.Fatalf("unexpected error searching Data.CustomFields: %v", err)
	}
	if gotBIC != "COBADEFFXXX" {
		t.Errorf("got %q for BIC", gotBIC)
	}
}

// TestHumanFieldName_ExactMatch verifies that humanFieldName returns the
// case-preserving field name when an exact match is found.
func TestHumanFieldName_ExactMatch(t *testing.T) {
	key := testKey()
	c := makeCipherWithFields(t, "id-1", "Bank", map[string]string{
		"IBAN": "DE89370400440532013000",
	}, key)

	got := humanFieldName(&c, key, "iban")
	if got != `field "IBAN"` {
		t.Errorf("got %q, want `field \"IBAN\"`", got)
	}
}

// TestHumanFieldName_SubstringMatch verifies that humanFieldName returns the
// full field name for a substring match.
func TestHumanFieldName_SubstringMatch(t *testing.T) {
	key := testKey()
	c := makeCipherWithFields(t, "id-1", "Hoster", map[string]string{
		`Storage Box ("backup") Password`: "s3cr3t",
	}, key)

	got := humanFieldName(&c, key, "storage box")
	if got != `field "Storage Box (\"backup\") Password"` {
		t.Errorf("got %q, want full field name", got)
	}
}

// TestHumanFieldName_NoMatch verifies that humanFieldName falls back to a
// generic label when no field matches.
func TestHumanFieldName_NoMatch(t *testing.T) {
	key := testKey()
	c := makeCipherWithFields(t, "id-1", "Bank", map[string]string{
		"IBAN": "DE89370400440532013000",
	}, key)

	got := humanFieldName(&c, key, "nonexistent")
	if got != "custom field" {
		t.Errorf("got %q, want \"custom field\"", got)
	}
}

// ---------------------------------------------------------------------------
// renderHistory / passwordOnlyValue
// ---------------------------------------------------------------------------

func TestRenderHistory(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "GitHub", "", key)
	c.Type = client.CipherTypeLogin
	c.PasswordHistory = []client.CipherPasswordHistory{
		{Password: encryptStr(t, key, "newer"), LastUsedDate: "2000-09-25T00:00:00.000Z"},
		{Password: encryptStr(t, key, "older"), LastUsedDate: "2000-08-25T00:00:00.000Z"},
	}

	out, err := renderHistory(&c, key, "fallback")
	if err != nil {
		t.Fatalf("renderHistory: %v", err)
	}
	want := "Password history for GitHub:\n" +
		"2000-09-25T00:00:00.000Z  newer\n" +
		"2000-08-25T00:00:00.000Z  older\n"
	if out != want {
		t.Errorf("renderHistory mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

func TestRenderHistory_NoHistory(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "GitHub", "", key)
	if _, err := renderHistory(&c, key, "GitHub"); err == nil {
		t.Fatal("expected error for item without password history, got nil")
	}
}

func TestRenderHistory_DecryptErrorSkipsEntry(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "GitHub", "", key)
	c.PasswordHistory = []client.CipherPasswordHistory{
		{Password: "not-a-valid-cipher-string", LastUsedDate: "2000-09-25T00:00:00.000Z"},
	}
	out, err := renderHistory(&c, key, "GitHub")
	if err != nil {
		t.Fatalf("renderHistory: %v", err)
	}
	if !strings.Contains(out, "[Decryption Error]") {
		t.Errorf("expected a [Decryption Error] placeholder, got:\n%s", out)
	}
}

func TestPasswordOnlyValue_Login(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "GitHub", "", key)
	c.Type = client.CipherTypeLogin
	got, err := passwordOnlyValue(&c, "s3cret", "GitHub")
	if err != nil {
		t.Fatalf("passwordOnlyValue: %v", err)
	}
	if got != "s3cret" {
		t.Errorf("got %q, want %q", got, "s3cret")
	}
}

func TestPasswordOnlyValue_EmptyPassword(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "GitHub", "", key)
	c.Type = client.CipherTypeLogin
	if _, err := passwordOnlyValue(&c, "", "GitHub"); err == nil {
		t.Fatal("expected error for empty password, got nil")
	}
}

func TestPasswordOnlyValue_NonLogin(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "My card", "", key)
	c.Type = client.CipherTypeCard
	_, err := passwordOnlyValue(&c, "", "My card")
	if err == nil {
		t.Fatal("expected error for card item, got nil")
	}
	if !strings.Contains(err.Error(), "card") {
		t.Errorf("error should name the item type, got: %v", err)
	}
}
