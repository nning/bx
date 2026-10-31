package cmd

import (
	"bytes"
	"testing"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
)

// TestCipherKey_NoOrgNoPerItemKey verifies that the account key is returned
// when the cipher has no organization ID and no per-item key.
func TestCipherKey_NoOrgNoPerItemKey(t *testing.T) {
	key := testKey()
	cipher := client.Cipher{ID: "id1"}
	got := cipherKey(cipher, key, nil)
	if !bytes.Equal(got, key) {
		t.Errorf("expected accountKey, got different key")
	}
}

// TestCipherKey_OrgInMap verifies that the matching org key is used as the
// base key when the cipher has an organization ID present in orgKeys.
func TestCipherKey_OrgInMap(t *testing.T) {
	accountKey := testKey()
	orgKey := make([]byte, 64)
	for i := range orgKey {
		orgKey[i] = byte(i + 100)
	}
	orgID := "org-123"
	orgKeys := map[string][]byte{orgID: orgKey}

	cipher := client.Cipher{ID: "id1", OrganizationID: &orgID}
	got := cipherKey(cipher, accountKey, orgKeys)
	if !bytes.Equal(got, orgKey) {
		t.Errorf("expected orgKey, got different key")
	}
}

// TestCipherKey_OrgNotInMap verifies that the account key is returned when
// the cipher has an organization ID that is not in orgKeys.
func TestCipherKey_OrgNotInMap(t *testing.T) {
	accountKey := testKey()
	orgID := "org-unknown"
	orgKeys := map[string][]byte{"other-org": make([]byte, 64)}

	cipher := client.Cipher{ID: "id1", OrganizationID: &orgID}
	got := cipherKey(cipher, accountKey, orgKeys)
	if !bytes.Equal(got, accountKey) {
		t.Errorf("expected accountKey fallback, got different key")
	}
}

// TestCipherKey_EmptyOrgID verifies that an empty organization ID string
// is treated as no organization, returning the account key.
func TestCipherKey_EmptyOrgID(t *testing.T) {
	accountKey := testKey()
	emptyOrg := ""
	cipher := client.Cipher{ID: "id1", OrganizationID: &emptyOrg}
	got := cipherKey(cipher, accountKey, nil)
	if !bytes.Equal(got, accountKey) {
		t.Errorf("expected accountKey for empty org ID, got different key")
	}
}

// TestCipherKey_NilKey verifies that the base key is returned when the
// cipher has no per-item key (nil).
func TestCipherKey_NilKey(t *testing.T) {
	accountKey := testKey()
	cipher := client.Cipher{ID: "id1", Key: nil}
	got := cipherKey(cipher, accountKey, nil)
	if !bytes.Equal(got, accountKey) {
		t.Errorf("expected accountKey for nil per-item key, got different key")
	}
}

// TestCipherKey_EmptyKey verifies that the base key is returned when the
// cipher has an empty per-item key string.
func TestCipherKey_EmptyKey(t *testing.T) {
	accountKey := testKey()
	emptyKey := ""
	cipher := client.Cipher{ID: "id1", Key: &emptyKey}
	got := cipherKey(cipher, accountKey, nil)
	if !bytes.Equal(got, accountKey) {
		t.Errorf("expected accountKey for empty per-item key, got different key")
	}
}

// TestCipherKey_DecryptFailure verifies that the base key is returned when
// the per-item key cipher string cannot be decrypted.
func TestCipherKey_DecryptFailure(t *testing.T) {
	accountKey := testKey()
	badKey := "2.invaliddatahere|invaliddatahere|invaliddatahere"
	cipher := client.Cipher{ID: "id1", Key: &badKey}
	got := cipherKey(cipher, accountKey, nil)
	if !bytes.Equal(got, accountKey) {
		t.Errorf("expected accountKey on decrypt failure, got different key")
	}
}

// TestCipherKey_64BytePerItemKey verifies that a per-item key that decrypts
// to 64 bytes is returned directly.
func TestCipherKey_64BytePerItemKey(t *testing.T) {
	accountKey := testKey()
	// 64-byte per-item key plaintext (distinct from accountKey)
	perItemPlaintext := bytes.Repeat([]byte{0xAB}, 64)
	encryptedPerItemKey := encryptStr(t, accountKey, string(perItemPlaintext))

	cipher := client.Cipher{ID: "id1", Key: &encryptedPerItemKey}
	got := cipherKey(cipher, accountKey, nil)
	if !bytes.Equal(got, perItemPlaintext) {
		t.Errorf("expected 64-byte per-item key, got key of len %d", len(got))
	}
}

// TestCipherKey_32BytePerItemKey verifies that a per-item key that decrypts
// to 32 bytes is HKDF-expanded to 64 bytes before being returned.
func TestCipherKey_32BytePerItemKey(t *testing.T) {
	accountKey := testKey()
	// 32-byte per-item key plaintext
	perItemPlaintext := bytes.Repeat([]byte{0xCD}, 32)
	encryptedPerItemKey := encryptStr(t, accountKey, string(perItemPlaintext))

	cipher := client.Cipher{ID: "id1", Key: &encryptedPerItemKey}
	got := cipherKey(cipher, accountKey, nil)

	// Should be the 64-byte expansion of the 32-byte plaintext
	expectedExpanded, err := crypto.ExpandKey(perItemPlaintext)
	if err != nil {
		t.Fatalf("ExpandKey: %v", err)
	}
	if len(got) != 64 {
		t.Errorf("expected 64-byte expanded key, got len %d", len(got))
	}
	if !bytes.Equal(got, expectedExpanded) {
		t.Errorf("expanded key mismatch")
	}
}

// TestCipherKey_OtherLengthPerItemKey verifies that a per-item key that
// decrypts to an unsupported length falls back to the base key.
func TestCipherKey_OtherLengthPerItemKey(t *testing.T) {
	accountKey := testKey()
	// 31-byte plaintext: hits the default case in the switch
	perItemPlaintext := bytes.Repeat([]byte{0xEF}, 31)
	encryptedPerItemKey := encryptStr(t, accountKey, string(perItemPlaintext))

	cipher := client.Cipher{ID: "id1", Key: &encryptedPerItemKey}
	got := cipherKey(cipher, accountKey, nil)
	if !bytes.Equal(got, accountKey) {
		t.Errorf("expected accountKey fallback for non-32/64 key length, got len %d", len(got))
	}
}

// TestCipherKey_OrgKey64BytePerItemKey verifies that when an org cipher has a
// per-item key, it is decrypted using the org key (not the account key).
func TestCipherKey_OrgKey64BytePerItemKey(t *testing.T) {
	accountKey := testKey()
	orgKey := make([]byte, 64)
	for i := range orgKey {
		orgKey[i] = byte(i + 50)
	}
	orgID := "org-abc"
	orgKeys := map[string][]byte{orgID: orgKey}

	// Encrypt a 64-byte per-item key using the orgKey as the base key
	perItemPlaintext := bytes.Repeat([]byte{0x77}, 64)
	encryptedPerItemKey := encryptStr(t, orgKey, string(perItemPlaintext))

	cipher := client.Cipher{
		ID:             "id1",
		OrganizationID: &orgID,
		Key:            &encryptedPerItemKey,
	}
	got := cipherKey(cipher, accountKey, orgKeys)
	if !bytes.Equal(got, perItemPlaintext) {
		t.Errorf("expected per-item key decrypted via orgKey, got different result")
	}
}
