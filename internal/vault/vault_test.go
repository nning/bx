package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
	"golang.org/x/crypto/argon2"
)

// TestLoadVault_MissingVaultFile verifies that LoadVault returns an error when
// the vault file does not exist.
func TestLoadVault_MissingVaultFile(t *testing.T) {
	withTempHome(t)
	_, _, _, err := LoadVault("testpassword")
	if err == nil {
		t.Fatal("Expected error when vault file does not exist")
	}
	if err.Error() == "" {
		t.Fatal("Error message should not be empty")
	}
}

// minimalVaultJSON is a well-formed vault payload that passes validateSyncResponse.
const minimalVaultJSON = `{
	"profile": {
		"id": "test-profile-id",
		"email": "test@example.com",
		"key": "test-profile-key"
	},
	"folders": [],
	"ciphers": []
}`

// --- validateSyncResponse ---

// TestValidateSyncResponse exercises every branch of the validation function.
func TestValidateSyncResponse(t *testing.T) {
	tooManyCiphers := make([]client.Cipher, 100001)
	tooManyFolders := make([]client.Folder, 100001)

	tests := []struct {
		name    string
		resp    *client.SyncResponse
		wantErr bool
	}{
		{name: "nil response", resp: nil, wantErr: true},
		{
			name:    "empty profile ID",
			resp:    &client.SyncResponse{Profile: client.Profile{Email: "a@b.com", Key: "k"}},
			wantErr: true,
		},
		{
			name:    "empty profile email",
			resp:    &client.SyncResponse{Profile: client.Profile{ID: "id", Key: "k"}},
			wantErr: true,
		},
		{
			name:    "empty profile key",
			resp:    &client.SyncResponse{Profile: client.Profile{ID: "id", Email: "a@b.com"}},
			wantErr: true,
		},
		{
			name: "too many ciphers",
			resp: &client.SyncResponse{
				Profile: client.Profile{ID: "id", Email: "a@b.com", Key: "k"},
				Ciphers: tooManyCiphers,
			},
			wantErr: true,
		},
		{
			name: "too many folders",
			resp: &client.SyncResponse{
				Profile: client.Profile{ID: "id", Email: "a@b.com", Key: "k"},
				Folders: tooManyFolders,
			},
			wantErr: true,
		},
		{
			name:    "valid minimal",
			resp:    &client.SyncResponse{Profile: client.Profile{ID: "id", Email: "a@b.com", Key: "k"}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSyncResponse(tt.resp)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSyncResponse error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// --- loadSyncData ---

// TestLoadSyncData_InvalidJSON verifies that loadSyncData returns an error when
// the vault file contains invalid JSON.
func TestLoadSyncData_InvalidJSON(t *testing.T) {
	home := withTempHome(t)
	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, []byte("not-valid-json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := loadSyncData()
	if err == nil {
		t.Fatal("expected error for invalid JSON in vault file")
	}
}

// TestLoadSyncData_ValidationFailure verifies that loadSyncData returns an error
// when the vault JSON is valid but fails structural validation (empty profile ID).
func TestLoadSyncData_ValidationFailure(t *testing.T) {
	home := withTempHome(t)
	vaultPath := filepath.Join(home, ".bx_vault.json")
	invalid := `{"profile":{"id":"","email":"","key":""},"folders":[],"ciphers":[]}`
	if err := os.WriteFile(vaultPath, []byte(invalid), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := loadSyncData()
	if err == nil {
		t.Fatal("expected error for vault with missing required profile fields")
	}
}

// TestLoadSyncData_Valid verifies that loadSyncData parses a well-formed vault
// file and returns the correct profile data.
func TestLoadSyncData_Valid(t *testing.T) {
	home := withTempHome(t)
	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, []byte(minimalVaultJSON), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	resp, err := loadSyncData()
	if err != nil {
		t.Fatalf("loadSyncData: %v", err)
	}
	if resp.Profile.ID != "test-profile-id" {
		t.Errorf("profile ID: got %q, want %q", resp.Profile.ID, "test-profile-id")
	}
	if resp.Profile.Email != "test@example.com" {
		t.Errorf("profile email: got %q, want %q", resp.Profile.Email, "test@example.com")
	}
}

// --- LoadVaultWithSession ---

// TestLoadVaultWithSession_ZeroTimeout verifies that timeout=0 always calls
// passwordFn even when a valid session is available.
func TestLoadVaultWithSession_ZeroTimeout(t *testing.T) {
	withTempHome(t)

	if err := SaveSession([]byte("accountkey"), nil); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	called := false
	_, _, _, _, err := LoadVaultWithSession(0, func() (string, error) {
		called = true
		return "", fmt.Errorf("sentinel error")
	})
	if !called {
		t.Error("passwordFn should have been called with zero timeout")
	}
	if err == nil {
		t.Error("expected error propagation from passwordFn")
	}
}

// TestLoadVaultWithSession_ValidSession verifies that a valid cached session is
// used without calling passwordFn.
func TestLoadVaultWithSession_ValidSession(t *testing.T) {
	home := withTempHome(t)

	accountKey := []byte("test-account-key-32bytes-12345xx")
	orgKeys := map[string][]byte{"org-id": []byte("test-org-key")}
	if err := SaveSession(accountKey, orgKeys); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, []byte(minimalVaultJSON), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, gotKey, gotOrgKeys, prompted, err := LoadVaultWithSession(15, func() (string, error) {
		t.Error("passwordFn must not be called when session is valid")
		return "", fmt.Errorf("should not be called")
	})
	if err != nil {
		t.Fatalf("LoadVaultWithSession: %v", err)
	}
	if prompted {
		t.Error("passwordPrompted should be false when using a cached session")
	}
	if string(gotKey) != string(accountKey) {
		t.Errorf("account key: got %q, want %q", gotKey, accountKey)
	}
	if string(gotOrgKeys["org-id"]) != string(orgKeys["org-id"]) {
		t.Errorf("org key: got %q, want %q", gotOrgKeys["org-id"], orgKeys["org-id"])
	}
}

// TestLoadVaultWithSession_ValidSession_VaultMissing verifies that a valid
// session still results in an error when the vault file is absent.
func TestLoadVaultWithSession_ValidSession_VaultMissing(t *testing.T) {
	withTempHome(t)

	if err := SaveSession([]byte("key"), nil); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	_, _, _, _, err := LoadVaultWithSession(15, func() (string, error) {
		t.Error("passwordFn must not be called when session is valid")
		return "", nil
	})
	if err == nil {
		t.Fatal("expected error when vault file is missing")
	}
}

// TestLoadVaultWithSession_PasswordFnError verifies that an error from passwordFn
// is propagated when no session is available.
func TestLoadVaultWithSession_PasswordFnError(t *testing.T) {
	withTempHome(t)

	_, _, _, _, err := LoadVaultWithSession(15, func() (string, error) {
		return "", fmt.Errorf("password read failed")
	})
	if err == nil {
		t.Fatal("expected error when passwordFn fails")
	}
}

// TestLoadVaultWithSession_SessionLoadError verifies that when LoadSession
// returns an error (e.g., insecure permissions) LoadVaultWithSession falls
// through to passwordFn.
func TestLoadVaultWithSession_SessionLoadError(t *testing.T) {
	home := withTempHome(t)

	// Write a timestamp file with insecure permissions so LoadSession fails.
	ts := sessionTimestamp{UnlockedAt: time.Now()}
	path := filepath.Join(home, ".bx_session.json")
	data, _ := json.Marshal(ts)
	if err := os.WriteFile(path, data, 0o644); err != nil { // insecure: world-readable
		t.Fatalf("WriteFile: %v", err)
	}

	// Confirm the file exists at the expected path before exercising the code.
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("expected session file to exist at %s: %v", path, err)
	}

	called := false
	_, _, _, _, _ = LoadVaultWithSession(15, func() (string, error) {
		called = true
		return "", fmt.Errorf("sentinel error")
	})
	if !called {
		t.Error("passwordFn should be called when LoadSession returns an error")
	}
}

// TestLoadVaultWithSession_SuccessWithSessionSave verifies that when no session
// exists and LoadVault succeeds, the keys are returned and a session is saved.
func TestLoadVaultWithSession_SuccessWithSessionSave(t *testing.T) {
	home := withTempHome(t)
	password := "correct-horse-battery"
	email := "test@example.com"

	vaultData, wantAccountKey := buildTestVaultJSON(t, password, email)
	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, vaultData, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	called := false
	_, gotKey, _, prompted, err := LoadVaultWithSession(15, func() (string, error) {
		called = true
		return password, nil
	})
	if err != nil {
		t.Fatalf("LoadVaultWithSession: %v", err)
	}
	if !called {
		t.Error("passwordFn should have been called when no session exists")
	}
	if !prompted {
		t.Error("passwordPrompted should be true when passwordFn was called")
	}
	if !bytes.Equal(gotKey, wantAccountKey) {
		t.Errorf("account key mismatch: got %x, want %x", gotKey, wantAccountKey)
	}

	// Verify that a session was saved (session file should now exist).
	session, err := LoadSession(15)
	if err != nil {
		t.Fatalf("LoadSession after save: %v", err)
	}
	if session == nil {
		t.Fatal("expected session to be saved after successful unlock")
	}
}

// --- LoadVault additional paths ---

// encryptAES creates a valid type-2 (AES-CBC-HMAC-SHA256) Bitwarden cipher
// string for the given plaintext using the provided 64-byte key.
func encryptAES(t *testing.T, key []byte, plaintext []byte) string {
	t.Helper()
	encKey, macKey := key[:32], key[32:]

	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}

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

// buildTestVaultJSON builds a vault JSON string with a properly encrypted
// profile key derived from the given password and email (PBKDF2, 100000 iter).
// Returns the JSON and the expected account key bytes.
func buildTestVaultJSON(t *testing.T, password, email string) ([]byte, []byte) {
	t.Helper()
	kdfConfig := crypto.KdfConfig{
		Type:       crypto.KdfTypePBKDF2,
		Iterations: 100000,
	}
	masterKey, err := crypto.DeriveMasterKey(password, email, kdfConfig)
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	expandedKey, err := crypto.ExpandKey(masterKey)
	if err != nil {
		t.Fatalf("ExpandKey: %v", err)
	}

	accountKey := bytes.Repeat([]byte{0x42}, 64)
	encryptedKey := encryptAES(t, expandedKey, accountKey)

	// Include UserDecryption so LoadVault reads the correct KDF params.
	vaultData := map[string]any{
		"profile": map[string]any{
			"id":    "test-profile-id",
			"email": email,
			"key":   encryptedKey,
		},
		"userDecryption": map[string]any{
			"masterPasswordUnlock": map[string]any{
				"kdf": map[string]any{
					"kdfType":    0,
					"iterations": 100000,
				},
				"salt": email,
			},
		},
		"folders": []any{},
		"ciphers": []any{},
	}
	data, err2 := json.Marshal(vaultData)
	if err2 != nil {
		t.Fatalf("json.Marshal: %v", err2)
	}
	return data, accountKey
}

// TestLoadVault_Success verifies that LoadVault successfully derives the master
// key, decrypts the profile key, and returns the expected account key.
func TestLoadVault_Success(t *testing.T) {
	home := withTempHome(t)
	password := "correct-horse-battery"
	email := "test@example.com"

	vaultData, wantAccountKey := buildTestVaultJSON(t, password, email)
	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, vaultData, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, accountKey, orgKeys, err := LoadVault(password)
	if err != nil {
		t.Fatalf("LoadVault: %v", err)
	}
	if !bytes.Equal(accountKey, wantAccountKey) {
		t.Errorf("account key mismatch: got %x, want %x", accountKey, wantAccountKey)
	}
	if len(orgKeys) != 0 {
		t.Errorf("expected empty orgKeys, got %d entries", len(orgKeys))
	}
}

// TestLoadVault_InvalidProfileKey verifies that LoadVault returns an error when
// the profile key cannot be decrypted with the derived master key.
func TestLoadVault_InvalidProfileKey(t *testing.T) {
	home := withTempHome(t)

	// Write a vault with a malformed encrypted profile key.
	vaultJSON := `{
		"profile": {
			"id": "test-id",
			"email": "test@example.com",
			"key": "2.notvalid|notvalid|notvalid"
		},
		"folders": [],
		"ciphers": []
	}`
	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, []byte(vaultJSON), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, _, _, err := LoadVault("anypassword")
	if err == nil {
		t.Fatal("expected error when profile key cannot be decrypted")
	}
}

// TestLoadVault_InvalidKdfType verifies that LoadVault returns an error when
// the vault specifies an unsupported KDF type via UserDecryption.
func TestLoadVault_InvalidKdfType(t *testing.T) {
	home := withTempHome(t)

	// Write a vault with an unsupported KDF type (99) in UserDecryption.
	vaultJSON := `{
		"profile": {
			"id": "test-id",
			"email": "test@example.com",
			"key": "some-key"
		},
		"userDecryption": {
			"masterPasswordUnlock": {
				"kdf": {"kdfType": 99, "iterations": 1},
				"salt": "test@example.com"
			}
		},
		"folders": [],
		"ciphers": []
	}`
	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, []byte(vaultJSON), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, _, _, err := LoadVault("anypassword")
	if err == nil {
		t.Fatal("expected error for unsupported KDF type")
	}
}

// TestLoadVault_UserDecryptionPath verifies that when UserDecryption is present,
// its KDF params and Salt are used instead of Profile.Email for key derivation.
func TestLoadVault_UserDecryptionPath(t *testing.T) {
	home := withTempHome(t)
	password := "mypassword"
	// Use the salt from UserDecryption.MasterPasswordUnlock for key derivation.
	saltEmail := "salt@example.com"

	kdfConfig := crypto.KdfConfig{
		Type:       crypto.KdfTypePBKDF2,
		Iterations: 100000,
	}
	masterKey, err := crypto.DeriveMasterKey(password, saltEmail, kdfConfig)
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	expandedKey, err := crypto.ExpandKey(masterKey)
	if err != nil {
		t.Fatalf("ExpandKey: %v", err)
	}

	accountKey := bytes.Repeat([]byte{0x55}, 64)
	encryptedKey := encryptAES(t, expandedKey, accountKey)

	// Build vault with UserDecryption pointing to saltEmail and Profile.Email different.
	vaultData := map[string]any{
		"profile": map[string]any{
			"id":    "test-id",
			"email": "different@example.com",
			"key":   encryptedKey,
		},
		"userDecryption": map[string]any{
			"masterPasswordUnlock": map[string]any{
				"kdf": map[string]any{
					"kdfType":    0,
					"iterations": 100000,
				},
				"salt": saltEmail,
			},
		},
		"folders": []any{},
		"ciphers": []any{},
	}
	data, err := json.Marshal(vaultData)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, gotKey, _, err := LoadVault(password)
	if err != nil {
		t.Fatalf("LoadVault: %v", err)
	}
	if !bytes.Equal(gotKey, accountKey) {
		t.Errorf("account key mismatch: got %x, want %x", gotKey, accountKey)
	}
}

// TestLoadVault_Argon2idSuccess verifies that LoadVault correctly handles
// Argon2id KDF parameters from the UserDecryption block, including the
// SHA256(email) salt derivation per the Bitwarden specification.
// The expected key is derived independently (direct argon2.IDKey with
// SHA256'd salt) to ensure correctness even if DeriveMasterKey is buggy.
func TestLoadVault_Argon2idSuccess(t *testing.T) {
	home := withTempHome(t)
	password := "argon2-test-password"
	email := "argon2@example.com"

	// Derive the master key independently — use argon2.IDKey directly with
	// the SHA256(email) salt so this test does not depend on DeriveMasterKey.
	emailLower := strings.ToLower(email)
	saltHash := sha256.Sum256([]byte(emailLower))
	masterKey := argon2.IDKey([]byte(password), saltHash[:], 3, 64*1024, 4, 32)

	expandedKey, err := crypto.ExpandKey(masterKey)
	if err != nil {
		t.Fatalf("ExpandKey: %v", err)
	}

	accountKey := bytes.Repeat([]byte{0xAA}, 64)
	encryptedKey := encryptAES(t, expandedKey, accountKey)

	memory := 64
	parallelism := 4
	vaultData := map[string]any{
		"profile": map[string]any{
			"id":    "test-argon2-id",
			"email": email,
			"key":   encryptedKey,
		},
		"userDecryption": map[string]any{
			"masterPasswordUnlock": map[string]any{
				"kdf": map[string]any{
					"kdfType":     1,
					"iterations":  3,
					"memory":      memory,
					"parallelism": parallelism,
				},
				"salt": email,
			},
		},
		"folders": []any{},
		"ciphers": []any{},
	}
	data, err := json.Marshal(vaultData)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, gotKey, _, err := LoadVault(password)
	if err != nil {
		t.Fatalf("LoadVault: %v", err)
	}
	if !bytes.Equal(gotKey, accountKey) {
		t.Errorf("account key mismatch: got %x, want %x", gotKey, accountKey)
	}
}

// ---- PatchCipher / PatchFolder tests -------------------------------------

// buildPatchVaultJSON writes a minimal vault JSON with the given ciphers and
// folders to the test home's .bx_vault.json file.
func buildPatchVaultJSON(t *testing.T, home string, ciphers []client.Cipher, folders []client.Folder) {
	t.Helper()
	data := map[string]any{
		"profile": map[string]any{
			"id":    "test-id",
			"email": "test@example.com",
			"key":   "dummy-key",
		},
		"folders": folders,
		"ciphers": ciphers,
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// readVaultCiphers loads the ciphers array from the test vault file.
func readVaultCiphers(t *testing.T, home string) []client.Cipher {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".bx_vault.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	var ciphers []client.Cipher
	if err := json.Unmarshal(raw["ciphers"], &ciphers); err != nil {
		t.Fatalf("Unmarshal ciphers: %v", err)
	}
	return ciphers
}

// readVaultFolders loads the folders array from the test vault file.
func readVaultFolders(t *testing.T, home string) []client.Folder {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".bx_vault.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	var folders []client.Folder
	if err := json.Unmarshal(raw["folders"], &folders); err != nil {
		t.Fatalf("Unmarshal folders: %v", err)
	}
	return folders
}

func TestPatchCipher_Create(t *testing.T) {
	home := withTempHome(t)
	buildPatchVaultJSON(t, home, nil, nil)

	newCipher := client.Cipher{ID: "new-cipher", Type: 1, RevisionDate: "2000-01-01T00:00:00Z"}
	if err := PatchCipher(PatchCipherCreate, &newCipher); err != nil {
		t.Fatalf("PatchCipher create: %v", err)
	}

	ciphers := readVaultCiphers(t, home)
	if len(ciphers) != 1 || ciphers[0].ID != "new-cipher" {
		t.Errorf("expected [new-cipher], got %v", ciphers)
	}
}

func TestPatchCipher_Edit(t *testing.T) {
	home := withTempHome(t)
	original := client.Cipher{ID: "cipher-1", Type: 1, RevisionDate: "2000-01-01T00:00:00Z"}
	buildPatchVaultJSON(t, home, []client.Cipher{original}, nil)

	updated := original
	updated.RevisionDate = "2000-02-01T00:00:00Z"
	if err := PatchCipher(PatchCipherEdit, &updated); err != nil {
		t.Fatalf("PatchCipher edit: %v", err)
	}

	ciphers := readVaultCiphers(t, home)
	if len(ciphers) != 1 {
		t.Fatalf("expected 1 cipher, got %d", len(ciphers))
	}
	if ciphers[0].RevisionDate != "2000-02-01T00:00:00Z" {
		t.Errorf("revision date not updated: %q", ciphers[0].RevisionDate)
	}
}

func TestPatchCipher_Edit_SetDeletedDate(t *testing.T) {
	home := withTempHome(t)
	original := client.Cipher{ID: "cipher-1", Type: 1}
	buildPatchVaultJSON(t, home, []client.Cipher{original}, nil)

	deletedDate := "2000-03-01T00:00:00Z"
	softDeleted := original
	softDeleted.DeletedDate = &deletedDate
	if err := PatchCipher(PatchCipherEdit, &softDeleted); err != nil {
		t.Fatalf("PatchCipher soft delete: %v", err)
	}

	ciphers := readVaultCiphers(t, home)
	if len(ciphers) != 1 {
		t.Fatalf("expected 1 cipher, got %d", len(ciphers))
	}
	if ciphers[0].DeletedDate == nil || *ciphers[0].DeletedDate != deletedDate {
		t.Errorf("DeletedDate not set: %v", ciphers[0].DeletedDate)
	}
}

func TestPatchCipher_HardDelete(t *testing.T) {
	home := withTempHome(t)
	c1 := client.Cipher{ID: "cipher-1", Type: 1}
	c2 := client.Cipher{ID: "cipher-2", Type: 1}
	buildPatchVaultJSON(t, home, []client.Cipher{c1, c2}, nil)

	if err := PatchCipher(PatchCipherHardDelete, &c1); err != nil {
		t.Fatalf("PatchCipher hard delete: %v", err)
	}

	ciphers := readVaultCiphers(t, home)
	if len(ciphers) != 1 || ciphers[0].ID != "cipher-2" {
		t.Errorf("expected [cipher-2] after hard delete, got %v", ciphers)
	}
}

func TestPatchCipher_VaultFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits not enforced on Windows")
	}
	home := withTempHome(t)
	buildPatchVaultJSON(t, home, nil, nil)

	newCipher := client.Cipher{ID: "c1"}
	if err := PatchCipher(PatchCipherCreate, &newCipher); err != nil {
		t.Fatalf("PatchCipher: %v", err)
	}

	fi, err := os.Lstat(filepath.Join(home, ".bx_vault.json"))
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("expected 0600 permissions, got %v", fi.Mode().Perm())
	}
}

func TestPatchCipher_MissingVaultFile(t *testing.T) {
	withTempHome(t)
	// No vault file written — should return an error.
	c := client.Cipher{ID: "c1"}
	if err := PatchCipher(PatchCipherCreate, &c); err == nil {
		t.Fatal("expected error when vault file is missing")
	}
}

func TestPatchFolder_Create(t *testing.T) {
	home := withTempHome(t)
	buildPatchVaultJSON(t, home, nil, nil)

	newFolder := client.Folder{ID: "folder-1", Name: "encrypted-name"}
	if err := PatchFolder(PatchFolderCreate, &newFolder); err != nil {
		t.Fatalf("PatchFolder create: %v", err)
	}

	folders := readVaultFolders(t, home)
	if len(folders) != 1 || folders[0].ID != "folder-1" {
		t.Errorf("expected [folder-1], got %v", folders)
	}
}

func TestPatchFolder_Delete(t *testing.T) {
	home := withTempHome(t)
	f1 := client.Folder{ID: "folder-1", Name: "n1"}
	f2 := client.Folder{ID: "folder-2", Name: "n2"}
	buildPatchVaultJSON(t, home, nil, []client.Folder{f1, f2})

	if err := PatchFolder(PatchFolderDelete, &f1); err != nil {
		t.Fatalf("PatchFolder delete: %v", err)
	}

	folders := readVaultFolders(t, home)
	if len(folders) != 1 || folders[0].ID != "folder-2" {
		t.Errorf("expected [folder-2] after delete, got %v", folders)
	}
}

func TestPatchVault_PreservesUnknownFields(t *testing.T) {
	home := withTempHome(t)
	// Write a vault with an extra unknown top-level field.
	raw := `{"profile":{"id":"test-id","email":"test@example.com","key":"k"},"folders":[],"ciphers":[],"extra_field":"should_be_preserved"}`
	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := client.Cipher{ID: "c1"}
	if err := PatchCipher(PatchCipherCreate, &c); err != nil {
		t.Fatalf("PatchCipher: %v", err)
	}

	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(data, []byte("extra_field")) {
		t.Error("unknown field 'extra_field' was lost after patch")
	}
}

// TestPatchVault_PreservesUnknownFieldsInEntries verifies that unknown fields
// inside individual cipher and folder entries that are NOT being modified are
// preserved byte-for-byte after a patch operation.
func TestPatchVault_PreservesUnknownFieldsInEntries(t *testing.T) {
	home := withTempHome(t)
	// Vault with two ciphers; the first has an unknown field "server_field".
	// We will edit the second cipher and assert the first's extra field survives.
	raw := `{
		"profile":{"id":"test-id","email":"test@example.com","key":"k"},
		"folders":[{"id":"f1","name":"n1","server_folder_field":"keep_me"}],
		"ciphers":[
			{"id":"c1","name":"N","type":1,"server_cipher_field":"keep_me"},
			{"id":"c2","name":"M","type":1}
		]
	}`
	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Edit c2 — c1 should remain untouched, including its unknown field.
	c2 := client.Cipher{ID: "c2", Type: 1, Data: client.CipherData{Name: "Updated"}}
	if err := PatchCipher(PatchCipherEdit, &c2); err != nil {
		t.Fatalf("PatchCipher edit: %v", err)
	}

	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(data, []byte("server_cipher_field")) {
		t.Error("unknown field 'server_cipher_field' in untouched cipher was lost after PatchCipher edit")
	}

	// Delete folder f1 via a no-op delete of a non-existent folder — f1 keeps its field.
	nonExistent := client.Folder{ID: "does-not-exist", Name: "x"}
	if err := PatchFolder(PatchFolderDelete, &nonExistent); err != nil {
		t.Fatalf("PatchFolder delete: %v", err)
	}

	data, err = os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile after folder patch: %v", err)
	}
	if !bytes.Contains(data, []byte("server_folder_field")) {
		t.Error("unknown field 'server_folder_field' in untouched folder was lost after PatchFolder delete")
	}
}

// TestPatchVault_PreservesUnknownFieldsInEditedCipher verifies that an
// unknown field present on the cipher being EDITED survives the rewrite.
// This is the regression test for D.2 — the field-level merge in
// PatchCipherEdit must preserve any cached keys that the inbound structured
// *Cipher does not model, so future server schema additions are not stripped
// from the local cache by a bx edit followed by another bx edit.
func TestPatchVault_PreservesUnknownFieldsInEditedCipher(t *testing.T) {
	home := withTempHome(t)
	vaultPath := filepath.Join(home, ".bx_vault.json")
	raw := `{
		"profile":{"id":"test-id","email":"test@example.com","key":"k"},
		"folders":[],
		"ciphers":[
			{"id":"c1","name":"Old","type":1,"revisionDate":"2000-01-01T00:00:00Z","future_server_field":"keep_me_too","nested":{"deep_field":"deep","keep_this":"yes"}}
		]
	}`
	if err := os.WriteFile(vaultPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Edit c1 by passing a structured *Cipher that lacks any knowledge of
	// "future_server_field" or "nested".
	updated := client.Cipher{
		ID:           "c1",
		Type:         1,
		RevisionDate: "2000-02-01T00:00:00Z",
		Data:         client.CipherData{Name: "New"},
	}
	if err := PatchCipher(PatchCipherEdit, &updated); err != nil {
		t.Fatalf("PatchCipher edit: %v", err)
	}

	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(data, []byte("future_server_field")) {
		t.Error("unknown top-level field 'future_server_field' was stripped from edited cipher")
	}
	if !bytes.Contains(data, []byte("deep_field")) {
		t.Error("unknown nested unknown field 'deep_field' was stripped from edited cipher")
	}
	if !bytes.Contains(data, []byte("\"New\"")) {
		t.Errorf("expected fresh name %q in output:\n%s", "New", string(data))
	}
	if !bytes.Contains(data, []byte("2000-02-01T00:00:00Z")) {
		t.Errorf("expected updated revisionDate in output:\n%s", string(data))
	}
}

// TestPatchVault_PreservesFido2CredentialsOnEdit verifies the passkey use
// case end-to-end: a login cipher carrying login.fido2Credentials (with a
// nullable nullable sub-field) keeps those credentials byte-for-byte after
// PatchCipherEdit only touches the notes field.
func TestPatchVault_PreservesFido2CredentialsOnEdit(t *testing.T) {
	home := withTempHome(t)
	vaultPath := filepath.Join(home, ".bx_vault.json")
	dummyMd := "2.userHandleBytes=|hBytes|macBytesMod="
	raw := `{
		"profile":{"id":"test-id","email":"test@example.com","key":"k"},
		"folders":[],
		"ciphers":[
			{
				"id":"c1",
				"name":"2.name|nm|m=",
				"type":1,
				"login":{
					"username":"2.user|usr|m=",
					"password":"2.pass|pwd|m=",
					"fido2Credentials":[
						{
							"credentialId":"2.cid|cid|m=",
							"keyType":"2.kt|kt|m=",
							"keyAlgorithm":"2.ka|ka|m=",
							"keyCurve":"2.kv|kv|m=",
							"keyValue":"2.kvv|kvv|m=",
							"rpId":"2.rpid|rpid|m=",
							"rpName":null,
							"userHandle":"` + dummyMd + `",
							"userName":"2.un|un|m=",
							"counter":"2.0|0|m=",
							"discoverable":"2.true|true|m=",
							"creationDate":"2023-01-01T12:00:00.0000000Z"
						}
					]
				}
			}
		]
	}`
	if err := os.WriteFile(vaultPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Simulate a server response to a notes update: the structured *Cipher
	// contains the same login+passkey bytes the cached blob already has
	// (matching the typical server-echo-edit flow), and only the notes field
	// is added as a distinguishing edit.
	notes := "2.newnote|note|m="
	unVal := "2.un|un|m="
	updated := client.Cipher{
		ID:           "c1",
		Type:         1,
		RevisionDate: "2000-09-01T00:00:00Z",
		Data: client.CipherData{
			Name:  "2.name|nm|m=",
			Notes: &notes,
		},
		Login: &client.CipherLogin{
			Username: "2.user|usr|m=",
			Password: "2.pass|pwd|m=",
			Fido2Credentials: []client.Fido2Credential{{
				CredentialId: "2.cid|cid|m=",
				KeyType:      "2.kt|kt|m=",
				KeyAlgorithm: "2.ka|ka|m=",
				KeyCurve:     "2.kv|kv|m=",
				KeyValue:     "2.kvv|kvv|m=",
				RpId:         "2.rpid|rpid|m=",
				RpName:       nil,
				UserHandle:   &dummyMd,
				UserName:     &unVal,
				Counter:      "2.0|0|m=",
				Discoverable: "2.true|true|m=",
				CreationDate: "2023-01-01T12:00:00.0000000Z",
			}},
		},
	}
	if err := PatchCipher(PatchCipherEdit, &updated); err != nil {
		t.Fatalf("PatchCipher edit: %v", err)
	}

	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Passkey fields must survive.
	for _, want := range []string{
		"fido2Credentials",
		"2.cid|cid|m=",
		"2.rpid|rpid|m=",
		"2023-01-01T12:00:00.0000000Z",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("expected %q to survive edit, output:\n%s", want, string(data))
		}
	}

	// New notes value must also be present.
	if !bytes.Contains(data, []byte("2.newnote|note|m=")) {
		t.Errorf("expected updated notes to be written, output:\n%s", string(data))
	}

	// Round-trip: loading the patched vault should yield a Cipher with one Fido2Credential.
	ciphers := readVaultCiphers(t, home)
	if len(ciphers) != 1 {
		t.Fatalf("expected 1 cipher, got %d", len(ciphers))
	}
	if ciphers[0].Login == nil || len(ciphers[0].Login.Fido2Credentials) != 1 {
		t.Fatalf("passkey stripped after edit. got Login=%v", ciphers[0].Login)
	}
	if ciphers[0].Data.Notes == nil || *ciphers[0].Data.Notes != notes {
		t.Errorf("notes not updated. got %v", ciphers[0].Data.Notes)
	}
}

// TestMergeCipherBlob_NonObjectInputs verifies mergeCipherBlob falls back to
// the fresh/cached blob respectively when either side is not a JSON object,
// so the helper never crashes on malformed input.
func TestMergeCipherBlob_NonObjectInputs(t *testing.T) {
	// Neither side is an object — fresh wins.
	out, err := mergeCipherBlob(
		json.RawMessage(`"hello"`),
		json.RawMessage(`"world"`),
	)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if string(out) != `"world"` {
		t.Errorf("expected fresh string to win, got %s", out)
	}

	// Only cached is an object — cached stays (fresh has no keys to merge).
	out, err = mergeCipherBlob(
		json.RawMessage(`{"a":1}`),
		json.RawMessage(`"world"`),
	)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if string(out) != `{"a":1}` {
		t.Errorf("expected cached object to survive when fresh is not an object, got %s", out)
	}
}

// --- VaultPath / ActiveAccount ---

// TestVaultPath_Default verifies that VaultPath returns the default path when
// no active account is set.
func TestVaultPath_Default(t *testing.T) {
	withTempHome(t)
	ActiveAccount = ""
	defer func() { ActiveAccount = "" }()

	path, err := VaultPath()
	if err != nil {
		t.Fatalf("VaultPath: %v", err)
	}
	home, _ := os.UserHomeDir()
	want := filepath.Join(home, ".bx_vault.json")
	if path != want {
		t.Errorf("VaultPath() = %q, want %q", path, want)
	}
}

// TestVaultPath_WithActiveAccount verifies that VaultPath returns a per-account
// path when ActiveAccount is set.
func TestVaultPath_WithActiveAccount(t *testing.T) {
	withTempHome(t)
	ActiveAccount = "work"
	defer func() { ActiveAccount = "" }()

	path, err := VaultPath()
	if err != nil {
		t.Fatalf("VaultPath: %v", err)
	}
	home, _ := os.UserHomeDir()
	want := filepath.Join(home, ".bx_vault_work.json")
	if path != want {
		t.Errorf("VaultPath() = %q, want %q", path, want)
	}
}

// TestLoadSyncData_WithActiveAccount verifies that loadSyncData reads from the
// per-account vault file when ActiveAccount is set.
func TestLoadSyncData_WithActiveAccount(t *testing.T) {
	home := withTempHome(t)
	ActiveAccount = "personal"
	defer func() { ActiveAccount = "" }()

	vaultPath := filepath.Join(home, ".bx_vault_personal.json")
	if err := os.WriteFile(vaultPath, []byte(minimalVaultJSON), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	resp, err := loadSyncData()
	if err != nil {
		t.Fatalf("loadSyncData: %v", err)
	}
	if resp.Profile.Email != "test@example.com" {
		t.Errorf("profile email: got %q, want %q", resp.Profile.Email, "test@example.com")
	}
}

// --- Additional PatchCipher / PatchFolder edge cases ---

// TestPatchCipher_UnknownOp verifies that an unrecognised PatchCipherOp returns
// an error rather than silently succeeding or panicking.
func TestPatchCipher_UnknownOp(t *testing.T) {
	home := withTempHome(t)
	buildPatchVaultJSON(t, home, nil, nil)

	c := &client.Cipher{ID: "c1"}
	err := PatchCipher(PatchCipherOp(99), c)
	if err == nil {
		t.Fatal("expected error for unknown PatchCipherOp")
	}
	if !strings.Contains(err.Error(), "unknown op") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestPatchFolder_UnknownOp verifies that an unrecognised PatchFolderOp returns
// an error rather than silently succeeding or panicking.
func TestPatchFolder_UnknownOp(t *testing.T) {
	home := withTempHome(t)
	buildPatchVaultJSON(t, home, nil, nil)

	f := &client.Folder{ID: "f1"}
	err := PatchFolder(PatchFolderOp(99), f)
	if err == nil {
		t.Fatal("expected error for unknown PatchFolderOp")
	}
	if !strings.Contains(err.Error(), "unknown op") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestPatchVaultFile_InvalidJSON verifies that patchVaultFile (called through
// PatchCipher) returns a meaningful error when the vault file contains invalid JSON.
func TestPatchVaultFile_InvalidJSON(t *testing.T) {
	home := withTempHome(t)

	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, []byte("not valid json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := &client.Cipher{ID: "c1"}
	if err := PatchCipher(PatchCipherCreate, c); err == nil {
		t.Fatal("expected error when vault JSON is invalid")
	}
}

// TestPatchCipher_InvalidCipherArrayJSON verifies that PatchCipher returns an
// error when the "ciphers" field in the vault is not a JSON array.
func TestPatchCipher_InvalidCipherArrayJSON(t *testing.T) {
	home := withTempHome(t)

	raw := `{"profile":{"id":"test-id","email":"test@example.com","key":"k"},"folders":[],"ciphers":"not-an-array"}`
	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := &client.Cipher{ID: "c1"}
	if err := PatchCipher(PatchCipherCreate, c); err == nil {
		t.Fatal("expected error when ciphers field is not an array")
	}
}

// TestPatchFolder_InvalidFolderArrayJSON verifies that PatchFolder returns an
// error when the "folders" field in the vault is not a JSON array.
func TestPatchFolder_InvalidFolderArrayJSON(t *testing.T) {
	home := withTempHome(t)

	raw := `{"profile":{"id":"test-id","email":"test@example.com","key":"k"},"folders":"not-an-array","ciphers":[]}`
	vaultPath := filepath.Join(home, ".bx_vault.json")
	if err := os.WriteFile(vaultPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f := &client.Folder{ID: "f1"}
	if err := PatchFolder(PatchFolderCreate, f); err == nil {
		t.Fatal("expected error when folders field is not an array")
	}
}

// TestPatchCipher_Edit_NotFoundAppends verifies that when PatchCipherEdit
// cannot find the cipher in the local cache, it appends the cipher rather than
// silently losing it.  This covers the case of an incomplete local cache.
func TestPatchCipher_Edit_NotFoundAppends(t *testing.T) {
	home := withTempHome(t)
	existing := client.Cipher{ID: "existing-cipher", Type: 1}
	buildPatchVaultJSON(t, home, []client.Cipher{existing}, nil)

	// Edit a cipher whose ID is not in the local cache.
	notInCache := client.Cipher{ID: "not-in-cache", Type: 1, RevisionDate: "2000-01-01T00:00:00Z"}
	if err := PatchCipher(PatchCipherEdit, &notInCache); err != nil {
		t.Fatalf("PatchCipher edit not-in-cache: %v", err)
	}

	ciphers := readVaultCiphers(t, home)
	if len(ciphers) != 2 {
		t.Fatalf("expected 2 ciphers after appending, got %d", len(ciphers))
	}
	ids := map[string]bool{}
	for _, c := range ciphers {
		ids[c.ID] = true
	}
	if !ids["existing-cipher"] || !ids["not-in-cache"] {
		t.Errorf("both ciphers should be present, got ids: %v", ids)
	}
}

// writeRawVaultCiphers writes a vault file whose ciphers array is built from raw
// JSON blobs, so that fields bx does not model can be part of a test fixture.
func writeRawVaultCiphers(t *testing.T, home string, blobs ...string) {
	t.Helper()
	data := map[string]any{
		"profile": map[string]any{
			"id":    "test-id",
			"email": "test@example.com",
			"key":   "dummy-key",
		},
		"folders": []any{},
		"ciphers": json.RawMessage("[" + strings.Join(blobs, ",") + "]"),
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".bx_vault.json"), raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// readRawVaultCiphers loads the ciphers array as generic maps.
func readRawVaultCiphers(t *testing.T, home string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".bx_vault.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	var ciphers []map[string]any
	if err := json.Unmarshal(raw["ciphers"], &ciphers); err != nil {
		t.Fatalf("Unmarshal ciphers: %v", err)
	}
	return ciphers
}

func TestPatchCipherRaw_ReplacesEncryptedFieldsIncludingUnmodelledOnes(t *testing.T) {
	home := withTempHome(t)
	// The cached copy is a personal item with password history — a field bx does
	// not model — encrypted with the account key.
	writeRawVaultCiphers(t, home, `{
		"id": "cipher-1",
		"organizationId": null,
		"key": null,
		"name": "2.old-name|old|old",
		"passwordHistory": [{"password": "2.old-history|old|old"}],
		"organizationUseTotp": false
	}`)

	// The server's copy after the move: everything re-encrypted with the
	// organization key.
	updated := json.RawMessage(`{
		"id": "cipher-1",
		"organizationId": "org-1",
		"key": null,
		"name": "2.new-name|new|new",
		"passwordHistory": [{"password": "2.new-history|new|new"}],
		"collectionIds": ["col-1"]
	}`)

	if err := PatchCipherRaw(updated); err != nil {
		t.Fatalf("PatchCipherRaw: %v", err)
	}

	ciphers := readRawVaultCiphers(t, home)
	if len(ciphers) != 1 {
		t.Fatalf("expected 1 cipher, got %d", len(ciphers))
	}
	got := ciphers[0]
	if got["organizationId"] != "org-1" {
		t.Errorf("organizationId: got %v", got["organizationId"])
	}
	if got["name"] != "2.new-name|new|new" {
		t.Errorf("name: got %v", got["name"])
	}
	history, ok := got["passwordHistory"].([]any)
	if !ok || len(history) != 1 {
		t.Fatalf("passwordHistory: got %v", got["passwordHistory"])
	}
	if entry := history[0].(map[string]any); entry["password"] != "2.new-history|new|new" {
		t.Errorf("unmodelled encrypted field was not refreshed: %v", entry["password"])
	}
	if ids, ok := got["collectionIds"].([]any); !ok || len(ids) != 1 || ids[0] != "col-1" {
		t.Errorf("collectionIds: got %v", got["collectionIds"])
	}
	// Keys only the cache knows about must survive.
	if _, present := got["organizationUseTotp"]; !present {
		t.Error("cached-only field organizationUseTotp was dropped")
	}
}

func TestPatchCipherRaw_AppendsWhenMissing(t *testing.T) {
	home := withTempHome(t)
	writeRawVaultCiphers(t, home, `{"id": "cipher-1"}`)

	if err := PatchCipherRaw(json.RawMessage(`{"id": "cipher-2", "name": "2.a|b|c"}`)); err != nil {
		t.Fatalf("PatchCipherRaw: %v", err)
	}

	ciphers := readRawVaultCiphers(t, home)
	if len(ciphers) != 2 || ciphers[1]["id"] != "cipher-2" {
		t.Errorf("expected the unknown cipher to be appended, got %v", ciphers)
	}
}

func TestPatchCipherRaw_LeavesOtherCiphersUntouched(t *testing.T) {
	home := withTempHome(t)
	writeRawVaultCiphers(t, home,
		`{"id": "cipher-1", "name": "2.one|one|one"}`,
		`{"id": "cipher-2", "name": "2.two|two|two"}`,
	)

	if err := PatchCipherRaw(json.RawMessage(`{"id": "cipher-2", "name": "2.new|new|new"}`)); err != nil {
		t.Fatalf("PatchCipherRaw: %v", err)
	}

	ciphers := readRawVaultCiphers(t, home)
	if len(ciphers) != 2 {
		t.Fatalf("expected 2 ciphers, got %d", len(ciphers))
	}
	if ciphers[0]["name"] != "2.one|one|one" {
		t.Errorf("unrelated cipher was modified: %v", ciphers[0])
	}
	if ciphers[1]["name"] != "2.new|new|new" {
		t.Errorf("target cipher not updated: %v", ciphers[1])
	}
}

func TestPatchCipherRaw_InvalidInput(t *testing.T) {
	home := withTempHome(t)
	writeRawVaultCiphers(t, home, `{"id": "cipher-1"}`)

	if err := PatchCipherRaw(json.RawMessage("not json")); err == nil {
		t.Error("expected an error for malformed JSON")
	}
	if err := PatchCipherRaw(json.RawMessage(`{"name": "2.a|b|c"}`)); err == nil {
		t.Error("expected an error for a cipher without an id")
	}
}
