package vault

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	keyring "github.com/zalando/go-keyring"
)

// withTempHome redirects the home directory to a temp dir for the duration of
// the test, ensuring session files do not leak between tests.
func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

// TestMain sets up a mock OS keyring so that session tests work without a
// real keyring daemon (e.g., in CI environments).
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

// TestLoadSession_NoFile verifies that LoadSession returns nil when the session
// file does not exist.
func TestLoadSession_NoFile(t *testing.T) {
	withTempHome(t)

	session, err := LoadSession(15)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session != nil {
		t.Fatal("expected nil session when no file exists")
	}
}

// TestSaveAndLoadSession verifies that a session can be saved and loaded back.
func TestSaveAndLoadSession(t *testing.T) {
	withTempHome(t)

	accountKey := []byte("accountkey-64bytes-padding-1234567890123456789012345678901234")
	orgKeys := map[string][]byte{
		"org-1": []byte("orgkey-64bytes-padding-12345678901234567890123456789012345678"),
	}

	if err := SaveSession(accountKey, orgKeys); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	session, err := LoadSession(15)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if session == nil {
		t.Fatal("expected non-nil session after save")
	}

	if string(session.AccountKey) != string(accountKey) {
		t.Errorf("account key mismatch: got %q, want %q", session.AccountKey, accountKey)
	}
	if len(session.OrgKeys) != 1 {
		t.Errorf("org keys count mismatch: got %d, want 1", len(session.OrgKeys))
	}
	if string(session.OrgKeys["org-1"]) != string(orgKeys["org-1"]) {
		t.Errorf("org key mismatch: got %q, want %q", session.OrgKeys["org-1"], orgKeys["org-1"])
	}
}

// TestSessionFileHasNoKeyMaterial verifies that the on-disk session file does
// not contain the account key or org keys – only the timestamp.  This ensures
// that copying the file alongside the vault is insufficient to decrypt it.
func TestSessionFileHasNoKeyMaterial(t *testing.T) {
	home := withTempHome(t)

	accountKey := []byte("super-secret-account-key")
	if err := SaveSession(accountKey, nil); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	path := filepath.Join(home, ".bx_session.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(raw, accountKey) {
		t.Error("session file must not contain account key material")
	}
}

// TestLoadSession_Expired verifies that a session past its timeout is ignored
// and the file is removed.
func TestLoadSession_Expired(t *testing.T) {
	home := withTempHome(t)

	// Write an expired timestamp file directly (no key material in the file).
	ts := sessionTimestamp{UnlockedAt: time.Now().Add(-2 * time.Hour)}
	path := filepath.Join(home, ".bx_session.json")
	data, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	session, err := LoadSession(15)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if session != nil {
		t.Fatal("expected nil session for expired entry")
	}

	// The session file should have been removed.
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Error("expected session file to be removed after expiry")
	}
}

// TestClearSession verifies that ClearSession removes the file and keyring
// entry, and is a no-op when neither exists.
func TestClearSession(t *testing.T) {
	home := withTempHome(t)

	// ClearSession on a missing file should not return an error.
	if err := ClearSession(); err != nil {
		t.Fatalf("ClearSession (no file): %v", err)
	}

	if err := SaveSession([]byte("somekey"), nil); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	path := filepath.Join(home, ".bx_session.json")
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("session file should exist after save: %v", err)
	}

	if err := ClearSession(); err != nil {
		t.Fatalf("ClearSession: %v", err)
	}

	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Error("expected session file to be removed by ClearSession")
	}

	// Keyring entry should also be gone.
	if _, err := keyring.Get(keyringService, sessionKeyringUser()); err != keyring.ErrNotFound {
		t.Error("expected keyring entry to be removed by ClearSession")
	}
}

// TestLoadSession_FilePermissions verifies that the session file is created
// with owner-only (0600) permissions.
func TestLoadSession_FilePermissions(t *testing.T) {
	home := withTempHome(t)

	if err := SaveSession([]byte("key"), nil); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	path := filepath.Join(home, ".bx_session.json")
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("expected permissions 0600, got %v", fi.Mode().Perm())
	}
}

// TestLoadSession_InsecurePermissions verifies that LoadSession rejects a
// session file with permissions that allow group or world access.
func TestLoadSession_InsecurePermissions(t *testing.T) {
	home := withTempHome(t)

	if err := SaveSession([]byte("key"), nil); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	path := filepath.Join(home, ".bx_session.json")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	_, err := LoadSession(15)
	if err == nil {
		t.Fatal("expected error for insecure session file permissions")
	}
}

// TestLoadSession_CorruptTimestampFile verifies that LoadSession handles a corrupt
// timestamp file gracefully, returning nil and removing the corrupt file.
func TestLoadSession_CorruptTimestampFile(t *testing.T) {
	home := withTempHome(t)

	path := filepath.Join(home, ".bx_session.json")
	if err := os.WriteFile(path, []byte("not-valid-json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	session, err := LoadSession(15)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session != nil {
		t.Fatal("expected nil session for corrupt timestamp file")
	}

	// The corrupt file should have been removed.
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Error("expected corrupt session file to be removed")
	}
}

// TestLoadSession_CorruptKeyringData verifies that LoadSession treats a valid
// timestamp paired with corrupt keyring JSON as no session.
func TestLoadSession_CorruptKeyringData(t *testing.T) {
	withTempHome(t)

	// Use SaveSession to write a valid timestamp, then overwrite the keyring entry
	// with corrupt JSON.
	if err := SaveSession([]byte("real-key"), nil); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if err := keyring.Set(keyringService, sessionKeyringUser(), "not-valid-json"); err != nil {
		t.Fatalf("keyring.Set: %v", err)
	}

	session, err := LoadSession(15)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session != nil {
		t.Fatal("expected nil session for corrupt keyring data")
	}
}

// TestLoadSession_MissingKeyringEntry verifies that a valid timestamp file
// without a corresponding keyring entry is treated as no session.
func TestLoadSession_MissingKeyringEntry(t *testing.T) {
	home := withTempHome(t)

	// Write a fresh timestamp file without touching the keyring.
	ts := sessionTimestamp{UnlockedAt: time.Now()}
	path := filepath.Join(home, ".bx_session.json")
	data, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Ensure the keyring entry is absent.
	_ = keyring.Delete(keyringService, sessionKeyringUser())

	session, err := LoadSession(15)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session != nil {
		t.Fatal("expected nil session when keyring entry is missing")
	}
}

// --- ActiveAccount / per-account session paths ---

// TestSaveAndLoadSession_WithActiveAccount verifies that sessions are isolated
// per account when ActiveAccount is set.
func TestSaveAndLoadSession_WithActiveAccount(t *testing.T) {
	withTempHome(t)

	// Save session for "work" account.
	ActiveAccount = "work"
	workKey := []byte("work-account-key-64bytes-padding-1234567890123456789012345")
	if err := SaveSession(workKey, nil); err != nil {
		t.Fatalf("SaveSession work: %v", err)
	}

	// Save session for "personal" account.
	ActiveAccount = "personal"
	personalKey := []byte("personal-account-key-64bytes-padding-12345678901234567890123")
	if err := SaveSession(personalKey, nil); err != nil {
		t.Fatalf("SaveSession personal: %v", err)
	}

	// Load work session — should return the work key.
	ActiveAccount = "work"
	workSession, err := LoadSession(15)
	if err != nil {
		t.Fatalf("LoadSession work: %v", err)
	}
	if workSession == nil {
		t.Fatal("expected non-nil session for work account")
	}
	if string(workSession.AccountKey) != string(workKey) {
		t.Errorf("work key mismatch: got %q, want %q", workSession.AccountKey, workKey)
	}

	// Load personal session — should return the personal key.
	ActiveAccount = "personal"
	personalSession, err := LoadSession(15)
	if err != nil {
		t.Fatalf("LoadSession personal: %v", err)
	}
	if personalSession == nil {
		t.Fatal("expected non-nil session for personal account")
	}
	if string(personalSession.AccountKey) != string(personalKey) {
		t.Errorf("personal key mismatch: got %q, want %q", personalSession.AccountKey, personalKey)
	}

	ActiveAccount = ""
}

// TestClearSession_WithActiveAccount verifies that ClearSession only removes the
// session for the active account and leaves other accounts' sessions intact.
func TestClearSession_WithActiveAccount(t *testing.T) {
	home := withTempHome(t)

	// Create sessions for two accounts.
	ActiveAccount = "work"
	if err := SaveSession([]byte("work-key"), nil); err != nil {
		t.Fatalf("SaveSession work: %v", err)
	}
	ActiveAccount = "personal"
	if err := SaveSession([]byte("personal-key"), nil); err != nil {
		t.Fatalf("SaveSession personal: %v", err)
	}

	// Clear only the work session.
	ActiveAccount = "work"
	if err := ClearSession(); err != nil {
		t.Fatalf("ClearSession work: %v", err)
	}

	// Work session file should be gone.
	workPath := filepath.Join(home, ".bx_session_work.json")
	if _, err := os.Lstat(workPath); !os.IsNotExist(err) {
		t.Error("expected work session file to be removed")
	}

	// Personal session file should still exist.
	personalPath := filepath.Join(home, ".bx_session_personal.json")
	if _, err := os.Lstat(personalPath); err != nil {
		t.Errorf("personal session file should still exist: %v", err)
	}

	ActiveAccount = ""
}
