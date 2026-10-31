package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	keyring "github.com/zalando/go-keyring"
)

// DefaultUnlockTimeoutMinutes is the default duration (in minutes) for which
// the vault remains unlocked after a successful password entry, similar to sudo.
const DefaultUnlockTimeoutMinutes = 15

const keyringService = "bx"

// ActiveAccount is the name of the currently active account.  When non-empty
// it is used to derive per-account session and vault file names so that
// multiple accounts can coexist on the same machine.  Set this before calling
// any Load/Save/Clear session or vault functions.
var ActiveAccount string

// sessionTimestamp is the on-disk representation of the session.  Only the
// unlock time is written to disk; key material is kept exclusively in the OS
// keyring so that copying the session file alongside the vault file is
// insufficient to decrypt the vault.
type sessionTimestamp struct {
	UnlockedAt time.Time `json:"unlocked_at"`
}

// sessionKeys is the value stored in the OS keyring.
type sessionKeys struct {
	AccountKey []byte            `json:"account_key"`
	OrgKeys    map[string][]byte `json:"org_keys"`
}

// Session holds the decrypted vault keys loaded at runtime.  These are never
// written to the session file on disk.
type Session struct {
	UnlockedAt time.Time
	AccountKey []byte
	OrgKeys    map[string][]byte
}

// sessionPath returns the path to the session timestamp file.
// When ActiveAccount is set it returns a per-account path so that multiple
// accounts can maintain independent session caches.
func sessionPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if ActiveAccount != "" {
		return filepath.Join(home, ".bx_session_"+ActiveAccount+".json"), nil
	}
	return filepath.Join(home, ".bx_session.json"), nil
}

// sessionKeyringUser returns the OS-keyring user key for the active account.
func sessionKeyringUser() string {
	if ActiveAccount != "" {
		return "session_" + ActiveAccount
	}
	return "session"
}

// LoadSession reads the session timestamp file and the OS keyring, returning a
// valid Session when both exist and the session has not yet expired.
// Returns nil (with no error) when no valid session is available.
func LoadSession(timeoutMinutes int) (*Session, error) {
	path, err := sessionPath()
	if err != nil {
		return nil, err
	}

	// Check metadata before reading content to guard against TOCTOU.
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	// Refuse to use a symlink or a file with insecure permissions.
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("session file %s is a symlink, refusing to read", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("session file %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("session file %s has insecure permissions %v", path, fi.Mode().Perm())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ts sessionTimestamp
	if err := json.Unmarshal(data, &ts); err != nil {
		// Corrupt timestamp file – treat as no session.
		_ = ClearSession()
		return nil, nil
	}

	if time.Since(ts.UnlockedAt) > time.Duration(timeoutMinutes)*time.Minute {
		// Session has expired.
		_ = ClearSession()
		return nil, nil
	}

	// Retrieve key material from the OS keyring.  If it is absent (e.g. the
	// keyring entry was cleared externally), treat as no session.
	raw, err := keyring.Get(keyringService, sessionKeyringUser())
	if err != nil {
		_ = ClearSession()
		return nil, nil
	}

	var keys sessionKeys
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		_ = ClearSession()
		return nil, nil
	}

	return &Session{
		UnlockedAt: ts.UnlockedAt,
		AccountKey: keys.AccountKey,
		OrgKeys:    keys.OrgKeys,
	}, nil
}

// SaveSession stores only the unlock timestamp on disk (0600) and writes the
// derived vault keys exclusively to the OS keyring.  If the OS keyring is
// unavailable, SaveSession returns an error and nothing is persisted.
func SaveSession(accountKey []byte, orgKeys map[string][]byte) error {
	// Encode key material and store in the OS keyring first.  If this fails
	// (e.g. no keyring daemon available) we do not fall back to storing keys
	// on disk.
	keys := sessionKeys{
		AccountKey: accountKey,
		OrgKeys:    orgKeys,
	}
	keysJSON, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	if err := keyring.Set(keyringService, sessionKeyringUser(), string(keysJSON)); err != nil {
		return fmt.Errorf("failed to store session keys in OS keyring: %w", err)
	}

	// Roll back the keyring entry on any subsequent error so that a stale
	// entry is never left behind without a corresponding timestamp file.
	keyringOK := false
	defer func() {
		if !keyringOK {
			_ = keyring.Delete(keyringService, sessionKeyringUser())
		}
	}()

	// Only write the timestamp file after the keyring write succeeds.
	path, err := sessionPath()
	if err != nil {
		return err
	}

	ts := sessionTimestamp{UnlockedAt: time.Now()}
	tsData, err := json.Marshal(ts)
	if err != nil {
		return err
	}

	// Write to a fresh temp file in the same directory, then rename atomically.
	// Using os.CreateTemp ensures the temp file is new (O_EXCL), preventing
	// symlink injection at the temp path.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".bx_session_*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(tsData); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}

	keyringOK = true
	return nil
}

// ClearSession removes the session timestamp file and the OS keyring entry,
// immediately locking the vault.  Returns nil if neither exists.
func ClearSession() error {
	// Remove the timestamp file.
	path, err := sessionPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	// Remove the keyring entry (best-effort: ignore "not found" errors).
	if err := keyring.Delete(keyringService, sessionKeyringUser()); err != nil && err != keyring.ErrNotFound {
		return err
	}

	return nil
}
