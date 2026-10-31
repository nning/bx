package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
)

// loadSyncData reads and parses the local vault file without performing any
// cryptographic operations. It is used by LoadVaultWithSession to load the
// vault data independently of key derivation.
func loadSyncData() (*client.SyncResponse, error) {
	path, err := VaultPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read vault from %s: %w. Did you run 'bx fetch'?", path, err)
	}
	var syncResp client.SyncResponse
	if err := json.Unmarshal(data, &syncResp); err != nil {
		return nil, err
	}
	if err := validateSyncResponse(&syncResp); err != nil {
		return nil, fmt.Errorf("invalid vault response: %w", err)
	}
	return &syncResp, nil
}

// LoadVaultWithSession loads the vault using a cached session when available.
// The returned bool is true when the master password was prompted interactively
// (i.e. passwordFn was called), and false when keys were loaded from a cached
// session without user interaction. Callers can use this to suppress UI
// decorations (e.g. blank lines) that only make sense after a prompt.
//
// If a valid session exists (timeoutMinutes > 0 and session not expired), the
// vault data is loaded and the cached decryption keys are returned without
// calling passwordFn. Otherwise passwordFn is called to obtain the master
// password, the keys are derived via LoadVault, and a new session is saved.
//
// Setting timeoutMinutes to 0 disables session caching entirely and always
// calls passwordFn.
func LoadVaultWithSession(timeoutMinutes int, passwordFn func() (string, error)) (*client.SyncResponse, []byte, map[string][]byte, bool, error) {
	if timeoutMinutes > 0 {
		session, err := LoadSession(timeoutMinutes)
		if err == nil && session != nil {
			syncResp, err := loadSyncData()
			if err != nil {
				return nil, nil, nil, false, err
			}
			return syncResp, session.AccountKey, session.OrgKeys, false, nil
		}
	}

	password, err := passwordFn()
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("failed to read password: %w", err)
	}

	syncResp, accountKey, orgKeys, err := LoadVault(password)
	if err != nil {
		return nil, nil, nil, false, err
	}

	if timeoutMinutes > 0 {
		// Best-effort: do not fail the command if session save fails.
		_ = SaveSession(accountKey, orgKeys)
	}

	return syncResp, accountKey, orgKeys, true, nil
}

// LoadVault loads the vault from the local file and decrypts the account key and
// any organization symmetric keys. The returned orgKeys map is keyed by org ID.
func LoadVault(password string) (*client.SyncResponse, []byte, map[string][]byte, error) {
	syncResp, err := loadSyncData()
	if err != nil {
		return nil, nil, nil, err
	}

	// Use KDF parameters from UserDecryption if available, otherwise from profile
	var kdfType, iterations, memory, parallelism int
	var email string

	if syncResp.UserDecryption != nil {
		kdf := syncResp.UserDecryption.MasterPasswordUnlock.Kdf
		kdfType = kdf.KdfType
		iterations = kdf.Iterations
		if kdf.Memory != nil {
			memory = *kdf.Memory
		}
		if kdf.Parallelism != nil {
			parallelism = *kdf.Parallelism
		}
		email = syncResp.UserDecryption.MasterPasswordUnlock.Salt
	}

	if email == "" {
		email = syncResp.Profile.Email
	}

	// Derive Master Key
	kdfConfig := crypto.KdfConfig{
		Type:        crypto.KdfType(kdfType),
		Iterations:  iterations,
		Memory:      memory,
		Parallelism: parallelism,
	}

	masterKey, err := crypto.DeriveMasterKey(password, email, kdfConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("master key derivation failed: %w", err)
	}

	// Expand master key to 64 bytes for decrypting the protected symmetric key
	expandedMasterKey, err := crypto.ExpandKey(masterKey)
	crypto.Wipe(masterKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("key expansion failed: %w", err)
	}

	// Decrypt the account key (User Symmetric Key)
	accountKeyBytes, err := crypto.Decrypt(syncResp.Profile.Key, expandedMasterKey)
	crypto.Wipe(expandedMasterKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decrypt account key: %w", err)
	}

	// Fail explicitly when a supplied organization key cannot be decrypted.
	// Empty keys can represent pending invitations and are skipped.
	orgKeys := make(map[string][]byte)
	for _, org := range syncResp.Profile.Organizations {
		if org.Key == "" {
			continue
		}
		privKeyDER, err := crypto.Decrypt(syncResp.Profile.PrivateKey, accountKeyBytes)
		if err != nil || len(privKeyDER) == 0 {
			crypto.Wipe(accountKeyBytes)
			return nil, nil, nil, fmt.Errorf("could not load private key for organization %s", org.ID)
		}
		orgKey, err := crypto.DecryptRSAOAEP(org.Key, privKeyDER)
		crypto.Wipe(privKeyDER)
		if err == nil {
			orgKey, err = crypto.NormalizeSymmetricKey(orgKey)
		}
		if err != nil {
			crypto.Wipe(accountKeyBytes)
			for _, key := range orgKeys {
				crypto.Wipe(key)
			}
			return nil, nil, nil, fmt.Errorf("could not decrypt organization %s key: %w", org.ID, err)
		}
		orgKeys[org.ID] = orgKey
	}

	return syncResp, accountKeyBytes, orgKeys, nil
}

// validateSyncResponse validates the sync response structure.
func validateSyncResponse(resp *client.SyncResponse) error {
	if resp == nil {
		return fmt.Errorf("response is nil")
	}
	if resp.Profile.ID == "" {
		return fmt.Errorf("profile ID is empty")
	}
	if resp.Profile.Email == "" {
		return fmt.Errorf("profile email is empty")
	}
	if resp.Profile.Key == "" {
		return fmt.Errorf("profile key is empty")
	}
	// Reasonable bounds check
	if len(resp.Ciphers) > 100000 {
		return fmt.Errorf("cipher count unreasonably large: %d", len(resp.Ciphers))
	}
	if len(resp.Folders) > 100000 {
		return fmt.Errorf("folder count unreasonably large: %d", len(resp.Folders))
	}
	if len(resp.Collections) > 100000 {
		return fmt.Errorf("collection count unreasonably large: %d", len(resp.Collections))
	}
	return nil
}

// PatchCipherOp identifies the type of patch operation to apply to the local
// vault cache for ciphers.
type PatchCipherOp int

const (
	// PatchCipherCreate appends the cipher to the local cache.
	PatchCipherCreate PatchCipherOp = iota
	// PatchCipherEdit replaces the matching cipher in the local cache by ID.
	// Use this for both edits, soft-deletes (server sets DeletedDate), and
	// restores (server clears DeletedDate).
	PatchCipherEdit
	// PatchCipherHardDelete removes the cipher from the local cache by ID.
	PatchCipherHardDelete
)

// PatchFolderOp identifies the type of patch operation to apply to the local
// vault cache for folders.
type PatchFolderOp int

const (
	// PatchFolderCreate appends the folder to the local cache.
	PatchFolderCreate PatchFolderOp = iota
	// PatchFolderDelete removes the folder from the local cache by ID.
	PatchFolderDelete
	// PatchFolderEdit replaces the matching folder in the local cache by ID.
	// Use this for renames.
	PatchFolderEdit
)

// VaultPath returns the path to the local vault cache file for the active
// account.  It is exported so that commands outside this package (e.g. fetch)
// can write to the same path that LoadVault reads from.
func VaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if ActiveAccount != "" {
		return filepath.Join(home, ".bx_vault_"+ActiveAccount+".json"), nil
	}
	return filepath.Join(home, ".bx_vault.json"), nil
}

// patchVaultFile reads the raw vault JSON, calls patchFn to apply an in-memory
// change, and writes the result back atomically with 0600 permissions.
// patchFn receives the raw JSON map and must return the modified map.
func patchVaultFile(patchFn func(raw map[string]json.RawMessage) error) error {
	path, err := VaultPath()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read vault %s: %w", path, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("could not parse vault JSON: %w", err)
	}

	if err := patchFn(raw); err != nil {
		return err
	}

	newData, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("could not marshal patched vault: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".bx_vault_*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(newData); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// On POSIX, os.Rename atomically replaces the destination.
	// On Windows it fails when the destination already exists, so fall back to
	// removing the destination first and retrying.  Removing before the first
	// attempt is avoided to keep the POSIX path fully atomic.
	if err := os.Rename(tmpPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("failed to replace vault file %q: %w (also failed to remove existing: %v)", path, err, removeErr)
		}
		if retryErr := os.Rename(tmpPath, path); retryErr != nil {
			return fmt.Errorf("failed to replace vault file %q: %w", path, retryErr)
		}
	}
	return nil
}

// PatchCipher applies op to the local vault cache using the provided cipher.
// The vault file is updated atomically with 0600 permissions.
// Each cipher entry is kept as a raw JSON message so that unknown fields
// present in any untouched entry are never discarded.
func PatchCipher(op PatchCipherOp, cipher *client.Cipher) error {
	return patchVaultFile(func(raw map[string]json.RawMessage) error {
		// Load existing entries as raw JSON blobs to preserve unknown fields.
		var rawCiphers []json.RawMessage
		if ciphersJSON, ok := raw["ciphers"]; ok {
			if err := json.Unmarshal(ciphersJSON, &rawCiphers); err != nil {
				return fmt.Errorf("could not parse ciphers: %w", err)
			}
		}

		// Marshal the new/updated cipher once for reuse.
		newBlob, err := json.Marshal(cipher)
		if err != nil {
			return fmt.Errorf("could not marshal cipher: %w", err)
		}

		switch op {
		case PatchCipherCreate:
			rawCiphers = append(rawCiphers, newBlob)

		case PatchCipherEdit:
			rawCiphers, err = mergeCipherIntoBlobs(rawCiphers, cipher.ID, newBlob)
			if err != nil {
				return err
			}

		case PatchCipherHardDelete:
			updated := rawCiphers[:0]
			for _, blob := range rawCiphers {
				var entry struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(blob, &entry); err != nil || entry.ID != cipher.ID {
					updated = append(updated, blob)
				}
			}
			rawCiphers = updated

		default:
			return fmt.Errorf("PatchCipher: unknown op %d", op)
		}

		b, err := json.Marshal(rawCiphers)
		if err != nil {
			return err
		}
		raw["ciphers"] = b
		return nil
	})
}

// PatchCipherRaw replaces the cached entry for a cipher with the server's raw
// JSON copy of it, merging it over the cached blob by ID.
//
// It exists for writes that change *every* encrypted value of an item — moving a
// personal item into an organization re-encrypts it with the organization key —
// where patching from bx's typed Cipher would leave fields bx does not model
// (password history, card, identity, and SSH key data) behind in the cache still
// encrypted with the old key.
func PatchCipherRaw(raw json.RawMessage) error {
	var entry struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		return fmt.Errorf("could not parse cipher: %w", err)
	}
	if entry.ID == "" {
		return fmt.Errorf("cipher has no id")
	}

	return patchVaultFile(func(rawVault map[string]json.RawMessage) error {
		var rawCiphers []json.RawMessage
		if ciphersJSON, ok := rawVault["ciphers"]; ok {
			if err := json.Unmarshal(ciphersJSON, &rawCiphers); err != nil {
				return fmt.Errorf("could not parse ciphers: %w", err)
			}
		}

		rawCiphers, err := mergeCipherIntoBlobs(rawCiphers, entry.ID, raw)
		if err != nil {
			return err
		}

		b, err := json.Marshal(rawCiphers)
		if err != nil {
			return err
		}
		rawVault["ciphers"] = b
		return nil
	})
}

// mergeCipherIntoBlobs merges newBlob over the cached entry with the given ID,
// preserving unknown fields of that entry.  When no entry matches — which can
// happen after an incomplete sync or a manually edited vault file — the blob is
// appended instead of dropped.
func mergeCipherIntoBlobs(rawCiphers []json.RawMessage, id string, newBlob json.RawMessage) ([]json.RawMessage, error) {
	for i, blob := range rawCiphers {
		var entry struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(blob, &entry); err != nil || entry.ID != id {
			continue
		}
		merged, err := mergeCipherBlob(blob, newBlob)
		if err != nil {
			return nil, err
		}
		rawCiphers[i] = merged
		return rawCiphers, nil
	}
	return append(rawCiphers, newBlob), nil
}

// mergeCipherBlob combines the cached cipher blob with the freshly marshalled
// inbound cipher, returning a new JSON blob that preserves unknown fields.
//
// The merge is recursive: at every level it walks two parallel maps (the
// cached raw blob and the newly marshalled blob) and copies each key from the
// new blob into the cached blob, leaving any cached keys the new struct does
// not model untouched. This prevents a bx edit on a cipher that has
// server-supplied fields bx does not yet understand (e.g. future schema
// additions beyond fido2Credentials) from silently dropping those fields
// from the local cache until the next `bx fetch`.
//
// The `id` key is always taken from the new blob to match the inbound
// struct's identity; nested objects below the top level recurse the same way
// so that, for example, an unknown field inside `login` survives an edit
// even if our CipherLogin struct doesn't model it.
func mergeCipherBlob(cachedBlob, newBlob json.RawMessage) (json.RawMessage, error) {
	return mergeRawMaps(cachedBlob, newBlob)
}

// mergeRawMaps deserializes both blobs into map[string]json.RawMessage and
// returns the result of overlaying `fresh` onto `cached`: every key present
// in `fresh` replaces its counterpart in `cached`, every key only in `cached`
// is preserved. When both values at a given key are themselves JSON objects,
// the merge recurses; otherwise the value from `fresh` wins.
func mergeRawMaps(cached, fresh json.RawMessage) (json.RawMessage, error) {
	var cachedMap, freshMap map[string]json.RawMessage
	if err := json.Unmarshal(cached, &cachedMap); err != nil {
		// cached isn't an object — fall back to the fresh blob alone so we
		// don't lose the inbound write.
		return fresh, nil
	}
	if err := json.Unmarshal(fresh, &freshMap); err != nil {
		// fresh isn't an object — keep cached unchanged.
		return cached, nil
	}

	for key, freshVal := range freshMap {
		if cachedVal, ok := cachedMap[key]; ok {
			// Recurse into nested objects when both sides are objects.
			if isJSONObject(cachedVal) && isJSONObject(freshVal) {
				merged, err := mergeRawMaps(cachedVal, freshVal)
				if err != nil {
					return nil, err
				}
				cachedMap[key] = merged
				continue
			}
		}
		cachedMap[key] = freshVal
	}

	return json.Marshal(cachedMap)
}

// isJSONObject reports whether b is a JSON object (starts with '{' after
// optional whitespace). It is used by mergeRawMaps to decide whether to
// recurse into nested values.
func isJSONObject(b json.RawMessage) bool {
	for _, c := range b {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		return c == '{'
	}
	return false
}

// mergeFolderIntoBlobs merges newBlob over the cached folder entry with the
// given ID, preserving unknown fields of that entry.  When no entry matches —
// which can happen after an incomplete sync or a manually edited vault file —
// the blob is appended instead of dropped.
func mergeFolderIntoBlobs(rawFolders []json.RawMessage, id string, newBlob json.RawMessage) ([]json.RawMessage, error) {
	for i, blob := range rawFolders {
		var entry struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(blob, &entry); err != nil || entry.ID != id {
			continue
		}
		merged, err := mergeRawMaps(blob, newBlob)
		if err != nil {
			return nil, err
		}
		rawFolders[i] = merged
		return rawFolders, nil
	}
	return append(rawFolders, newBlob), nil
}

// PatchFolder applies op to the local vault cache using the provided folder.
// The vault file is updated atomically with 0600 permissions.
// Each folder entry is kept as a raw JSON message so that unknown fields
// present in any untouched entry are never discarded.
func PatchFolder(op PatchFolderOp, folder *client.Folder) error {
	return patchVaultFile(func(raw map[string]json.RawMessage) error {
		// Load existing entries as raw JSON blobs to preserve unknown fields.
		var rawFolders []json.RawMessage
		if foldersJSON, ok := raw["folders"]; ok {
			if err := json.Unmarshal(foldersJSON, &rawFolders); err != nil {
				return fmt.Errorf("could not parse folders: %w", err)
			}
		}

		// Marshal the new/updated folder once for reuse.
		newBlob, err := json.Marshal(folder)
		if err != nil {
			return fmt.Errorf("could not marshal folder: %w", err)
		}

		switch op {
		case PatchFolderCreate:
			rawFolders = append(rawFolders, newBlob)

		case PatchFolderDelete:
			updated := rawFolders[:0]
			for _, blob := range rawFolders {
				var entry struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(blob, &entry); err != nil || entry.ID != folder.ID {
					updated = append(updated, blob)
				}
			}
			rawFolders = updated

		case PatchFolderEdit:
			rawFolders, err = mergeFolderIntoBlobs(rawFolders, folder.ID, newBlob)
			if err != nil {
				return err
			}

		default:
			return fmt.Errorf("PatchFolder: unknown op %d", op)
		}

		b, err := json.Marshal(rawFolders)
		if err != nil {
			return err
		}
		raw["folders"] = b
		return nil
	})
}
