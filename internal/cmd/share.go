package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
)

// cipherRequestKeys is the set of cipher JSON keys forwarded to
// PUT /api/ciphers/{id} and PUT /api/ciphers/{id}/share.  Keys that only exist in server *responses*
// (attachments, permissions, edit, viewPassword, revisionDate, …) are dropped:
// their JSON shape differs from the request model and sending them can make the
// server reject the whole request.
//
// Everything the request model does accept is forwarded verbatim — including
// keys bx does not model, such as passwordHistory, card, identity, secureNote,
// and sshKey — because the server replaces the item's contents with whatever the
// request contains.  Omitting a field would delete it.
var cipherRequestKeys = map[string]bool{
	"id":              true,
	"type":            true,
	"folderId":        true,
	"favorite":        true,
	"reprompt":        true,
	"key":             true,
	"name":            true,
	"notes":           true,
	"fields":          true,
	"login":           true,
	"card":            true,
	"identity":        true,
	"secureNote":      true,
	"sshKey":          true,
	"data":            true,
	"archivedDate":    true,
	"passwordHistory": true,
}

// cipherRequestFields returns the members of a raw cipher object that belong
// in a write request (see cipherRequestKeys).
func cipherRequestFields(obj map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(obj))
	for key, val := range obj {
		if cipherRequestKeys[key] {
			out[key] = val
		}
	}
	return out
}

// setEncryptedFor sets the encryptedFor member of a write request: the ID of
// the user whose keys encrypted it.  Vaultwarden 1.37.4 and later reject a
// request without it, and the official clients always send it.
func setEncryptedFor(out map[string]json.RawMessage, userID string) error {
	b, err := json.Marshal(userID)
	if err != nil {
		return err
	}
	out["encryptedFor"] = b
	return nil
}

// cipherRawString extracts a top-level string field from a raw cipher JSON
// object.  Missing, null, and non-string values yield "".
func cipherRawString(raw json.RawMessage, field string) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	val, ok := obj[field]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(val, &s); err != nil {
		return ""
	}
	return s
}

// rawCipherHasAttachments reports whether a raw cipher JSON object carries at
// least one attachment.
func rawCipherHasAttachments(raw json.RawMessage) bool {
	attachments, err := rawCipherAttachments(raw)
	return err == nil && len(attachments) > 0
}

// attachmentsBlockMove reports whether an item with attachments cannot be
// moved to an organization.  Only items with a per-item key are safe: only
// the wrapped item key is re-encrypted, so the attachment keys (wrapped in the
// item key) and the attachment files stay valid.  When the item is encrypted
// with the account key directly, the attachment keys would have to be
// re-encrypted too, which the share request cannot express.
func attachmentsBlockMove(raw json.RawMessage) bool {
	if !rawCipherHasAttachments(raw) {
		return false
	}
	return cipherRawString(raw, "key") == ""
}

// buildShareCipher turns the server's copy of a personal cipher into the
// `cipher` object of a share request that is readable by members of the target
// organization.
//
// Two cases exist.  When the item has a per-item key, every encrypted value is
// encrypted with *that* key, so only the item key itself has to be re-wrapped —
// from the account key to the organization key — and all ciphertexts stay as
// they are.  Otherwise the values are encrypted with the account key directly
// and each one is re-encrypted with the organization key.
//
// lastKnownRevisionDate is set from the server copy's revisionDate so the server
// performs its own conflict check on top of ours.
func buildShareCipher(raw json.RawMessage, orgID, userID string, accountKey, orgKey []byte) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("could not parse server copy of item: %w", err)
	}

	out := cipherRequestFields(obj)

	orgIDJSON, err := json.Marshal(orgID)
	if err != nil {
		return nil, err
	}
	out["organizationId"] = orgIDJSON
	if revision, ok := obj["revisionDate"]; ok {
		out["lastKnownRevisionDate"] = revision
	}
	if err := setEncryptedFor(out, userID); err != nil {
		return nil, err
	}

	if itemKey := cipherRawString(raw, "key"); itemKey != "" {
		keyBytes, err := crypto.Decrypt(itemKey, accountKey)
		if err != nil {
			return nil, fmt.Errorf("could not decrypt the item's own key: %w", err)
		}
		rewrapped, err := crypto.Encrypt(keyBytes, orgKey)
		if err != nil {
			return nil, fmt.Errorf("could not re-encrypt the item's own key: %w", err)
		}
		rewrappedJSON, err := json.Marshal(rewrapped)
		if err != nil {
			return nil, err
		}
		out["key"] = rewrappedJSON
		return json.Marshal(out)
	}

	for key, val := range out {
		reencrypted, err := reencryptJSONValue(val, accountKey, orgKey)
		if err != nil {
			return nil, fmt.Errorf("could not re-encrypt %s: %w", key, err)
		}
		out[key] = reencrypted
	}
	return json.Marshal(out)
}

// reencryptJSONValue walks a JSON value and re-encrypts every string that is a
// Bitwarden cipher string from oldKey to newKey, leaving all other values
// untouched.  Walking the raw JSON rather than a typed struct means custom
// fields, passkeys, password history, and any field bx does not model are
// re-encrypted too.
//
// Any cipher string that fails to decrypt aborts the walk: a partially
// re-encrypted item would be unreadable for everyone.
func reencryptJSONValue(val json.RawMessage, oldKey, newKey []byte) (json.RawMessage, error) {
	trimmed := bytes.TrimLeft(val, " \t\r\n")
	if len(trimmed) == 0 {
		return val, nil
	}

	switch trimmed[0] {
	case '{':
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(val, &obj); err != nil {
			return nil, err
		}
		for key, member := range obj {
			reencrypted, err := reencryptJSONValue(member, oldKey, newKey)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			obj[key] = reencrypted
		}
		return json.Marshal(obj)

	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(val, &arr); err != nil {
			return nil, err
		}
		for i, item := range arr {
			reencrypted, err := reencryptJSONValue(item, oldKey, newKey)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			arr[i] = reencrypted
		}
		return json.Marshal(arr)

	case '"':
		var s string
		if err := json.Unmarshal(val, &s); err != nil {
			return nil, err
		}
		if !crypto.IsCipherString(s) {
			return val, nil
		}
		reencrypted, err := crypto.Reencrypt(s, oldKey, newKey)
		if err != nil {
			return nil, err
		}
		return json.Marshal(reencrypted)

	default:
		// Numbers, booleans, and null carry no ciphertext.
		return val, nil
	}
}

// rawCipherAttachments decodes the attachments of a raw cipher JSON object.
func rawCipherAttachments(raw json.RawMessage) ([]client.CipherAttachment, error) {
	var obj struct {
		Attachments []client.CipherAttachment `json:"attachments"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	return obj.Attachments, nil
}

// organizationKey returns the organization's symmetric key in the 64-byte form
// Encrypt and Decrypt expect.  A missing key means the vault cache predates
// joining the organization or its key could not be unwrapped with the account's
// RSA key, neither of which allows reading or writing its items.
func organizationKey(orgID, orgName string, orgKeys map[string][]byte) ([]byte, error) {
	key, ok := orgKeys[orgID]
	if !ok {
		return nil, fmt.Errorf("no decryption key available for organization %q; run 'bx fetch' to refresh the vault", orgName)
	}
	normalized, err := crypto.NormalizeSymmetricKey(key)
	if err != nil {
		return nil, fmt.Errorf("unusable key for organization %q: %w", orgName, err)
	}
	return normalized, nil
}

// ownershipTarget is the outcome of resolving --organization against the
// organization an item currently belongs to.  move is true when the item has to
// be transferred (and therefore re-encrypted); when it is false only the item's
// collection assignment changes.
type ownershipTarget struct {
	orgID   string
	orgName string
	move    bool
}

// resolveOwnershipTarget decides which organization an ownership change targets
// and rejects the combinations the Bitwarden API cannot express: unsharing an
// item and moving one organization's item into another organization.
func resolveOwnershipTarget(itemName, orgFlag string, orgFlagChanged bool, currentOrgID string, orgs []client.ProfileOrganization) (*ownershipTarget, error) {
	// Without --organization the target is the organization the item is in
	// already, so only its collections change.
	if !orgFlagChanged {
		if currentOrgID == "" {
			return nil, fmt.Errorf("%q is owned by you, not by an organization; pass --organization <name|id> to move it", itemName)
		}
		return &ownershipTarget{orgID: currentOrgID, orgName: orgNameByID(orgs, currentOrgID)}, nil
	}

	if strings.TrimSpace(orgFlag) == "" {
		return nil, fmt.Errorf("--organization needs an organization name or ID; moving an item back to personal ownership is not supported by the Bitwarden API")
	}

	org, err := findOrganization(orgFlag, orgs)
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, fmt.Errorf("organization not found: %s (run 'bx collection list' to see your organizations, or 'bx fetch' if you joined one recently)", orgFlag)
	}

	name := org.Name
	if name == "" {
		name = shortID(org.ID)
	}
	if currentOrgID != "" && currentOrgID != org.ID {
		return nil, fmt.Errorf(
			"%q already belongs to organization %q; the Bitwarden API cannot move an item from one organization to another — recreate it in %q instead",
			itemName, orgNameByID(orgs, currentOrgID), name,
		)
	}

	return &ownershipTarget{orgID: org.ID, orgName: name, move: currentOrgID == ""}, nil
}

// runEditOwnership handles `bx edit --organization/--collection`: it moves a
// personal item to an organization (re-encrypting it with the organization key)
// or changes the collections of an item that already belongs to one.
func runEditOwnership(cmd *cobra.Command, pattern string, v *client.SyncResponse, foundCipher *client.Cipher, effectiveKey, accountKey []byte, orgKeys map[string][]byte) error {
	orgFlag, _ := cmd.Flags().GetString("organization")
	collectionFlags, _ := cmd.Flags().GetStringArray("collection")
	force, _ := cmd.Flags().GetBool("force")

	itemName := pattern
	if nameBytes, err := crypto.Decrypt(cipherName(foundCipher), effectiveKey); err == nil && len(nameBytes) > 0 {
		itemName = string(nameBytes)
	}

	currentOrgID := ""
	if foundCipher.OrganizationID != nil {
		currentOrgID = *foundCipher.OrganizationID
	}

	target, err := resolveOwnershipTarget(itemName, orgFlag, cmd.Flags().Changed("organization"), currentOrgID, v.Profile.Organizations)
	if err != nil {
		return err
	}

	// Resolve the organization key before anything else that needs it: collection
	// names are encrypted with it, so without it collection lookups would fail
	// with a misleading "collection not found".
	orgKey, err := organizationKey(target.orgID, target.orgName, orgKeys)
	if err != nil {
		return err
	}

	if len(collectionFlags) == 0 {
		return fmt.Errorf("--collection is required: an organization item must belong to at least one collection (run 'bx collection list -o %q' to see them)", target.orgName)
	}
	collections, err := findCollections(collectionFlags, v.Collections, target.orgID, orgKeys)
	if err != nil {
		return err
	}
	collectionIDs := make([]string, 0, len(collections))
	collectionLabels := make([]string, 0, len(collections))
	for _, col := range collections {
		collectionIDs = append(collectionIDs, col.ID)
		label := collectionName(col, orgKeys)
		if label == "" {
			label = shortID(col.ID)
		}
		collectionLabels = append(collectionLabels, label)
	}

	// Changing collections within the same organization needs no re-encryption.
	if !target.move {
		if !force {
			if err := checkCipherConflict(pattern, foundCipher); err != nil {
				return err
			}
		}

		var updated json.RawMessage
		if err := withAutoLogin(func() error {
			var err error
			updated, err = apiClient.UpdateCipherCollections(foundCipher.ID, client.CipherCollectionsRequest{
				CollectionIDs: collectionIDs,
			})
			return err
		}); err != nil {
			return fmt.Errorf("failed to update collections: %w", err)
		}

		patchLocalRawCipher(updated, collectionIDs)
		fmt.Printf("Updated collections of %s in %s: %s\n", itemName, target.orgName, strings.Join(collectionLabels, ", "))
		return nil
	}

	// Work from the server's copy: it is authoritative and contains fields the
	// local cache may not have.
	var rawCipher json.RawMessage
	if err := withAutoLogin(func() error {
		var err error
		rawCipher, err = apiClient.GetCipherRaw(foundCipher.ID)
		return err
	}); err != nil {
		return fmt.Errorf("failed to fetch item from server: %w", err)
	}

	if serverRevision := cipherRawString(rawCipher, "revisionDate"); !force && serverRevision != foundCipher.RevisionDate {
		return conflictError(pattern, foundCipher.RevisionDate, serverRevision)
	}

	if attachmentsBlockMove(rawCipher) {
		return fmt.Errorf(
			"%q has attachments and is encrypted with your account key directly; the Bitwarden API cannot re-encrypt their attachment keys when moving to an organization — use the Bitwarden web vault for this item",
			itemName,
		)
	}

	shareCipher, err := buildShareCipher(rawCipher, target.orgID, v.Profile.ID, accountKey, orgKey)
	if err != nil {
		return err
	}

	var updated json.RawMessage
	if err := withAutoLogin(func() error {
		var err error
		updated, err = apiClient.ShareCipher(foundCipher.ID, client.ShareCipherRequest{
			Cipher:        shareCipher,
			CollectionIDs: collectionIDs,
		})
		return err
	}); err != nil {
		return fmt.Errorf("failed to move item to organization %q: %w", target.orgName, err)
	}

	patchLocalRawCipher(updated, collectionIDs)
	fmt.Printf("Moved %s to %s (collections: %s)\n", itemName, target.orgName, strings.Join(collectionLabels, ", "))
	return nil
}

// patchLocalRawCipher writes the server's raw copy of an item to the local cache,
// with collectionIDs applied.  The raw copy is used instead of bx's typed Cipher
// so that fields bx does not model are cached with their new encryption; the
// collection IDs are applied explicitly because GET /api/ciphers/{id} does not
// report collection membership on every server.
func patchLocalRawCipher(raw json.RawMessage, collectionIDs []string) {
	withCollections, err := setRawCollectionIDs(raw, collectionIDs)
	if err != nil {
		warnCacheUpdateFailed(err)
		return
	}
	if err := vault.PatchCipherRaw(withCollections); err != nil {
		warnCacheUpdateFailed(err)
	}
}

// setRawCollectionIDs returns raw with its collectionIds field replaced.
func setRawCollectionIDs(raw json.RawMessage, collectionIDs []string) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("could not parse the server's copy of the item: %w", err)
	}
	ids, err := json.Marshal(collectionIDs)
	if err != nil {
		return nil, err
	}
	obj["collectionIds"] = ids
	return json.Marshal(obj)
}

func warnCacheUpdateFailed(err error) {
	fmt.Fprintf(os.Stderr, "warning: item updated on server but local cache update failed: %v\n", err)
	fmt.Fprintf(os.Stderr, "Run 'bx fetch' to sync the local cache.\n")
}
