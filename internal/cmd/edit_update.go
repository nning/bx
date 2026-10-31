package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
)

// passwordHistoryLimit is the number of previous passwords kept per item,
// matching the official Bitwarden clients.
const passwordHistoryLimit = 5

// Linked custom field targets of login items (Bitwarden's LoginLinkedId).
const (
	linkedIDUsername = 100
	linkedIDPassword = 101
)

// cipherUpdate describes the plaintext changes of an edit.  A nil field is
// left untouched: its value is taken from the server's copy of the item, in
// whatever form the server sent it.
type cipherUpdate struct {
	Name         *string
	Notes        *string
	Username     *string
	Password     *string
	Totp         *string
	URLs         *[]string
	CustomFields *[]cipherCustomField
	// FolderID moves the item into a folder; an empty string removes it from
	// its folder ("none").  nil leaves the folder untouched.
	FolderID *string
	// TypeObj is the JSON object holding the fields of a non-login item type
	// ("card", "identity", or "sshKey"); "" for login items.  TypeFields holds
	// the new plaintext values, keyed by the JSON field name; nil is left
	// untouched and an empty string clears the field.
	TypeObj    string
	TypeFields map[string]*string
}

// isEmpty reports whether the update changes nothing.
func (u cipherUpdate) isEmpty() bool {
	return u.Name == nil && u.Notes == nil && u.Username == nil && u.Password == nil &&
		u.Totp == nil && u.URLs == nil && u.CustomFields == nil && u.FolderID == nil &&
		u.TypeObj == "" && u.TypeFields == nil
}

// buildEditCipher applies u to the server's raw copy of an item and returns the
// body of a PUT /api/ciphers/{id} request.
//
// The server replaces the item's contents with whatever the request contains,
// so the request is built from the complete server copy rather than from bx's
// typed Cipher: passkeys, password history, reprompt, per-URI settings, and any
// field bx does not model are forwarded verbatim.  Only the values in u are
// re-encrypted, and only if they actually differ from the current ones.
//
// A changed password is recorded in the item's password history, as the
// official clients do, so the previous password is never lost.
func buildEditCipher(raw json.RawMessage, u cipherUpdate, userID string, key []byte, now time.Time) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("could not parse server copy of item: %w", err)
	}

	out := cipherRequestFields(obj)
	if org, ok := obj["organizationId"]; ok {
		out["organizationId"] = org
	}
	if revision, ok := obj["revisionDate"]; ok {
		out["lastKnownRevisionDate"] = revision
	}
	if err := setEncryptedFor(out, userID); err != nil {
		return nil, err
	}

	if err := setEncryptedString(out, "name", u.Name, key, false); err != nil {
		return nil, fmt.Errorf("name: %w", err)
	}
	if err := setEncryptedString(out, "notes", u.Notes, key, true); err != nil {
		return nil, fmt.Errorf("notes: %w", err)
	}

	// The folder is a plaintext UUID reference on the item, not an encrypted
	// value: an empty FolderID clears the folder by storing null.
	if u.FolderID != nil {
		if *u.FolderID == "" {
			out["folderId"] = json.RawMessage("null")
		} else {
			b, err := json.Marshal(*u.FolderID)
			if err != nil {
				return nil, err
			}
			out["folderId"] = b
		}
	}

	if u.Username != nil || u.Password != nil || u.Totp != nil || u.URLs != nil {
		var login map[string]json.RawMessage
		if raw, ok := out["login"]; ok {
			if err := json.Unmarshal(raw, &login); err != nil {
				return nil, fmt.Errorf("could not parse login: %w", err)
			}
		}
		if login == nil {
			login = map[string]json.RawMessage{}
		}

		if err := setEncryptedString(login, "username", u.Username, key, true); err != nil {
			return nil, fmt.Errorf("username: %w", err)
		}
		oldPassword := login["password"]
		if err := setEncryptedString(login, "password", u.Password, key, true); err != nil {
			return nil, fmt.Errorf("password: %w", err)
		}
		if string(login["password"]) != string(oldPassword) {
			if err := recordPasswordChange(out, login, oldPassword, now); err != nil {
				return nil, err
			}
		}
		if err := setEncryptedString(login, "totp", u.Totp, key, true); err != nil {
			return nil, fmt.Errorf("totp: %w", err)
		}

		if u.URLs != nil {
			var rawURIs []json.RawMessage
			if err := unmarshalOptionalArray(login["uris"], &rawURIs); err != nil {
				return nil, fmt.Errorf("could not parse URIs: %w", err)
			}
			uris, err := applyURLs(rawURIs, *u.URLs, key)
			if err != nil {
				return nil, err
			}
			if login["uris"], err = json.Marshal(uris); err != nil {
				return nil, err
			}
		}

		b, err := json.Marshal(login)
		if err != nil {
			return nil, err
		}
		out["login"] = b
	}

	// A non-login item type carries its fields in its own object ("card",
	// "identity", "sshKey"): the current object is forwarded verbatim with
	// only the changed fields re-encrypted.
	if u.TypeObj != "" {
		var typeObj map[string]json.RawMessage
		if raw, ok := out[u.TypeObj]; ok {
			if err := json.Unmarshal(raw, &typeObj); err != nil {
				return nil, fmt.Errorf("could not parse %s: %w", u.TypeObj, err)
			}
		}
		if typeObj == nil {
			typeObj = map[string]json.RawMessage{}
		}
		for field, value := range u.TypeFields {
			if err := setEncryptedString(typeObj, field, value, key, true); err != nil {
				return nil, fmt.Errorf("%s: %w", field, err)
			}
		}
		b, err := json.Marshal(typeObj)
		if err != nil {
			return nil, err
		}
		out[u.TypeObj] = b
	}

	if u.CustomFields != nil {
		var rawFields []json.RawMessage
		if err := unmarshalOptionalArray(out["fields"], &rawFields); err != nil {
			return nil, fmt.Errorf("could not parse custom fields: %w", err)
		}
		fields, err := applyCustomFields(rawFields, *u.CustomFields, key)
		if err != nil {
			return nil, err
		}
		if out["fields"], err = json.Marshal(fields); err != nil {
			return nil, err
		}
	}

	return json.Marshal(out)
}

// setEncryptedString replaces obj[field] with the encryption of *value, unless
// value is nil or equal to the current plaintext — then the current ciphertext
// is kept.  With emptyAsNull, an empty value is stored as null, which is how the
// official clients represent an absent username, password, TOTP, or note.
func setEncryptedString(obj map[string]json.RawMessage, field string, value *string, key []byte, emptyAsNull bool) error {
	if value == nil {
		return nil
	}
	current, err := decryptRawString(obj[field], key)
	if err != nil {
		return err
	}
	if _, present := obj[field]; present && current == *value {
		return nil
	}
	if *value == "" && emptyAsNull {
		obj[field] = json.RawMessage("null")
		return nil
	}
	enc, err := encryptField(field, *value, key)
	if err != nil {
		return err
	}
	obj[field], err = json.Marshal(enc)
	return err
}

// decryptRawString decrypts a JSON cipher string; missing and null values
// decrypt to "".
func decryptRawString(raw json.RawMessage, key []byte) (string, error) {
	var s *string
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", err
		}
	}
	if s == nil {
		return "", nil
	}
	b, err := crypto.Decrypt(*s, key)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}
	return string(b), nil
}

// recordPasswordChange prepends the previous password (still encrypted) to the
// item's password history, trims the history to passwordHistoryLimit entries,
// and sets login.passwordRevisionDate.  Setting a first password records
// nothing, as in the official clients.
func recordPasswordChange(out, login map[string]json.RawMessage, oldPassword json.RawMessage, now time.Time) error {
	var old *string
	if len(oldPassword) > 0 {
		if err := json.Unmarshal(oldPassword, &old); err != nil {
			return fmt.Errorf("could not parse previous password: %w", err)
		}
	}
	if old == nil || *old == "" {
		return nil
	}

	date, err := json.Marshal(now.UTC().Format("2006-01-02T15:04:05.000Z"))
	if err != nil {
		return err
	}
	login["passwordRevisionDate"] = date

	var history []json.RawMessage
	if err := unmarshalOptionalArray(out["passwordHistory"], &history); err != nil {
		return fmt.Errorf("could not parse password history: %w", err)
	}
	entry, err := json.Marshal(map[string]json.RawMessage{
		"password":     oldPassword,
		"lastUsedDate": date,
	})
	if err != nil {
		return err
	}
	history = append([]json.RawMessage{entry}, history...)
	if len(history) > passwordHistoryLimit {
		history = history[:passwordHistoryLimit]
	}
	out["passwordHistory"], err = json.Marshal(history)
	return err
}

// unmarshalOptionalArray decodes a JSON array, treating a missing or null
// value as empty.
func unmarshalOptionalArray(raw json.RawMessage, v *[]json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		*v = nil
		return nil
	}
	return json.Unmarshal(raw, v)
}

// applyURLs builds the login URI list for the given URLs.  Each URL is matched
// to the first unused current URI with the same value, which is reused verbatim
// so that its match setting, checksum, and anything else bx does not model are
// kept.  Unmatched URLs become new URIs; current URIs without a match are
// removed.
func applyURLs(rawURIs []json.RawMessage, urls []string, key []byte) ([]json.RawMessage, error) {
	values := make([]string, len(rawURIs))
	for i, raw := range rawURIs {
		var u client.CipherURI
		if err := json.Unmarshal(raw, &u); err != nil {
			return nil, fmt.Errorf("could not parse URI: %w", err)
		}
		b, err := crypto.Decrypt(u.URI, key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt URI: %w", err)
		}
		values[i] = string(b)
	}

	used := make([]bool, len(rawURIs))
	out := make([]json.RawMessage, 0, len(urls))
	for _, url := range urls {
		match := -1
		for i, v := range values {
			if !used[i] && v == url {
				match = i
				break
			}
		}
		if match >= 0 {
			used[match] = true
			out = append(out, rawURIs[match])
			continue
		}

		encURI, err := encryptField("uri", url, key)
		if err != nil {
			return nil, err
		}
		// The checksum lets clients detect a URI that was tampered with; the
		// official clients store the base64 SHA-256 of the URI, encrypted.
		sum := sha256.Sum256([]byte(url))
		encSum, err := crypto.Encrypt([]byte(base64.StdEncoding.EncodeToString(sum[:])), key)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt URL checksum: %w", err)
		}
		b, err := json.Marshal(map[string]any{"uri": encURI, "uriChecksum": encSum, "match": nil})
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// decodeCustomField decrypts a custom field into its editor representation.
// A linked field's value is the name of the login field it points to.
func decodeCustomField(cf client.CipherField, key []byte) (cipherCustomField, error) {
	f := cipherCustomField{Type: cf.Type}
	if cf.Name != nil {
		b, err := crypto.Decrypt(*cf.Name, key)
		if err != nil {
			return f, fmt.Errorf("failed to decrypt custom field name: %w", err)
		}
		f.Name = string(b)
	}
	if cf.Type == client.FieldTypeLinked {
		if cf.LinkedID != nil {
			f.Value = linkedTargetName(*cf.LinkedID)
		}
		return f, nil
	}
	b, err := crypto.Decrypt(cf.Value, key)
	if err != nil {
		return f, fmt.Errorf("failed to decrypt custom field value: %w", err)
	}
	f.Value = string(b)
	return f, nil
}

// linkedTargetName names the login field a linked custom field points to.
func linkedTargetName(id int) string {
	switch id {
	case linkedIDUsername:
		return "username"
	case linkedIDPassword:
		return "password"
	default:
		return strconv.Itoa(id)
	}
}

// parseLinkedTarget is the inverse of linkedTargetName.
func parseLinkedTarget(s string) (int, error) {
	switch strings.ToLower(s) {
	case "username":
		return linkedIDUsername, nil
	case "password":
		return linkedIDPassword, nil
	}
	if id, err := strconv.Atoi(s); err == nil {
		return id, nil
	}
	return 0, fmt.Errorf("unknown linked field target %q; use username or password", s)
}

// applyCustomFields builds the custom field list for the given fields.  Each
// field is matched to the first unused current field of the same name: if its
// type and value are unchanged the current field is reused verbatim, otherwise
// its encrypted name is kept and only the type and value are replaced.
// Unmatched fields are created; current fields without a match are removed.
func applyCustomFields(rawFields []json.RawMessage, fields []cipherCustomField, key []byte) ([]json.RawMessage, error) {
	current := make([]cipherCustomField, len(rawFields))
	for i, raw := range rawFields {
		var cf client.CipherField
		if err := json.Unmarshal(raw, &cf); err != nil {
			return nil, fmt.Errorf("could not parse custom field: %w", err)
		}
		f, err := decodeCustomField(cf, key)
		if err != nil {
			return nil, err
		}
		current[i] = f
	}

	used := make([]bool, len(rawFields))
	out := make([]json.RawMessage, 0, len(fields))
	for _, f := range fields {
		match := -1
		for i, c := range current {
			if !used[i] && c.Name == f.Name {
				match = i
				break
			}
		}

		obj := map[string]json.RawMessage{}
		if match >= 0 {
			used[match] = true
			if current[match] == f {
				out = append(out, rawFields[match])
				continue
			}
			if err := json.Unmarshal(rawFields[match], &obj); err != nil {
				return nil, fmt.Errorf("could not parse custom field: %w", err)
			}
		} else {
			obj["name"] = json.RawMessage("null")
			if f.Name != "" {
				encName, err := encryptField("field name", f.Name, key)
				if err != nil {
					return nil, err
				}
				if obj["name"], err = json.Marshal(encName); err != nil {
					return nil, err
				}
			}
		}

		var err error
		if obj["type"], err = json.Marshal(f.Type); err != nil {
			return nil, err
		}
		obj["value"] = json.RawMessage("null")
		obj["linkedId"] = json.RawMessage("null")
		if f.Type == client.FieldTypeLinked {
			id, err := parseLinkedTarget(f.Value)
			if err != nil {
				return nil, fmt.Errorf("custom field %q: %w", f.Name, err)
			}
			if obj["linkedId"], err = json.Marshal(id); err != nil {
				return nil, err
			}
		} else if f.Value != "" {
			encValue, err := encryptField("field value", f.Value, key)
			if err != nil {
				return nil, err
			}
			if obj["value"], err = json.Marshal(encValue); err != nil {
				return nil, err
			}
		}

		b, err := json.Marshal(obj)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}
