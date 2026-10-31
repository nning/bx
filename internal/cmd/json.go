package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
	"github.com/spf13/cobra"
)

// ---------------------------------------------------------------------------
// JSON output schema
//
// `bx list --json` and `bx get --json` are stable, documented interfaces for
// scripts (see README.md): fields are only ever added, never renamed or
// removed, and absent values are omitted.  Every value is decrypted with the
// item's key, so the output contains secrets in plaintext — scripts must
// handle it with the same care as the terminal output.
// ---------------------------------------------------------------------------

// jsonListEntry is one row of `bx list --json`.
type jsonListEntry struct {
	ID           string  `json:"id"`
	Type         string  `json:"type"`
	Name         string  `json:"name"`
	Username     string  `json:"username,omitempty"`
	HasPasskey   bool    `json:"hasPasskey,omitempty"`
	Favorite     bool    `json:"favorite"`
	Folder       string  `json:"folder,omitempty"`
	Organization string  `json:"organization,omitempty"`
	RevisionDate string  `json:"revisionDate"`
	DeletedDate  *string `json:"deletedDate,omitempty"`
}

// jsonURI is one URI of a login item.
type jsonURI struct {
	URI   string `json:"uri"`
	Match *int   `json:"match"`
}

// jsonField is one custom field.  For linked fields Value names the login
// field the link points to ("username" or "password").
type jsonField struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// jsonPasskey is one FIDO2 (passkey) credential of a login item.
type jsonPasskey struct {
	CredentialID string `json:"credentialId"`
	RPID         string `json:"rpId"`
	RPName       string `json:"rpName,omitempty"`
	Username     string `json:"username,omitempty"`
	Handle       string `json:"handle,omitempty"`
	Created      string `json:"created,omitempty"`
	Counter      string `json:"counter,omitempty"`
	Discoverable bool   `json:"discoverable"`
}

// jsonAttachment is one attachment of an item (metadata only; the file itself
// is downloaded with `bx attachment get`).
type jsonAttachment struct {
	ID       string `json:"id"`
	FileName string `json:"fileName"`
	Size     int64  `json:"size"`
}

// jsonCard is the decrypted card data of a card item.
type jsonCard struct {
	CardholderName string `json:"cardholderName,omitempty"`
	Brand          string `json:"brand,omitempty"`
	Number         string `json:"number,omitempty"`
	ExpMonth       string `json:"expMonth,omitempty"`
	ExpYear        string `json:"expYear,omitempty"`
	Code           string `json:"code,omitempty"`
}

// jsonIdentity is the decrypted identity data of an identity item.
type jsonIdentity struct {
	Title          string `json:"title,omitempty"`
	FirstName      string `json:"firstName,omitempty"`
	MiddleName     string `json:"middleName,omitempty"`
	LastName       string `json:"lastName,omitempty"`
	Address1       string `json:"address1,omitempty"`
	Address2       string `json:"address2,omitempty"`
	Address3       string `json:"address3,omitempty"`
	City           string `json:"city,omitempty"`
	State          string `json:"state,omitempty"`
	PostalCode     string `json:"postalCode,omitempty"`
	Country        string `json:"country,omitempty"`
	Company        string `json:"company,omitempty"`
	Email          string `json:"email,omitempty"`
	Phone          string `json:"phone,omitempty"`
	Username       string `json:"username,omitempty"`
	SSN            string `json:"ssn,omitempty"`
	PassportNumber string `json:"passportNumber,omitempty"`
	LicenseNumber  string `json:"licenseNumber,omitempty"`
}

// jsonSSHKey is the decrypted SSH key data of an SSH key item.
type jsonSSHKey struct {
	PrivateKey  string `json:"privateKey,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// jsonCipher is the record printed by `bx get --json`.
type jsonCipher struct {
	ID           string           `json:"id"`
	Type         string           `json:"type"`
	Name         string           `json:"name"`
	Username     string           `json:"username,omitempty"`
	Password     string           `json:"password,omitempty"`
	TOTP         string           `json:"totp,omitempty"`
	URIs         []jsonURI        `json:"uris,omitempty"`
	Notes        string           `json:"notes,omitempty"`
	Fields       []jsonField      `json:"fields,omitempty"`
	Passkeys     []jsonPasskey    `json:"passkeys,omitempty"`
	Card         *jsonCard        `json:"card,omitempty"`
	Identity     *jsonIdentity    `json:"identity,omitempty"`
	SSHKey       *jsonSSHKey      `json:"sshKey,omitempty"`
	Attachments  []jsonAttachment `json:"attachments,omitempty"`
	Favorite     bool             `json:"favorite"`
	Folder       string           `json:"folder,omitempty"`
	Organization string           `json:"organization,omitempty"`
	Collections  []string         `json:"collections,omitempty"`
	RevisionDate string           `json:"revisionDate"`
	DeletedDate  *string          `json:"deletedDate,omitempty"`
}

// jsonHistoryEntry is one entry of a login item's password history.
type jsonHistoryEntry struct {
	Date     string `json:"date"`
	Password string `json:"password"`
}

// cipherTypeName names a cipher item type the way the JSON output spells it.
// Unknown types are spelled "type-<n>" so that output never lies silently.
func cipherTypeName(t int) string {
	switch t {
	case client.CipherTypeLogin:
		return "login"
	case client.CipherTypeNote:
		return "note"
	case client.CipherTypeCard:
		return "card"
	case client.CipherTypeIdentity:
		return "identity"
	case client.CipherTypeSshKey:
		return "ssh-key"
	default:
		return fmt.Sprintf("type-%d", t)
	}
}

// jsonFieldType names a custom field type the way the JSON output spells it.
func jsonFieldType(t int) string {
	switch t {
	case client.FieldTypeHidden:
		return "hidden"
	case client.FieldTypeBoolean:
		return "boolean"
	case client.FieldTypeLinked:
		return "linked"
	default:
		return "text"
	}
}

// strictDecrypt decrypts s with key and aborts the JSON build on failure: a
// script should fail on a broken item instead of silently working with a
// "[Decryption Error]" placeholder.
func strictDecrypt(s string, key []byte) (string, error) {
	b, err := crypto.Decrypt(s, key)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt value: %w", err)
	}
	return string(b), nil
}

// strictDecryptPtr is strictDecrypt for an optional cipher string.
func strictDecryptPtr(s *string, key []byte) (string, error) {
	if s == nil {
		return "", nil
	}
	return strictDecrypt(*s, key)
}

// folderNamesForJSON maps folder IDs to their decrypted names, falling back to
// the short ID when a name cannot be decrypted.
func folderNamesForJSON(folders []client.Folder, accountKey []byte) map[string]string {
	names := make(map[string]string, len(folders))
	for _, f := range folders {
		name := shortID(f.ID)
		if b, err := crypto.Decrypt(f.Name, accountKey); err == nil && len(b) > 0 {
			name = string(b)
		}
		names[f.ID] = name
	}
	return names
}

// buildJSONCipher decrypts every field of c with itemKey and returns the
// record printed by `bx get --json`.
func buildJSONCipher(c *client.Cipher, itemKey, accountKey []byte, v *client.SyncResponse, orgKeys map[string][]byte, folderNames map[string]string) (*jsonCipher, error) {
	name, err := strictDecrypt(cipherName(c), itemKey)
	if err != nil {
		return nil, fmt.Errorf("name: %w", err)
	}

	j := &jsonCipher{
		ID:           c.ID,
		Type:         cipherTypeName(c.Type),
		Name:         name,
		Favorite:     c.Favorite,
		Organization: orgNameByID(v.Profile.Organizations, orgIDOf(c)),
		Collections:  collectionNames(c.CollectionIDs, v.Collections, orgKeys),
		RevisionDate: c.RevisionDate,
		DeletedDate:  c.DeletedDate,
	}
	if c.FolderID != nil && *c.FolderID != "" {
		j.Folder = folderNames[*c.FolderID]
		if j.Folder == "" {
			j.Folder = shortID(*c.FolderID)
		}
	}

	if notes, err := strictDecryptPtr(cipherNotes(c), itemKey); err != nil {
		return nil, fmt.Errorf("notes: %w", err)
	} else {
		j.Notes = notes
	}

	for _, cf := range cipherCustomFields(c) {
		fieldName, value, err := decryptCustomField(cf, itemKey)
		if err != nil {
			return nil, fmt.Errorf("custom field: %w", err)
		}
		if cf.Type == client.FieldTypeLinked && cf.LinkedID != nil {
			value = linkedTargetName(*cf.LinkedID)
		}
		j.Fields = append(j.Fields, jsonField{Name: fieldName, Type: jsonFieldType(cf.Type), Value: value})
	}

	for _, a := range c.Attachments {
		fileName, err := strictDecrypt(a.FileName, itemKey)
		if err != nil {
			return nil, fmt.Errorf("attachment %s: %w", a.ID, err)
		}
		size, _ := a.Size.Int64()
		j.Attachments = append(j.Attachments, jsonAttachment{ID: a.ID, FileName: fileName, Size: size})
	}

	switch c.Type {
	case client.CipherTypeLogin:
		if j.Username, err = strictDecrypt(cipherUsername(c), itemKey); err != nil {
			return nil, fmt.Errorf("username: %w", err)
		}
		if j.Password, err = strictDecrypt(cipherPassword(c), itemKey); err != nil {
			return nil, fmt.Errorf("password: %w", err)
		}
		if j.TOTP, err = strictDecryptPtr(cipherTotp(c), itemKey); err != nil {
			return nil, fmt.Errorf("totp: %w", err)
		}
		for _, u := range cipherURIs(c) {
			uri, err := strictDecrypt(u.URI, itemKey)
			if err != nil {
				return nil, fmt.Errorf("uri: %w", err)
			}
			j.URIs = append(j.URIs, jsonURI{URI: uri, Match: u.Match})
		}
		for _, cred := range cipherFido2Credentials(c) {
			p, err := buildJSONPasskey(cred, itemKey)
			if err != nil {
				return nil, err
			}
			j.Passkeys = append(j.Passkeys, p)
		}

	case client.CipherTypeCard:
		if c.Card != nil {
			jc := &jsonCard{}
			if jc.CardholderName, err = strictDecrypt(c.Card.CardholderName, itemKey); err != nil {
				return nil, fmt.Errorf("card.cardholderName: %w", err)
			}
			if jc.Brand, err = strictDecrypt(c.Card.Brand, itemKey); err != nil {
				return nil, fmt.Errorf("card.brand: %w", err)
			}
			if jc.Number, err = strictDecrypt(c.Card.Number, itemKey); err != nil {
				return nil, fmt.Errorf("card.number: %w", err)
			}
			if jc.ExpMonth, err = strictDecrypt(c.Card.ExpMonth, itemKey); err != nil {
				return nil, fmt.Errorf("card.expMonth: %w", err)
			}
			if jc.ExpYear, err = strictDecrypt(c.Card.ExpYear, itemKey); err != nil {
				return nil, fmt.Errorf("card.expYear: %w", err)
			}
			if jc.Code, err = strictDecrypt(c.Card.Code, itemKey); err != nil {
				return nil, fmt.Errorf("card.code: %w", err)
			}
			j.Card = jc
		}

	case client.CipherTypeIdentity:
		if c.Identity != nil {
			ji := &jsonIdentity{}
			fields := []struct {
				dst  *string
				src  string
				name string
			}{
				{&ji.Title, c.Identity.Title, "title"},
				{&ji.FirstName, c.Identity.FirstName, "firstName"},
				{&ji.MiddleName, c.Identity.MiddleName, "middleName"},
				{&ji.LastName, c.Identity.LastName, "lastName"},
				{&ji.Address1, c.Identity.Address1, "address1"},
				{&ji.Address2, c.Identity.Address2, "address2"},
				{&ji.Address3, c.Identity.Address3, "address3"},
				{&ji.City, c.Identity.City, "city"},
				{&ji.State, c.Identity.State, "state"},
				{&ji.PostalCode, c.Identity.PostalCode, "postalCode"},
				{&ji.Country, c.Identity.Country, "country"},
				{&ji.Company, c.Identity.Company, "company"},
				{&ji.Email, c.Identity.Email, "email"},
				{&ji.Phone, c.Identity.Phone, "phone"},
				{&ji.Username, c.Identity.Username, "username"},
				{&ji.SSN, c.Identity.SSN, "ssn"},
				{&ji.PassportNumber, c.Identity.PassportNumber, "passportNumber"},
				{&ji.LicenseNumber, c.Identity.LicenseNumber, "licenseNumber"},
			}
			for _, f := range fields {
				if *f.dst, err = strictDecrypt(f.src, itemKey); err != nil {
					return nil, fmt.Errorf("identity.%s: %w", f.name, err)
				}
			}
			j.Identity = ji
		}

	case client.CipherTypeSshKey:
		if c.SshKey != nil {
			js := &jsonSSHKey{}
			if js.PrivateKey, err = strictDecrypt(c.SshKey.PrivateKey, itemKey); err != nil {
				return nil, fmt.Errorf("sshKey.privateKey: %w", err)
			}
			if js.PublicKey, err = strictDecrypt(c.SshKey.PublicKey, itemKey); err != nil {
				return nil, fmt.Errorf("sshKey.publicKey: %w", err)
			}
			if js.Fingerprint, err = strictDecrypt(c.SshKey.KeyFingerprint, itemKey); err != nil {
				return nil, fmt.Errorf("sshKey.keyFingerprint: %w", err)
			}
			j.SSHKey = js
		}
	}

	return j, nil
}

// orgIDOf returns the organization ID of a cipher, or "" for personal items.
func orgIDOf(c *client.Cipher) string {
	if c.OrganizationID == nil {
		return ""
	}
	return *c.OrganizationID
}

// buildJSONPasskey decrypts a single FIDO2 credential for the JSON output.
func buildJSONPasskey(cred client.Fido2Credential, itemKey []byte) (jsonPasskey, error) {
	p := jsonPasskey{Created: cred.CreationDate}
	var err error
	if p.CredentialID, err = strictDecrypt(cred.CredentialId, itemKey); err != nil {
		return p, fmt.Errorf("passkey.credentialId: %w", err)
	}
	if p.RPID, err = strictDecrypt(cred.RpId, itemKey); err != nil {
		return p, fmt.Errorf("passkey.rpId: %w", err)
	}
	if p.RPName, err = strictDecryptPtr(cred.RpName, itemKey); err != nil {
		return p, fmt.Errorf("passkey.rpName: %w", err)
	}
	if p.Username, err = strictDecryptPtr(cred.UserName, itemKey); err != nil {
		return p, fmt.Errorf("passkey.userName: %w", err)
	}
	if p.Handle, err = strictDecryptPtr(cred.UserHandle, itemKey); err != nil {
		return p, fmt.Errorf("passkey.userHandle: %w", err)
	}
	if p.Counter, err = strictDecrypt(cred.Counter, itemKey); err != nil {
		return p, fmt.Errorf("passkey.counter: %w", err)
	}
	if disc, err := strictDecrypt(cred.Discoverable, itemKey); err == nil {
		p.Discoverable = strings.EqualFold(disc, "true")
	}
	return p, nil
}

// printJSON marshals v as indented JSON and prints it to stdout.
func printJSON(v any) {
	enc, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		cobra.CheckErr(err)
	}
	fmt.Println(string(enc))
}

// buildHistoryJSON decrypts an item's password history for the JSON output.
// It aborts when the item has no history, so that scripts can tell "no
// history" from "empty output".
func buildHistoryJSON(c *client.Cipher, itemKey []byte) ([]jsonHistoryEntry, error) {
	if len(c.PasswordHistory) == 0 {
		return nil, fmt.Errorf("item has no password history")
	}
	entries := make([]jsonHistoryEntry, 0, len(c.PasswordHistory))
	for _, e := range c.PasswordHistory {
		pw, err := strictDecrypt(e.Password, itemKey)
		if err != nil {
			return nil, fmt.Errorf("password history: %w", err)
		}
		entries = append(entries, jsonHistoryEntry{Date: e.LastUsedDate, Password: pw})
	}
	return entries, nil
}
