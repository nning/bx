package cmd

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
	"github.com/nning/bx/internal/vault"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// shortID returns the first segment of a UUID (the part before the first "-"),
// which is used as a shorter, more readable representation of an item ID.
// For example, "550e8400-e29b-41d4-a716-446655440000" → "550e8400".
// If the string contains no "-", the full string is returned unchanged.
func shortID(id string) string {
	if i := strings.IndexByte(id, '-'); i >= 0 {
		return id[:i]
	}
	return id
}

// cipherName returns the effective encrypted name for a cipher.
// The top-level Name (Bitwarden/Vaultwarden API field) takes priority over
// Data.Name (legacy/legacy-cache format).
func cipherName(c *client.Cipher) string {
	if c.Name != "" {
		return c.Name
	}
	return c.Data.Name
}

// cipherNotes returns the effective encrypted notes for a cipher.
// The top-level Notes (Bitwarden/Vaultwarden API field) takes priority over
// Data.Notes (legacy/legacy-cache format).
func cipherNotes(c *client.Cipher) *string {
	if c.Notes != nil && *c.Notes != "" {
		return c.Notes
	}
	return c.Data.Notes
}

// cipherURIs returns the effective URI list for a cipher.
// Login.URIs (Vaultwarden primary field) takes priority over Data.URIs.
func cipherURIs(c *client.Cipher) []client.CipherURI {
	if c.Login != nil && len(c.Login.URIs) > 0 {
		return c.Login.URIs
	}
	return c.Data.URIs
}

// cipherUsername returns the effective username for a cipher.
// Login.Username (Vaultwarden primary field) takes priority over Data.Username.
func cipherUsername(c *client.Cipher) string {
	if c.Login != nil && c.Login.Username != "" {
		return c.Login.Username
	}
	return c.Data.Username
}

// cipherPassword returns the effective password for a cipher.
// Login.Password (Vaultwarden primary field) takes priority over Data.Password.
func cipherPassword(c *client.Cipher) string {
	if c.Login != nil && c.Login.Password != "" {
		return c.Login.Password
	}
	return c.Data.Password
}

// cipherTotp returns the effective TOTP field for a cipher.
// Login.Totp (Vaultwarden primary field) takes priority over Data.Totp.
func cipherTotp(c *client.Cipher) *string {
	if c.Login != nil && c.Login.Totp != nil && *c.Login.Totp != "" {
		return c.Login.Totp
	}
	return c.Data.Totp
}

// cipherFido2Credentials returns the effective FIDO2 (passkey) credentials
// for a cipher. Login.Fido2Credentials (Vaultwarden primary field) takes
// priority over Data.Fido2Credentials.  Returns nil when the cipher has no
// passkeys attached.
func cipherFido2Credentials(c *client.Cipher) []client.Fido2Credential {
	if c.Login != nil && len(c.Login.Fido2Credentials) > 0 {
		return c.Login.Fido2Credentials
	}
	return c.Data.Fido2Credentials
}

// renderPasskeyBlock produces the human-readable display lines for a single
// decrypted-at-runtime FIDO2 credential. It writes one "Passkey: <rpId>"
// header followed by indented detail lines (User, Handle, Created, Counter,
// Discoverable).  Fields that fail to decrypt are skipped (matching the
// existing behaviour for URIs and custom fields in get.go); the only hard
// error is rpId, which short-circuits the whole credential.
//
// The output is returned as a single string with trailing newlines on every
// line, ready to be written to stdout.  Callers write it directly instead of
// going through fmt.Printf so the block can be unit-tested without capturing
// os.Stdout.
func renderPasskeyBlock(cred client.Fido2Credential, key []byte) string {
	var b strings.Builder
	rpIdBytes, err := crypto.Decrypt(cred.RpId, key)
	if err != nil {
		return ""
	}
	fmt.Fprintf(&b, "Passkey:  %s\n", string(rpIdBytes))

	if cred.UserName != nil && *cred.UserName != "" {
		userNameBytes, err := crypto.Decrypt(*cred.UserName, key)
		if err == nil && len(userNameBytes) > 0 {
			line := string(userNameBytes)
			if cred.UserDisplayName != nil && *cred.UserDisplayName != "" {
				if dnBytes, err := crypto.Decrypt(*cred.UserDisplayName, key); err == nil && len(dnBytes) > 0 {
					line = fmt.Sprintf("%s (%s)", line, string(dnBytes))
				}
			}
			fmt.Fprintf(&b, "  User:    %s\n", line)
		}
	}
	if cred.UserHandle != nil && *cred.UserHandle != "" {
		if handleBytes, err := crypto.Decrypt(*cred.UserHandle, key); err == nil && len(handleBytes) > 0 {
			fmt.Fprintf(&b, "  Handle:  %s\n", string(handleBytes))
		}
	}
	if cred.CreationDate != "" {
		fmt.Fprintf(&b, "  Created: %s\n", cred.CreationDate)
	}
	if counterBytes, err := crypto.Decrypt(cred.Counter, key); err == nil {
		fmt.Fprintf(&b, "  Counter: %s\n", string(counterBytes))
	}
	if cred.Discoverable != "" {
		if discBytes, err := crypto.Decrypt(cred.Discoverable, key); err == nil {
			flag := "no"
			if strings.EqualFold(string(discBytes), "true") {
				flag = "yes"
			}
			fmt.Fprintf(&b, "  Discoverable: %s\n", flag)
		}
	}
	return b.String()
}

// ownerLine renders the organization an item belongs to, followed by its
// collections in parentheses, e.g. `Family (Wife, Kid 1)`.  It returns "" for
// items the account owns itself, so personal items print no Owner line at all.
func ownerLine(c *client.Cipher, v *client.SyncResponse, orgKeys map[string][]byte) string {
	if c.OrganizationID == nil || *c.OrganizationID == "" {
		return ""
	}
	owner := orgNameByID(v.Profile.Organizations, *c.OrganizationID)
	if names := collectionNames(c.CollectionIDs, v.Collections, orgKeys); len(names) > 0 {
		return fmt.Sprintf("%s (%s)", owner, strings.Join(names, ", "))
	}
	return owner
}

// cipherCustomFields returns the effective custom fields for a cipher.
// Cipher-level "fields" (Vaultwarden) takes priority over Data.CustomFields
// (Bitwarden).  Both sources are concatenated so that no fields are lost.
func cipherCustomFields(c *client.Cipher) []client.CipherField {
	var fields []client.CipherField
	fields = append(fields, c.Fields...)
	fields = append(fields, c.Data.CustomFields...)
	return fields
}

// decryptCustomField decrypts the name and value of a single custom field.
// If the name is nil or empty, fieldName is left empty.
func decryptCustomField(cf client.CipherField, key []byte) (fieldName, value string, err error) {
	valBytes, err := crypto.Decrypt(cf.Value, key)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt custom field value: %w", err)
	}
	if cf.Name != nil && *cf.Name != "" {
		nameBytes, err := crypto.Decrypt(*cf.Name, key)
		if err != nil {
			return "", "", fmt.Errorf("failed to decrypt custom field name: %w", err)
		}
		fieldName = string(nameBytes)
	}
	return fieldName, string(valBytes), nil
}

// findCustomField decrypts all custom fields of c and returns the decrypted
// value of the field whose name matches pattern (case-insensitive).  Exact
// name matches take priority over substring matches; fields with an empty
// (un-named) or un-decryptable name are skipped.  When multiple fields match
// by substring and none is exact, an error listing the candidate names is
// returned so the user can disambiguate.
func findCustomField(c *client.Cipher, key []byte, pattern string) (string, error) {
	fields := cipherCustomFields(c)
	if len(fields) == 0 {
		return "", fmt.Errorf("item has no custom fields")
	}

	patternLower := strings.ToLower(pattern)

	type candidate struct {
		name  string
		value string
	}
	var substrMatches []candidate
	var available []string

	for _, cf := range fields {
		fieldName, val, err := decryptCustomField(cf, key)
		if err != nil || fieldName == "" {
			continue
		}
		available = append(available, fieldName)

		nameLower := strings.ToLower(fieldName)
		if nameLower == patternLower {
			return val, nil
		}
		if substrMatches == nil && strings.Contains(nameLower, patternLower) {
			substrMatches = []candidate{{name: fieldName, value: val}}
		} else if len(substrMatches) > 0 && strings.Contains(nameLower, patternLower) {
			substrMatches = append(substrMatches, candidate{name: fieldName, value: val})
		}
	}

	if len(substrMatches) == 1 {
		return substrMatches[0].value, nil
	}
	if len(substrMatches) > 1 {
		names := make([]string, len(substrMatches))
		for i, m := range substrMatches {
			names[i] = m.name
		}
		return "", fmt.Errorf("multiple custom fields match %q: %s", pattern, strings.Join(names, ", "))
	}

	if len(available) == 0 {
		return "", fmt.Errorf("no decryptable custom field matches %q (item has only unnamed fields)", pattern)
	}
	return "", fmt.Errorf("item has no custom field matching %q; available: %s", pattern, strings.Join(available, ", "))
}

// totpSecretFromString extracts the raw TOTP seed from a stored value.
// If value is an otpauth:// URL the "secret" query parameter is returned.
// Otherwise the value itself is returned unchanged.
func totpSecretFromString(value string) (string, error) {
	if !strings.HasPrefix(value, "otpauth://") {
		return value, nil
	}
	u, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("invalid otpauth URI: %w", err)
	}
	secret := u.Query().Get("secret")
	if secret == "" {
		return "", fmt.Errorf("otpauth URI missing secret parameter")
	}
	return secret, nil
}

// cipherEntry pairs a cipher with its pre-decrypted name and resolved key.
// It is used by findCipher/findDeletedCipher to avoid redundant decryption
// across multiple search passes.
type cipherEntry struct {
	cipher client.Cipher
	name   string
	key    []byte
}

// buildCipherEntries pre-computes the decrypted name and resolved cipher key
// for every cipher matching the include predicate.  This one-time decryption
// replaces up to 4 redundant Decrypt calls per cipher in the original
// multi-pass search, and the cached cipher key avoids recomputing HKDF
// expansions on every pass.
func buildCipherEntries(ciphers []client.Cipher, resolver *cipherKeyResolver, include func(c client.Cipher) bool) []cipherEntry {
	entries := make([]cipherEntry, 0, len(ciphers))
	for _, cipher := range ciphers {
		if !include(cipher) {
			continue
		}
		key := resolver.key(cipher)
		nameBytes, _ := crypto.Decrypt(cipherName(&cipher), key)
		entries = append(entries, cipherEntry{
			cipher: cipher,
			name:   string(nameBytes),
			key:    key,
		})
	}
	return entries
}

// findCipher searches for the best matching cipher by ID, then name, then
// username, then URL.
// ID matching accepts the full UUID or the short form (first UUID segment).
// Short-ID matches are rejected when ambiguous (multiple ciphers share the same
// first segment); an error is returned so callers can prompt the user to supply
// the full UUID. For name and username matching, non-org exact matches take
// priority, followed by shorter substring matches. URL matching is used as a
// final fallback; URIs are decrypted and checked for a case-insensitive
// substring match.
func findCipher(pattern string, ciphers []client.Cipher, accountKey []byte, orgKeys map[string][]byte) (*client.Cipher, error) {
	isOrg := func(c client.Cipher) bool {
		return c.OrganizationID != nil && *c.OrganizationID != ""
	}

	resolver := newCipherKeyResolver(accountKey, orgKeys)
	isActive := func(c client.Cipher) bool { return c.DeletedDate == nil }
	entries := buildCipherEntries(ciphers, resolver, isActive)

	// Exact ID pass: full UUID is always unambiguous.
	for _, e := range entries {
		if e.cipher.ID == pattern {
			c := e.cipher
			return &c, nil
		}
	}

	// Short-ID pass: collect all matches before deciding.
	var shortMatches []client.Cipher
	for _, e := range entries {
		if shortID(e.cipher.ID) == pattern {
			shortMatches = append(shortMatches, e.cipher)
		}
	}
	if len(shortMatches) == 1 {
		c := shortMatches[0]
		return &c, nil
	}
	if len(shortMatches) > 1 {
		return nil, fmt.Errorf("ambiguous short ID %q: use the full UUID to disambiguate", pattern)
	}

	var foundCipher *client.Cipher
	foundExact := false
	bestLen := -1

	// Name pass — names are already decrypted in entries.
	for _, e := range entries {
		matched, isExact := matchByName(e.name, pattern)
		if !matched {
			continue
		}
		cipher := e.cipher

		// Exact name match: prefer non-org, accept org only if nothing better found.
		if isExact {
			if !isOrg(cipher) {
				c := cipher
				return &c, nil
			}
			// Org exact match: keep as candidate unless we already have an exact match.
			if !foundExact {
				c := cipher
				foundCipher = &c
				foundExact = true
				bestLen = len(e.name)
			}
			continue
		}

		// Substring match: never replace an exact match.
		if foundExact {
			continue
		}

		// Non-org beats org; within same org-status, shorter name wins.
		if foundCipher == nil {
			c := cipher
			foundCipher = &c
			bestLen = len(e.name)
		} else if isOrg(*foundCipher) && !isOrg(cipher) {
			// Upgrade from org to non-org match.
			c := cipher
			foundCipher = &c
			bestLen = len(e.name)
		} else if isOrg(*foundCipher) == isOrg(cipher) && len(e.name) < bestLen {
			// Same org-status: prefer shorter name.
			c := cipher
			foundCipher = &c
			bestLen = len(e.name)
		}
	}

	if foundCipher != nil {
		return foundCipher, nil
	}

	// Username pass: fallback when no name/ID match.
	// Names are already cached in entries; only usernames need decryption.
	for _, e := range entries {
		cipher := e.cipher
		usernameBytes, err := crypto.Decrypt(cipherUsername(&cipher), e.key)
		if err != nil || len(usernameBytes) == 0 {
			continue
		}
		username := string(usernameBytes)

		matched, isExact := matchByName(username, pattern)
		if !matched {
			continue
		}

		name := e.name

		if isExact {
			if !isOrg(cipher) {
				c := cipher
				return &c, nil
			}
			if !foundExact {
				c := cipher
				foundCipher = &c
				foundExact = true
				bestLen = len(name)
			}
			continue
		}

		if foundExact {
			continue
		}

		if foundCipher == nil {
			c := cipher
			foundCipher = &c
			bestLen = len(name)
		} else if isOrg(*foundCipher) && !isOrg(cipher) {
			c := cipher
			foundCipher = &c
			bestLen = len(name)
		} else if isOrg(*foundCipher) == isOrg(cipher) && len(name) < bestLen {
			c := cipher
			foundCipher = &c
			bestLen = len(name)
		}
	}

	if foundCipher != nil {
		return foundCipher, nil
	}

	// Login@domain pass: pattern of the form "user@domain" is split and
	// matched against username (user part) AND URI (domain part) together.
	if atIdx := strings.LastIndexByte(pattern, '@'); atIdx > 0 && atIdx < len(pattern)-1 {
		userPart := pattern[:atIdx]
		domainPart := pattern[atIdx+1:]

		for _, e := range entries {
			cipher := e.cipher
			usernameBytes, err := crypto.Decrypt(cipherUsername(&cipher), e.key)
			if err != nil || len(usernameBytes) == 0 {
				continue
			}
			userMatched, _ := matchByName(string(usernameBytes), userPart)
			if !userMatched {
				continue
			}

			var decryptedURIs []string
			for _, u := range cipherURIs(&cipher) {
				uriBytes, err := crypto.Decrypt(u.URI, e.key)
				if err == nil && len(uriBytes) > 0 {
					decryptedURIs = append(decryptedURIs, string(uriBytes))
				}
			}
			if !matchByURL(decryptedURIs, domainPart) {
				continue
			}

			name := e.name
			if foundCipher == nil {
				c := cipher
				foundCipher = &c
				bestLen = len(name)
			} else if isOrg(*foundCipher) && !isOrg(cipher) {
				c := cipher
				foundCipher = &c
				bestLen = len(name)
			} else if isOrg(*foundCipher) == isOrg(cipher) && len(name) < bestLen {
				c := cipher
				foundCipher = &c
				bestLen = len(name)
			}
		}

		if foundCipher != nil {
			return foundCipher, nil
		}
	}

	// URL pass: fallback when no name/ID/username match.
	// Names are already cached in entries; only URIs need decryption.
	bestLen = -1
	for _, e := range entries {
		cipher := e.cipher

		var decryptedURIs []string
		for _, u := range cipherURIs(&cipher) {
			uriBytes, err := crypto.Decrypt(u.URI, e.key)
			if err == nil && len(uriBytes) > 0 {
				decryptedURIs = append(decryptedURIs, string(uriBytes))
			}
		}

		if !matchByURL(decryptedURIs, pattern) {
			continue
		}

		name := e.name
		if foundCipher == nil {
			c := cipher
			foundCipher = &c
			bestLen = len(name)
		} else if isOrg(*foundCipher) && !isOrg(cipher) {
			c := cipher
			foundCipher = &c
			bestLen = len(name)
		} else if isOrg(*foundCipher) == isOrg(cipher) && len(name) < bestLen {
			c := cipher
			foundCipher = &c
			bestLen = len(name)
		}
	}

	return foundCipher, nil
}

func runGet(cmd *cobra.Command, args []string) {
	pattern := args[0]

	v, accountKey, orgKeys, passwordPrompted, err := vault.LoadVaultWithSession(unlockTimeoutMinutes(), readPassword)
	if err != nil {
		cobra.CheckErr(err)
	}

	foundCipher, err := findCipher(pattern, v.Ciphers, accountKey, orgKeys)
	if err != nil {
		cobra.CheckErr(err)
		return
	}
	if foundCipher == nil {
		cobra.CheckErr(fmt.Errorf("item not found: %s", pattern))
		return
	}

	itemKey := cipherKey(*foundCipher, accountKey, orgKeys)

	// JSON output (--json) is a scripting interface; it is mutually exclusive
	// with the interactive output options, which all shape the output around
	// a human in front of the terminal.
	jsonOut, _ := cmd.Flags().GetBool("json")
	getHistory, _ := cmd.Flags().GetBool("history")
	if jsonOut {
		for _, f := range []string{"copy", "totp", "field", "password-only", "print"} {
			if cmd.Flags().Changed(f) {
				cobra.CheckErr(fmt.Errorf("--json cannot be combined with --%s", f))
				return
			}
		}
		if getHistory {
			entries, err := buildHistoryJSON(foundCipher, itemKey)
			if err != nil {
				cobra.CheckErr(err)
				return
			}
			printJSON(entries)
			return
		}
		record, err := buildJSONCipher(foundCipher, itemKey, accountKey, v, orgKeys, folderNamesForJSON(v.Folders, accountKey))
		if err != nil {
			cobra.CheckErr(err)
			return
		}
		printJSON(record)
		return
	}

	// Handle TOTP
	getTotp, _ := cmd.Flags().GetBool("totp")
	if getTotp {
		totpField := cipherTotp(foundCipher)
		if totpField == nil || *totpField == "" {
			cobra.CheckErr(fmt.Errorf("item has no TOTP: %s", pattern))
			return
		}
		totpBytes, err := crypto.Decrypt(*totpField, itemKey)
		if err != nil {
			cobra.CheckErr(err)
			return
		}
		secret, err := totpSecretFromString(string(totpBytes))
		if err != nil {
			cobra.CheckErr(err)
			return
		}
		if secret == "" {
			cobra.CheckErr(fmt.Errorf("TOTP secret is empty"))
			return
		}

		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			cobra.CheckErr(err)
			return
		}
		if err := copySecret("TOTP code", code, false); err != nil {
			cobra.CheckErr(err)
		}
		return
	}

	fieldKey, _ := cmd.Flags().GetString("field")
	copyToClipboard, _ := cmd.Flags().GetBool("copy")
	passwordOnly, _ := cmd.Flags().GetBool("password-only")

	// Flag combinations that shape the output in incompatible ways are
	// rejected up front rather than silently preferring one of them.
	if passwordOnly && (getTotp || fieldKey != "" || getHistory) {
		cobra.CheckErr(fmt.Errorf("--password-only cannot be combined with --totp, --field or --history"))
		return
	}
	if passwordOnly && cmd.Flags().Changed("print") {
		cobra.CheckErr(fmt.Errorf("--password-only cannot be combined with --print"))
		return
	}

	// Handle custom field selection (--field/-k).  When set, only the matched
	// field's value is emitted: to the clipboard with --copy, or to stdout
	// with --print.  If neither flag is given and stdout is a terminal we
	// default to copying; when piped we default to printing just the value.
	if fieldKey != "" {
		value, err := findCustomField(foundCipher, itemKey, fieldKey)
		if err != nil {
			cobra.CheckErr(err)
			return
		}
		printRecord, _ := cmd.Flags().GetBool("print")
		switch {
		case copyToClipboard:
			if err := copySecret(humanFieldName(foundCipher, itemKey, fieldKey), value, true); err != nil {
				cobra.CheckErr(err)
			}
		case printRecord:
			if passwordPrompted {
				fmt.Fprintln(os.Stderr)
			}
			fmt.Print(value)
		default:
			// Neither --copy nor --print was given.  Default to printing when
			// stdout is piped (scripting use) and copying otherwise.
			if term.IsTerminal(int(os.Stdout.Fd())) {
				if err := copySecret(humanFieldName(foundCipher, itemKey, fieldKey), value, true); err != nil {
					cobra.CheckErr(err)
				}
			} else {
				if passwordPrompted {
					fmt.Fprintln(os.Stderr)
				}
				fmt.Print(value)
			}
		}
		return
	}

	// Handle password history (--history): print the item's previous
	// passwords, newest first, decrypted with the item key.
	if getHistory {
		out, err := renderHistory(foundCipher, itemKey, pattern)
		if err != nil {
			cobra.CheckErr(err)
			return
		}
		fmt.Print(out)
		return
	}

	passwordBytes, err := crypto.Decrypt(cipherPassword(foundCipher), itemKey)
	if err != nil {
		cobra.CheckErr(err)
	}

	pw := string(passwordBytes)

	// Password-only output (--password-only/-P): print just the password, or
	// copy it with --copy, without the rest of the record.
	if passwordOnly {
		value, err := passwordOnlyValue(foundCipher, pw, pattern)
		if err != nil {
			cobra.CheckErr(err)
			return
		}
		if copyToClipboard {
			if err := copySecret("Password", value, true); err != nil {
				cobra.CheckErr(err)
			}
			return
		}
		if passwordPrompted {
			fmt.Fprintln(os.Stderr)
		}
		fmt.Println(value)
		return
	}

	printRecord, _ := cmd.Flags().GetBool("print")

	// Auto-enable print mode when stdout is not a terminal (piped output)
	if !printRecord && !copyToClipboard && !term.IsTerminal(int(os.Stdout.Fd())) {
		printRecord = true
	}

	if printRecord {
		if passwordPrompted {
			fmt.Fprintln(os.Stderr)
		}
		fmt.Print(renderRecord(foundCipher, itemKey, v, orgKeys, pattern))
	} else if copyToClipboard {
		if err := copySecret("Password", pw, true); err != nil {
			cobra.CheckErr(err)
		}
	} else {
		cobra.CheckErr(fmt.Errorf("use --copy/-c flag to copy password to clipboard, or --print/-p flag to print the record to terminal"))
	}
}

// renderRecord returns the full human-readable record for c (the
// `bx get -p` output) as a single string.  Login items print their login
// data, TOTP and passkeys; notes, cards, identities and SSH keys print their
// own fields.  Fields that fail to decrypt are skipped, as elsewhere in
// `bx get`; the only hard error is an undecryptable custom field.
func renderRecord(c *client.Cipher, itemKey []byte, v *client.SyncResponse, orgKeys map[string][]byte, pattern string) string {
	var b strings.Builder

	name := pattern
	if nameBytes, err := crypto.Decrypt(cipherName(c), itemKey); err == nil && len(nameBytes) > 0 {
		name = string(nameBytes)
	}
	fmt.Fprintf(&b, "Name:     %s\n", name)
	if owner := ownerLine(c, v, orgKeys); owner != "" {
		fmt.Fprintf(&b, "Owner:    %s\n", owner)
	}

	// dec decrypts an encrypted value and returns "" on failure; empty values
	// are skipped by line(), so a broken value hides its line like an unset one.
	dec := func(s string) string {
		val, err := crypto.Decrypt(s, itemKey)
		if err != nil || len(val) == 0 {
			return ""
		}
		return string(val)
	}
	line := func(label, value string) {
		if value == "" {
			return
		}
		fmt.Fprintf(&b, "%-9s %s\n", label+":", value)
	}

	switch c.Type {
	case client.CipherTypeLogin:
		line("Username", dec(cipherUsername(c)))
		fmt.Fprintf(&b, "Password: %s\n", dec(cipherPassword(c)))
		for i, u := range cipherURIs(c) {
			if uri := dec(u.URI); uri != "" {
				if i == 0 {
					fmt.Fprintf(&b, "URL:      %s\n", uri)
				} else {
					fmt.Fprintf(&b, "URL %d:    %s\n", i+1, uri)
				}
			}
		}

	case client.CipherTypeCard:
		if c.Card != nil {
			line("Cardholder", dec(c.Card.CardholderName))
			line("Brand", dec(c.Card.Brand))
			line("Number", dec(c.Card.Number))
			month, year := dec(c.Card.ExpMonth), dec(c.Card.ExpYear)
			if month != "" && year != "" {
				line("Expiry", month+"/"+year)
			} else {
				line("Expiry month", month)
				line("Expiry year", year)
			}
			line("Code", dec(c.Card.Code))
		}

	case client.CipherTypeIdentity:
		if c.Identity != nil {
			id := c.Identity
			line("Title", dec(id.Title))
			line("First name", dec(id.FirstName))
			line("Middle name", dec(id.MiddleName))
			line("Last name", dec(id.LastName))
			line("Company", dec(id.Company))
			line("Email", dec(id.Email))
			line("Phone", dec(id.Phone))
			line("Username", dec(id.Username))
			line("Address 1", dec(id.Address1))
			line("Address 2", dec(id.Address2))
			line("Address 3", dec(id.Address3))
			line("City", dec(id.City))
			line("State", dec(id.State))
			line("Postal code", dec(id.PostalCode))
			line("Country", dec(id.Country))
			line("SSN", dec(id.SSN))
			line("Passport", dec(id.PassportNumber))
			line("License", dec(id.LicenseNumber))
		}

	case client.CipherTypeSshKey:
		if c.SshKey != nil {
			line("Fingerprint", dec(c.SshKey.KeyFingerprint))
			line("Public key", dec(c.SshKey.PublicKey))
			line("Private key", dec(c.SshKey.PrivateKey))
		}
	}

	// Decrypt and print notes if present
	if notes := cipherNotes(c); notes != nil && *notes != "" {
		if n := dec(*notes); n != "" {
			fmt.Fprintf(&b, "Notes:    %s\n", n)
		}
	}

	// Decrypt and print custom fields if present
	for _, cf := range cipherCustomFields(c) {
		if cf.Value == "" {
			continue
		}
		fieldName, val, err := decryptCustomField(cf, itemKey)
		if err != nil {
			cobra.CheckErr(err)
			return ""
		}
		if fieldName == "" {
			fieldName = "CustomField"
		}
		fmt.Fprintf(&b, "%-9s %s\n", fieldName+":", val)
	}

	// Generate and print TOTP if present (login items only)
	if c.Type == client.CipherTypeLogin {
		if totpField := cipherTotp(c); totpField != nil && *totpField != "" {
			totpBytes, err := crypto.Decrypt(*totpField, itemKey)
			if err == nil {
				if totpSecret, err := totpSecretFromString(string(totpBytes)); err == nil && totpSecret != "" {
					if code, err := totp.GenerateCode(totpSecret, time.Now()); err == nil {
						fmt.Fprintf(&b, "TOTP:     %s\n", code)
					}
				}
			}
		}
	}

	// Decrypt and print passkeys (FIDO2 credentials) if present.
	if c.Type == client.CipherTypeLogin {
		if creds := cipherFido2Credentials(c); len(creds) > 0 {
			for _, cred := range creds {
				block := renderPasskeyBlock(cred, itemKey)
				if block == "" {
					fmt.Fprintf(os.Stderr, "warning: failed to decrypt passkey rpId, skipping\n")
					continue
				}
				b.WriteString(block)
			}
		}
	}

	return b.String()
}

// renderHistory renders an item's password history: one line per entry,
// newest first, with the date and the decrypted password.  It aborts when the
// item has no history, so a missing history is never mistaken for an empty one.
func renderHistory(c *client.Cipher, itemKey []byte, pattern string) (string, error) {
	if len(c.PasswordHistory) == 0 {
		return "", fmt.Errorf("item has no password history")
	}
	name := pattern
	if nameBytes, err := crypto.Decrypt(cipherName(c), itemKey); err == nil && len(nameBytes) > 0 {
		name = string(nameBytes)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Password history for %s:\n", name)
	for _, e := range c.PasswordHistory {
		pw, err := crypto.Decrypt(e.Password, itemKey)
		if err != nil {
			fmt.Fprintf(&b, "%s  [Decryption Error]\n", e.LastUsedDate)
			continue
		}
		fmt.Fprintf(&b, "%s  %s\n", e.LastUsedDate, string(pw))
	}
	return b.String(), nil
}

// passwordOnlyValue returns the plaintext printed for --password-only.  It
// rejects items that cannot carry a password instead of printing an empty
// line that would look like a password to a script.
func passwordOnlyValue(c *client.Cipher, pw, pattern string) (string, error) {
	if c.Type != client.CipherTypeLogin {
		return "", fmt.Errorf("item has no password: this is a %s item", cipherTypeName(c.Type))
	}
	if pw == "" {
		return "", fmt.Errorf("item has no password: %s", pattern)
	}
	return pw, nil
}

// humanFieldName returns a display label for the custom field matched by
// pattern, e.g. "Custom field \"IBAN\"".  It re-scans the cipher's fields so
// the user sees the actual (case-preserving) name in messages.
func humanFieldName(c *client.Cipher, key []byte, pattern string) string {
	patternLower := strings.ToLower(pattern)
	for _, cf := range cipherCustomFields(c) {
		fieldName, _, err := decryptCustomField(cf, key)
		if err != nil || fieldName == "" {
			continue
		}
		if strings.ToLower(fieldName) == patternLower {
			return fmt.Sprintf("field %q", fieldName)
		}
	}
	for _, cf := range cipherCustomFields(c) {
		fieldName, _, err := decryptCustomField(cf, key)
		if err != nil || fieldName == "" {
			continue
		}
		if strings.Contains(strings.ToLower(fieldName), patternLower) {
			return fmt.Sprintf("field %q", fieldName)
		}
	}
	return "custom field"
}

func addGetFlags(cmd *cobra.Command) {
	cmd.Flags().BoolP("copy", "c", false, "Copy password to clipboard")
	cmd.Flags().BoolP("totp", "t", false, "Generate TOTP code")
	cmd.Flags().BoolP("print", "p", false, "Print record to terminal (includes all information)")
	cmd.Flags().StringP("field", "k", "", `Copy or print the value of a custom field by name (case-insensitive; exact match preferred, substring otherwise). Use with -c to copy, or -p to print only the value. Without -c/-p on a TTY it defaults to copying; when piped it prints just the value.`)
	cmd.Flags().Bool("json", false, "Print the record as JSON (stable schema; see README)")
	cmd.Flags().Bool("history", false, "Print the item's previous passwords, newest first (with --json: as a JSON array)")
	cmd.Flags().BoolP("password-only", "P", false, "Print just the password, not the full record (with -c: copy just the password)")
}

var getCmd = &cobra.Command{
	Use:     "get <id|name|username|url>",
	Aliases: []string{"show"},
	Short:   "Get or print vault item details (alias: show)",
	Args:    cobra.ExactArgs(1),
	Run:     runGet,
}

func init() {
	addGetFlags(getCmd)
	rootCmd.AddCommand(getCmd)
}
