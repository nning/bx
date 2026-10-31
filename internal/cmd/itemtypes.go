package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// ---------------------------------------------------------------------------
// Non-login item types
//
// Cards, identities and SSH keys carry their fields in a type-specific JSON
// object ("card", "identity", "sshKey").  typeSpecs describes those fields in
// one place; it drives the CLI flags, the editor template, the diff of the
// editor output, and `bx get -p`/JSON rendering.
// ---------------------------------------------------------------------------

// typeFieldSpec describes one field of a non-login item type: flag is the CLI
// flag name (kebab-case), json is the field name in the type object, and
// secret marks values that warn when passed on the command line.
type typeFieldSpec struct {
	flag   string
	json   string
	secret bool
}

// typeSpecs describes the fields of every non-login item type that has its
// own object, in the order they are shown in `bx get -p` and the editor
// template.  Secure notes (type 2) carry only the notes field and have no
// entry here.
var typeSpecs = map[int]struct {
	obj    string
	fields []typeFieldSpec
}{
	client.CipherTypeCard: {
		obj: "card",
		fields: []typeFieldSpec{
			{"cardholder", "cardholderName", false},
			{"brand", "brand", false},
			{"number", "number", true},
			{"exp-month", "expMonth", false},
			{"exp-year", "expYear", false},
			{"code", "code", true},
		},
	},
	client.CipherTypeIdentity: {
		obj: "identity",
		fields: []typeFieldSpec{
			{"title", "title", false},
			{"first-name", "firstName", false},
			{"middle-name", "middleName", false},
			{"last-name", "lastName", false},
			{"company", "company", false},
			{"email", "email", false},
			{"phone", "phone", false},
			{"username", "username", false},
			{"address1", "address1", false},
			{"address2", "address2", false},
			{"address3", "address3", false},
			{"city", "city", false},
			{"state", "state", false},
			{"postal-code", "postalCode", false},
			{"country", "country", false},
			{"ssn", "ssn", true},
			{"passport-number", "passportNumber", true},
			{"license-number", "licenseNumber", true},
		},
	},
	client.CipherTypeSshKey: {
		obj: "sshKey",
		fields: []typeFieldSpec{
			{"private-key", "privateKey", true},
			{"public-key", "publicKey", false},
			{"fingerprint", "keyFingerprint", false},
		},
	},
}

// addTypeFlags registers the type-specific flags of every non-login type on
// cmd.  Flags that already exist (such as --username) are skipped.
func addTypeFlags(cmd *cobra.Command) {
	for _, spec := range typeSpecs {
		for _, f := range spec.fields {
			if cmd.Flags().Lookup(f.flag) != nil {
				continue
			}
			usage := fmt.Sprintf("%s field of a %s item", f.json, spec.obj)
			if f.secret {
				usage += " (visible to other processes when passed on the command line)"
			}
			cmd.Flags().String(f.flag, "", usage)
		}
	}
	// --private-key-stdin lets an SSH private key be piped in, keeping it out
	// of argv like --password-stdin does for passwords.
	if cmd.Flags().Lookup("private-key-stdin") == nil {
		cmd.Flags().Bool("private-key-stdin", false, "Read the SSH private key from the first line of stdin (keeps it out of argv)")
	}
}

// alwaysAllowedForEdit lists edit flags that apply to every item type.
var alwaysAllowedForEdit = []string{"name", "notes", "folder", "force", "interactive", "organization", "collection"}

// alwaysAllowedForCreate lists create flags that apply to every item type.
var alwaysAllowedForCreate = []string{"name", "notes", "folder", "type"}

// validateTypeFlags rejects flags that do not apply to the item type being
// created or edited, so that a value is never silently dropped.  alwaysAllowed
// names the flags that are valid regardless of the type; login items accept
// every flag and are not validated.
func validateTypeFlags(cmd *cobra.Command, cipherType int, alwaysAllowed []string) error {
	if cipherType == client.CipherTypeLogin {
		return nil
	}

	allowed := map[string]bool{}
	for _, f := range alwaysAllowed {
		allowed[f] = true
	}
	if spec, ok := typeSpecs[cipherType]; ok {
		for _, f := range spec.fields {
			allowed[f.flag] = true
		}
	}
	if cipherType == client.CipherTypeSshKey {
		allowed["private-key-stdin"] = true
	}

	var bad []string
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if !allowed[f.Name] {
			bad = append(bad, "--"+f.Name)
		}
	})
	if len(bad) > 0 {
		return fmt.Errorf("%s not valid for a %s item", strings.Join(bad, ", "), cipherTypeName(cipherType))
	}
	return nil
}

// collectTypeFields reads every set type-specific flag of cipherType and
// returns the values keyed by their JSON field name.
func collectTypeFields(cmd *cobra.Command, cipherType int) map[string]string {
	values := map[string]string{}
	spec, ok := typeSpecs[cipherType]
	if !ok {
		return values
	}
	for _, f := range spec.fields {
		fl := cmd.Flags().Lookup(f.flag)
		if fl == nil || !fl.Changed {
			continue
		}
		values[f.json] = fl.Value.String()
	}
	return values
}

// readSSHPrivateKeyStdin applies --private-key-stdin to the collected values:
// it reads the private key from stdin and is mutually exclusive with
// --private-key.
func readSSHPrivateKeyStdin(cmd *cobra.Command, values map[string]string) error {
	if !cmd.Flags().Changed("private-key-stdin") {
		return nil
	}
	if _, ok := values["privateKey"]; ok {
		return fmt.Errorf("--private-key and --private-key-stdin are mutually exclusive")
	}
	pk, err := readSecretLineStdin("private-key")
	if err != nil {
		return err
	}
	values["privateKey"] = pk
	return nil
}

// encryptTypeFields encrypts the collected plaintext values with key and
// returns them keyed by their JSON field name.
func encryptTypeFields(values map[string]string, key []byte) (map[string]*string, error) {
	out := make(map[string]*string, len(values))
	for field, value := range values {
		enc, err := encryptField(field, value, key)
		if err != nil {
			return nil, err
		}
		v := enc
		out[field] = &v
	}
	return out, nil
}

// editorTypeKey returns the key a type field is written with in the editor
// template: the camelCase JSON field name, which the parser matches
// case-insensitively.
func editorTypeKey(f typeFieldSpec) string {
	return f.json
}

// matchTypeField matches a lower-cased editor key against a type field spec:
// both the kebab-case flag name and the camelCase JSON name are accepted.
func matchTypeField(keyLower string, f typeFieldSpec) bool {
	return strings.EqualFold(f.json, keyLower) || strings.EqualFold(f.flag, keyLower)
}

// decryptTypeFields decrypts every field of the type object of c with key and
// returns them keyed by their JSON field name.  It is used by the interactive
// editor, which shows every field: a field missing from the editor would be
// deleted.
func decryptTypeFields(c *client.Cipher, key []byte) (map[string]string, error) {
	values := map[string]string{}
	spec, ok := typeSpecs[c.Type]
	if !ok {
		return values, nil
	}

	var raws map[string]string
	switch c.Type {
	case client.CipherTypeCard:
		if c.Card != nil {
			raws = map[string]string{
				"cardholderName": c.Card.CardholderName,
				"brand":          c.Card.Brand,
				"number":         c.Card.Number,
				"expMonth":       c.Card.ExpMonth,
				"expYear":        c.Card.ExpYear,
				"code":           c.Card.Code,
			}
		}
	case client.CipherTypeIdentity:
		if c.Identity != nil {
			raws = map[string]string{
				"title":          c.Identity.Title,
				"firstName":      c.Identity.FirstName,
				"middleName":     c.Identity.MiddleName,
				"lastName":       c.Identity.LastName,
				"company":        c.Identity.Company,
				"email":          c.Identity.Email,
				"phone":          c.Identity.Phone,
				"username":       c.Identity.Username,
				"address1":       c.Identity.Address1,
				"address2":       c.Identity.Address2,
				"address3":       c.Identity.Address3,
				"city":           c.Identity.City,
				"state":          c.Identity.State,
				"postalCode":     c.Identity.PostalCode,
				"country":        c.Identity.Country,
				"ssn":            c.Identity.SSN,
				"passportNumber": c.Identity.PassportNumber,
				"licenseNumber":  c.Identity.LicenseNumber,
			}
		}
	case client.CipherTypeSshKey:
		if c.SshKey != nil {
			raws = map[string]string{
				"privateKey":     c.SshKey.PrivateKey,
				"publicKey":      c.SshKey.PublicKey,
				"keyFingerprint": c.SshKey.KeyFingerprint,
			}
		}
	}

	for _, f := range spec.fields {
		b, err := crypto.Decrypt(raws[f.json], key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt %s: %w", f.json, err)
		}
		values[f.json] = string(b)
	}
	return values, nil
}

// warnArgvTypeSecrets warns about type-specific secret flags that were given
// on the command line (card number, code, SSN, private key, …).
func warnArgvTypeSecrets(cmd *cobra.Command) {
	for _, spec := range typeSpecs {
		for _, f := range spec.fields {
			fl := cmd.Flags().Lookup(f.flag)
			if fl == nil || !fl.Changed || fl.Value.String() == "" {
				continue
			}
			if !f.secret {
				continue
			}
			fmt.Fprintf(os.Stderr, "warning: --%s is visible to other processes and may be saved in your shell history\n", f.flag)
		}
	}
}
