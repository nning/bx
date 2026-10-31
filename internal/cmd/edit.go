package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
)

var editCmd = &cobra.Command{
	Use:   "edit <id|name>",
	Short: "Edit fields of an existing vault item",
	Args:  cobra.ExactArgs(1),
	RunE:  runEdit,
}

// editMutableFlags lists the flags that change an item's own fields or its
// folder.  At least one of them (or --interactive) is required so that a bare
// `bx edit <name>` does not send a no-op write to the server, which would bump
// RevisionDate.
var editMutableFlags = []string{"name", "username", "password", "password-stdin", "notes", "totp", "url", "remove-url", "generate", "folder"}

// editOwnershipFlags lists the flags that change who owns an item rather than
// what it contains.  They are handled by runEditOwnership.
var editOwnershipFlags = []string{"organization", "collection"}

// anyFlagChanged reports whether the user explicitly set any of the given flags.
func anyFlagChanged(cmd *cobra.Command, names []string) bool {
	for _, name := range names {
		if cmd.Flags().Changed(name) {
			return true
		}
	}
	return false
}

// conflictError builds the error returned when the server's copy of an item is
// newer than the local cache.
func conflictError(pattern, localRevision, serverRevision string) error {
	return fmt.Errorf(
		"conflict detected for %q: local revision %q differs from server revision %q — run 'bx fetch' to sync before retrying",
		pattern, localRevision, serverRevision,
	)
}

// checkCipherConflict compares the local RevisionDate with the server's and
// returns an error when they differ, so that an edit never silently overwrites
// changes made elsewhere.
func checkCipherConflict(pattern string, foundCipher *client.Cipher) error {
	var serverCipher *client.Cipher
	if err := withAutoLogin(func() error {
		var err error
		serverCipher, err = apiClient.GetCipher(foundCipher.ID)
		return err
	}); err != nil {
		return fmt.Errorf("conflict check failed: %w", err)
	}
	if serverCipher.RevisionDate != foundCipher.RevisionDate {
		return conflictError(pattern, foundCipher.RevisionDate, serverCipher.RevisionDate)
	}
	return nil
}

func runEdit(cmd *cobra.Command, args []string) error {
	if apiClient == nil {
		return fmt.Errorf("api client not initialized. Run 'bx setup' or 'bx account add <name>'")
	}
	if apiClient.Token == "" {
		return fmt.Errorf("not logged in. Run 'bx login'")
	}

	pattern := args[0]

	v, accountKey, orgKeys, _, err := vault.LoadVaultWithSession(unlockTimeoutMinutes(), readPassword)
	if err != nil {
		return err
	}

	foundCipher, err := findCipher(pattern, v.Ciphers, accountKey, orgKeys)
	if err != nil {
		return err
	}
	if foundCipher == nil {
		return fmt.Errorf("item not found: %s", pattern)
	}

	effectiveKey := cipherKey(*foundCipher, accountKey, orgKeys)

	// Type-specific flags that do not apply to the item type are rejected
	// before anything else, so that a value is never silently dropped.
	if err := validateTypeFlags(cmd, foundCipher.Type, alwaysAllowedForEdit); err != nil {
		return err
	}
	warnArgvTypeSecrets(cmd)

	// Collect the type-specific field changes up front: they count as field
	// edits for the checks below.  A private key from --private-key-stdin is
	// read only once the plain flag route is taken, so that a rejected
	// combination does not consume stdin needlessly.
	typeValues := map[string]string{}
	if _, ok := typeSpecs[foundCipher.Type]; ok {
		typeValues = collectTypeFields(cmd, foundCipher.Type)
	}

	// Ownership changes (--organization/--collection) take a different route:
	// they re-key or re-assign the item as a whole instead of writing single
	// fields, so they run on their own rather than being mixed with field edits.
	if anyFlagChanged(cmd, editOwnershipFlags) {
		if anyFlagChanged(cmd, editMutableFlags) || len(typeValues) > 0 || cmd.Flags().Changed("interactive") {
			return fmt.Errorf("--organization/--collection cannot be combined with field edits; change the owner first, then edit the fields")
		}
		return runEditOwnership(cmd, pattern, v, foundCipher, effectiveKey, accountKey, orgKeys)
	}

	interactive, _ := cmd.Flags().GetBool("interactive")

	if interactive {
		if anyFlagChanged(cmd, editMutableFlags) || len(typeValues) > 0 {
			return fmt.Errorf("--interactive opens the item in your editor; field flags cannot be combined with it")
		}
		return runEditInteractive(cmd, pattern, v.Profile.ID, foundCipher, accountKey, orgKeys)
	}

	if foundCipher.Type == client.CipherTypeSshKey {
		if err := readSSHPrivateKeyStdin(cmd, typeValues); err != nil {
			return err
		}
	}

	typeObj := ""
	if len(typeValues) > 0 {
		typeObj = typeSpecs[foundCipher.Type].obj
	}

	if !anyFlagChanged(cmd, editMutableFlags) && len(typeValues) == 0 {
		return fmt.Errorf("no fields to update; provide at least one flag (--name, --username, --password, --url, etc.) or use --interactive/-i")
	}

	warnArgvSecrets(cmd)

	// Collect the requested changes before contacting the server, so that
	// invalid flag combinations fail early.
	var u cipherUpdate
	for flag, dst := range map[string]**string{
		"name":     &u.Name,
		"notes":    &u.Notes,
		"username": &u.Username,
		"totp":     &u.Totp,
	} {
		if cmd.Flags().Changed(flag) {
			v, _ := cmd.Flags().GetString(flag)
			*dst = &v
		}
	}

	// A new password comes from --password, --password-stdin, or --generate.
	var newPassword string
	passwordChanged := cmd.Flags().Changed("password")
	if passwordChanged {
		newPassword, _ = cmd.Flags().GetString("password")
	}
	if passStdin, _ := cmd.Flags().GetBool("password-stdin"); passStdin {
		if passwordChanged {
			return fmt.Errorf("--password and --password-stdin are mutually exclusive")
		}
		if useGenerate, _ := cmd.Flags().GetBool("generate"); useGenerate {
			return fmt.Errorf("--generate and --password-stdin are mutually exclusive")
		}
		newPassword, err = readSecretLineStdin("password")
		if err != nil {
			return err
		}
		passwordChanged = true
	}
	generated := false
	if useGenerate, _ := cmd.Flags().GetBool("generate"); useGenerate && !passwordChanged {
		newPassword, err = crypto.GeneratePassword(36, true, true, true, true)
		if err != nil {
			return fmt.Errorf("failed to generate password: %w", err)
		}
		passwordChanged, generated = true, true
	}
	if passwordChanged {
		u.Password = &newPassword
	}

	// Cards, identities and SSH keys carry their fields in a type-specific
	// object; only the changed fields are re-encrypted, and the rest of the
	// object is forwarded verbatim.
	if typeObj != "" {
		u.TypeObj = typeObj
		u.TypeFields = map[string]*string{}
		for field, value := range typeValues {
			v := value
			u.TypeFields[field] = &v
		}
	}

	force, _ := cmd.Flags().GetBool("force")
	raw, serverCipher, key, err := fetchEditBase(pattern, foundCipher, force, accountKey, orgKeys)
	if err != nil {
		return err
	}

	// The folder is resolved against the local folder list: a name, an ID, or
	// a short ID.  The sentinel "none" removes the item from its folder.
	if cmd.Flags().Changed("folder") {
		folderFlag, _ := cmd.Flags().GetString("folder")
		if strings.EqualFold(folderFlag, "none") {
			none := ""
			u.FolderID = &none
		} else {
			fid, err := findFolderID(folderFlag, v.Folders, accountKey)
			if err != nil {
				return err
			}
			if fid == "" {
				return fmt.Errorf("folder not found: %s", folderFlag)
			}
			u.FolderID = &fid
		}
	}

	if cmd.Flags().Changed("url") || cmd.Flags().Changed("remove-url") {
		addURLs, _ := cmd.Flags().GetStringArray("url")
		removeURLs, _ := cmd.Flags().GetStringArray("remove-url")
		urls, err := editURLs(serverCipher, key, addURLs, removeURLs)
		if err != nil {
			return err
		}
		u.URLs = &urls
	}

	if err := sendEdit(foundCipher, raw, u, v.Profile.ID, key); err != nil {
		return err
	}
	// Only shown once the password is stored, so that a failed update does
	// not leave the user with a password that was never saved.
	// Display the actual item name: use the newly supplied --name value if
	// the flag was changed, otherwise fall back to the search pattern.
	displayName := pattern
	if u.Name != nil {
		displayName = *u.Name
	}
	fmt.Printf("Updated: %s\n", displayName)
	if generated {
		announceGeneratedPassword(displayName, newPassword)
	}
	return nil
}

// fetchEditBase fetches the server's copy of the item an edit is applied to:
// raw, to build the request from, and typed, to decrypt it, together with the
// key its values are encrypted with.  Unless force is set, it refuses to
// continue when the server's copy differs from the local cache, so that an
// edit never silently overwrites changes made elsewhere.
func fetchEditBase(pattern string, local *client.Cipher, force bool, accountKey []byte, orgKeys map[string][]byte) (json.RawMessage, *client.Cipher, []byte, error) {
	var raw json.RawMessage
	if err := withAutoLogin(func() error {
		var err error
		raw, err = apiClient.GetCipherRaw(local.ID)
		return err
	}); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to fetch item from server: %w", err)
	}

	var server client.Cipher
	if err := json.Unmarshal(raw, &server); err != nil {
		return nil, nil, nil, fmt.Errorf("could not parse server copy of item: %w", err)
	}
	if !force && server.RevisionDate != local.RevisionDate {
		return nil, nil, nil, conflictError(pattern, local.RevisionDate, server.RevisionDate)
	}
	return raw, &server, cipherKey(server, accountKey, orgKeys), nil
}

// sendEdit applies u to the server's raw copy of the item, writes the result
// to the server on behalf of userID, and updates the local cache from the
// server's response.
//
// The request carries lastKnownRevisionDate from the server copy, so the
// server rejects the write if the item changed since it was fetched — for
// example while the interactive editor was open.
func sendEdit(local *client.Cipher, raw json.RawMessage, u cipherUpdate, userID string, key []byte) error {
	body, err := buildEditCipher(raw, u, userID, key, time.Now())
	if err != nil {
		return err
	}

	var updated json.RawMessage
	if err := withAutoLogin(func() error {
		var err error
		updated, err = apiClient.UpdateCipherRaw(local.ID, body)
		return err
	}); err != nil {
		return fmt.Errorf("failed to update item: %w", err)
	}

	patchLocalRawCipher(updated, local.CollectionIDs)
	return nil
}

// editURLs returns the item's URLs with removeURLs taken out and addURLs
// appended; both comparisons are case-insensitive, and URLs that are already
// present are not added again.
func editURLs(c *client.Cipher, key []byte, addURLs, removeURLs []string) ([]string, error) {
	var urls []string
	seen := map[string]bool{}
	for _, u := range cipherURIs(c) {
		b, err := crypto.Decrypt(u.URI, key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt URI: %w", err)
		}
		url := string(b)
		remove := false
		for _, rem := range removeURLs {
			if strings.EqualFold(url, rem) {
				remove = true
				break
			}
		}
		if !remove {
			urls = append(urls, url)
			seen[strings.ToLower(url)] = true
		}
	}
	for _, url := range addURLs {
		if !seen[strings.ToLower(url)] {
			urls = append(urls, url)
			seen[strings.ToLower(url)] = true
		}
	}
	return urls, nil
}

// runEditInteractive handles the --interactive editor flow.  It decrypts the
// server's copy of the item, opens it in the user's editor, and sends only the
// values the user changed.
func runEditInteractive(cmd *cobra.Command, pattern, userID string, foundCipher *client.Cipher, accountKey []byte, orgKeys map[string][]byte) error {
	// The server's copy is fetched before the editor opens, so that the user
	// edits the current item; see sendEdit for changes made meanwhile.
	force, _ := cmd.Flags().GetBool("force")
	raw, serverCipher, key, err := fetchEditBase(pattern, foundCipher, force, accountKey, orgKeys)
	if err != nil {
		return err
	}

	original, err := decryptCipherToFields(serverCipher, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt item for editing: %w", err)
	}

	content := formatCipherForEditor(original)
	edited, err := openInEditor(content)
	if err != nil {
		return err
	}

	// Diff against the unedited file as parsed rather than against original,
	// so that anything the text format normalizes (such as trailing newlines
	// in notes) is not mistaken for an edit and is kept as it was.
	updated := parseCipherFromEditor(edited, serverCipher.Type)
	u := diffEditFields(parseCipherFromEditor(content, serverCipher.Type), updated)
	if u.isEmpty() {
		fmt.Fprintln(os.Stderr, "No changes detected.")
		return nil
	}

	if err := sendEdit(foundCipher, raw, u, userID, key); err != nil {
		return err
	}

	displayName := updated.Name
	if displayName == "" {
		displayName = pattern
	}
	fmt.Printf("Updated: %s\n", displayName)
	return nil
}

// diffEditFields returns the changes that turn before into after.  For
// non-login item types the fields of the type object are diffed as well.
func diffEditFields(before, after cipherEditFields) cipherUpdate {
	var u cipherUpdate
	for _, f := range []struct {
		before, after string
		dst           **string
	}{
		{before.Name, after.Name, &u.Name},
		{before.Username, after.Username, &u.Username},
		{before.Password, after.Password, &u.Password},
		{before.Totp, after.Totp, &u.Totp},
		{before.Notes, after.Notes, &u.Notes},
	} {
		if f.before != f.after {
			v := f.after
			*f.dst = &v
		}
	}
	if !urlsEqual(before.URLs, after.URLs) {
		u.URLs = &after.URLs
	}
	if !customFieldsEqual(before.CustomFields, after.CustomFields) {
		u.CustomFields = &after.CustomFields
	}
	if spec, ok := typeSpecs[before.Type]; ok {
		changed := map[string]*string{}
		for k, v := range after.TypeFields {
			if before.TypeFields[k] != v {
				s := v
				changed[k] = &s
			}
		}
		if len(changed) > 0 {
			u.TypeObj = spec.obj
			u.TypeFields = changed
		}
	}
	return u
}

// customFieldsEqual returns true if two custom field slices have the same
// types, names, and values in the same order.
func customFieldsEqual(a, b []cipherCustomField) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// urlsEqual returns true if two URL slices have the same elements in the same order.
func urlsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func init() {
	editCmd.Flags().StringP("name", "n", "", "New item name")
	editCmd.Flags().StringP("username", "u", "", "New username")
	editCmd.Flags().StringP("password", "p", "", "New password")
	editCmd.Flags().Bool("password-stdin", false, "Read the new password from the first line of stdin (keeps it out of argv)")
	editCmd.Flags().StringArrayP("url", "U", nil, "Add URL(s) to the existing list (repeatable; duplicates are skipped)")
	editCmd.Flags().StringArray("remove-url", nil, "Remove URL(s) from the existing list by value (repeatable)")
	editCmd.Flags().String("notes", "", "New notes")
	editCmd.Flags().StringP("organization", "o", "", "Move the item to this organization (name or ID); requires --collection")
	editCmd.Flags().StringArrayP("collection", "c", nil, "Collection(s) the item belongs to (repeatable; replaces the current set)")
	editCmd.Flags().StringP("totp", "t", "", "New TOTP seed or otpauth:// URI (login items only)")
	editCmd.Flags().String("folder", "", "Move the item to this folder (name, ID or short ID); \"none\" removes it from its folder")
	editCmd.Flags().BoolP("force", "f", false, "Skip conflict check and overwrite regardless")
	editCmd.Flags().Bool("generate", false, "Generate a random password for the item (login items only)")
	addTypeFlags(editCmd)
	editCmd.Flags().BoolP("interactive", "i", false, "Open item in $VISUAL/$EDITOR for interactive editing")
	rootCmd.AddCommand(editCmd)
	registerFolderFlagCompletion(editCmd)
}
