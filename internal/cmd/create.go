package cmd

import (
	"fmt"
	"os"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
)

// cipherTypeFromString maps a type flag value to the Bitwarden cipher type int.
// Returns an error if s is not a recognized type.
func cipherTypeFromString(s string) (int, error) {
	switch s {
	case "login":
		return client.CipherTypeLogin, nil
	case "note":
		return client.CipherTypeNote, nil
	case "card":
		return client.CipherTypeCard, nil
	case "identity":
		return client.CipherTypeIdentity, nil
	case "ssh-key":
		return client.CipherTypeSshKey, nil
	default:
		return 0, fmt.Errorf("unsupported item type %q: use login, note, card, identity or ssh-key", s)
	}
}

// findFolderID resolves a folder flag value (ID, short ID or name) to a folder
// ID using findFolder. Returns an empty string and no error when no folder
// matches.
func findFolderID(flagVal string, folders []client.Folder, accountKey []byte) (string, error) {
	f, err := findFolder(flagVal, folders, accountKey)
	if err != nil || f == nil {
		return "", err
	}
	return f.ID, nil
}

var createCmd = &cobra.Command{
	Use:     "create",
	Aliases: []string{"new"},
	Short:   "Create a new vault item on the server (alias: new)",
	RunE:    runCreate,
}

func runCreate(cmd *cobra.Command, _ []string) error {
	if apiClient == nil {
		return fmt.Errorf("api client not initialized. Run 'bx setup' or 'bx account add <name>'")
	}
	if apiClient.Token == "" {
		return fmt.Errorf("not logged in. Run 'bx login'")
	}

	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		return fmt.Errorf("--name is required")
	}

	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")
	urls, _ := cmd.Flags().GetStringArray("url")
	notes, _ := cmd.Flags().GetString("notes")
	totpFlag, _ := cmd.Flags().GetString("totp")
	folderFlag, _ := cmd.Flags().GetString("folder")
	typeFlag, _ := cmd.Flags().GetString("type")
	genPass, _ := cmd.Flags().GetBool("generate")

	cipherType, err := cipherTypeFromString(typeFlag)
	if err != nil {
		return err
	}
	if err := validateTypeFlags(cmd, cipherType, alwaysAllowedForCreate); err != nil {
		return err
	}
	warnArgvSecrets(cmd)
	warnArgvTypeSecrets(cmd)

	// --password-stdin takes the item password from a pipe so that it never
	// reaches argv.  It is mutually exclusive with the other ways of supplying
	// one, because silently preferring one source would hide a mistake.
	if passStdin, _ := cmd.Flags().GetBool("password-stdin"); passStdin {
		if cmd.Flags().Changed("password") {
			return fmt.Errorf("--password and --password-stdin are mutually exclusive")
		}
		if genPass {
			return fmt.Errorf("--generate and --password-stdin are mutually exclusive")
		}
		if cipherType != client.CipherTypeLogin {
			return fmt.Errorf("--password-stdin is only valid for login items")
		}
		password, err = readSecretLineStdin("password")
		if err != nil {
			return err
		}
	}

	// Prompt securely for item password only when creating a login item and NOT using --generate.
	if password == "" && cipherType == client.CipherTypeLogin && !genPass {
		var err error
		password, err = promptSecure("Item password (blank to skip): ")
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}

	// If generate flag is set, create a random password for login items.
	generatedPassword := false
	if genPass && password == "" && cipherType == client.CipherTypeLogin {
		generatedPassword = true
		var err error
		password, err = crypto.GeneratePassword(36, true, true, true, true)
		if err != nil {
			return fmt.Errorf("failed to generate password: %w", err)
		}
	}

	v, accountKey, _, _, err := vault.LoadVaultWithSession(unlockTimeoutMinutes(), readPassword)
	if err != nil {
		return err
	}

	var folderID *string
	if folderFlag != "" {
		fid, err := findFolderID(folderFlag, v.Folders, accountKey)
		if err != nil {
			return err
		}
		if fid == "" {
			return fmt.Errorf("folder not found: %s", folderFlag)
		}
		folderID = &fid
	}

	// Encrypt fields
	encName, err := encryptField("name", name, accountKey)
	if err != nil {
		return err
	}

	req := client.CipherRequest{
		Type:         cipherType,
		Name:         encName,
		FolderID:     folderID,
		Favorite:     false,
		EncryptedFor: v.Profile.ID,
	}

	if notes != "" {
		encNotes, err := encryptField("notes", notes, accountKey)
		if err != nil {
			return err
		}
		req.Notes = &encNotes
	}

	if cipherType == client.CipherTypeLogin { // login
		loginReq := &client.CipherLoginReq{}

		if username != "" {
			encUser, err := encryptField("username", username, accountKey)
			if err != nil {
				return err
			}
			loginReq.Username = &encUser
		}

		if password != "" {
			encPass, err := encryptField("password", password, accountKey)
			if err != nil {
				return err
			}
			loginReq.Password = &encPass
		}

		if totpFlag != "" {
			encTotp, err := encryptField("totp", totpFlag, accountKey)
			if err != nil {
				return err
			}
			loginReq.Totp = &encTotp
		}

		for _, u := range urls {
			encURI, err := encryptField("uri", u, accountKey)
			if err != nil {
				return err
			}
			loginReq.URIs = append(loginReq.URIs, client.CipherURIReq{URI: encURI})
		}

		req.Login = loginReq
	} else if cipherType != client.CipherTypeNote {
		// Cards, identities and SSH keys carry their fields in a
		// type-specific object; secure notes carry only the notes above.
		values := collectTypeFields(cmd, cipherType)
		if cipherType == client.CipherTypeSshKey {
			if err := readSSHPrivateKeyStdin(cmd, values); err != nil {
				return err
			}
			if _, ok := values["privateKey"]; !ok {
				return fmt.Errorf("an SSH key item needs --private-key or --private-key-stdin")
			}
		}
		enc, err := encryptTypeFields(values, accountKey)
		if err != nil {
			return err
		}
		switch cipherType {
		case client.CipherTypeCard:
			req.Card = &client.CipherCardReq{
				CardholderName: enc["cardholderName"],
				Brand:          enc["brand"],
				Number:         enc["number"],
				ExpMonth:       enc["expMonth"],
				ExpYear:        enc["expYear"],
				Code:           enc["code"],
			}
		case client.CipherTypeIdentity:
			req.Identity = &client.CipherIdentityReq{
				Title:          enc["title"],
				FirstName:      enc["firstName"],
				MiddleName:     enc["middleName"],
				LastName:       enc["lastName"],
				Company:        enc["company"],
				Email:          enc["email"],
				Phone:          enc["phone"],
				Username:       enc["username"],
				Address1:       enc["address1"],
				Address2:       enc["address2"],
				Address3:       enc["address3"],
				City:           enc["city"],
				State:          enc["state"],
				PostalCode:     enc["postalCode"],
				Country:        enc["country"],
				SSN:            enc["ssn"],
				PassportNumber: enc["passportNumber"],
				LicenseNumber:  enc["licenseNumber"],
			}
		case client.CipherTypeSshKey:
			req.SshKey = &client.CipherSshKeyReq{
				PrivateKey:     enc["privateKey"],
				PublicKey:      enc["publicKey"],
				KeyFingerprint: enc["keyFingerprint"],
			}
		}
	}

	var cipher *client.Cipher
	if err := withAutoLogin(func() error {
		var err error
		cipher, err = apiClient.CreateCipher(req)
		return err
	}); err != nil {
		return fmt.Errorf("failed to create item: %w", err)
	}

	if err := vault.PatchCipher(vault.PatchCipherCreate, cipher); err != nil {
		fmt.Fprintf(os.Stderr, "warning: item created on server but local cache update failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run 'bx fetch' to sync the local cache.\n")
	}

	fmt.Printf("Created: %s (ID: %s)\n", name, cipher.ID)
	// Only handed out once the item exists, so that a failed create does not
	// leave the user with a password that was never saved.
	if generatedPassword {
		announceGeneratedPassword(name, password)
	}
	return nil
}

func addCreateFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("name", "n", "", "Item name (required)")
	cmd.Flags().StringP("username", "u", "", "Username (login and identity items)")
	cmd.Flags().StringP("password", "p", "", "Password (login items only; omit to prompt securely)")
	cmd.Flags().Bool("password-stdin", false, "Read the password from the first line of stdin (keeps it out of argv)")
	cmd.Flags().StringArrayP("url", "U", nil, "URL (repeatable; login items only)")
	cmd.Flags().String("notes", "", "Free-text notes")
	cmd.Flags().StringP("totp", "t", "", "TOTP seed or otpauth:// URI (login items only)")
	cmd.Flags().String("folder", "", "Parent folder ID or name")
	cmd.Flags().String("type", "login", "Item type: login, note, card, identity or ssh-key")
	cmd.Flags().Bool("generate", false, "Generate a random password (login items only)")
	addTypeFlags(cmd)
}

func init() {
	addCreateFlags(createCmd)
	registerFolderFlagCompletion(createCmd)
	rootCmd.AddCommand(createCmd)
}
