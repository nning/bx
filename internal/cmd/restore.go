package cmd

import (
	"fmt"
	"os"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
)

// findDeletedCipher searches the cipher list for a deleted item matching pattern
// by ID (exact or short form) or decrypted name (case-insensitive prefix/substring match). For short-ID matches (first UUID
// segment), an error is returned when multiple deleted ciphers share the same
// prefix so callers can prompt the user to supply the full UUID.
func findDeletedCipher(pattern string, ciphers []client.Cipher, accountKey []byte, orgKeys map[string][]byte) (*client.Cipher, error) {
	resolver := newCipherKeyResolver(accountKey, orgKeys)
	isDeleted := func(c client.Cipher) bool { return c.DeletedDate != nil }
	entries := buildCipherEntries(ciphers, resolver, isDeleted)

	// Exact ID pass.
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
	// Name pass — names are already decrypted in entries.
	for _, e := range entries {
		matched, _ := matchByName(e.name, pattern)
		if matched {
			c := e.cipher
			return &c, nil
		}
	}
	// Username pass.
	for _, e := range entries {
		cipher := e.cipher
		usernameBytes, err := crypto.Decrypt(cipherUsername(&cipher), e.key)
		if err != nil || len(usernameBytes) == 0 {
			continue
		}
		matched, _ := matchByName(string(usernameBytes), pattern)
		if matched {
			c := cipher
			return &c, nil
		}
	}
	return nil, nil
}

var restoreCmd = &cobra.Command{
	Use:   "restore <id|name|username>",
	Short: "Restore a soft-deleted vault item from the Trash",
	Args:  cobra.ExactArgs(1),
	RunE:  runRestore,
}

func runRestore(_ *cobra.Command, args []string) error {
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

	foundCipher, err := findDeletedCipher(pattern, v.Ciphers, accountKey, orgKeys)
	if err != nil {
		return err
	}
	if foundCipher == nil {
		return fmt.Errorf("deleted item not found: %s (use 'bx list --deleted' to see Trash items)", pattern)
	}

	nameBytes, _ := crypto.Decrypt(cipherName(foundCipher), cipherKey(*foundCipher, accountKey, orgKeys))
	displayName := string(nameBytes)
	if displayName == "" {
		displayName = foundCipher.ID
	}

	var updatedCipher *client.Cipher
	if err := withAutoLogin(func() error {
		var err error
		updatedCipher, err = apiClient.RestoreCipher(foundCipher.ID)
		return err
	}); err != nil {
		return fmt.Errorf("failed to restore item: %w", err)
	}

	if err := vault.PatchCipher(vault.PatchCipherEdit, updatedCipher); err != nil {
		fmt.Fprintf(os.Stderr, "warning: item restored on server but local cache update failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run 'bx fetch' to sync the local cache.\n")
	}

	fmt.Printf("Restored: %s\n", displayName)
	return nil
}

func init() {
	rootCmd.AddCommand(restoreCmd)
}
