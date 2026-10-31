package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete <id|name>",
	Short: "Delete a vault item (soft-delete by default, use --permanent for hard delete)",
	Args:  cobra.ExactArgs(1),
	RunE:  runDelete,
}

func runDelete(cmd *cobra.Command, args []string) error {
	if apiClient == nil {
		return fmt.Errorf("api client not initialized. Run 'bx setup' or 'bx account add <name>'")
	}
	if apiClient.Token == "" {
		return fmt.Errorf("not logged in. Run 'bx login'")
	}

	pattern := args[0]
	permanent, _ := cmd.Flags().GetBool("permanent")
	force, _ := cmd.Flags().GetBool("force")

	v, accountKey, orgKeys, _, err := vault.LoadVaultWithSession(unlockTimeoutMinutes(), readPassword)
	if err != nil {
		return err
	}

	var foundCipher *client.Cipher
	if permanent {
		// Permanent delete requires the item to already be in the Trash.
		var findErr error
		foundCipher, findErr = findDeletedCipher(pattern, v.Ciphers, accountKey, orgKeys)
		if findErr != nil {
			return findErr
		}
		if foundCipher == nil {
			return fmt.Errorf("deleted item not found: %s (use 'bx list --deleted' to see Trash items)", pattern)
		}
	} else {
		var findErr error
		foundCipher, findErr = findCipher(pattern, v.Ciphers, accountKey, orgKeys)
		if findErr != nil {
			return findErr
		}
		if foundCipher == nil {
			return fmt.Errorf("item not found: %s", pattern)
		}
	}

	// Decrypt the name for display.
	nameBytes, _ := crypto.Decrypt(cipherName(foundCipher), cipherKey(*foundCipher, accountKey, orgKeys))
	displayName := string(nameBytes)
	if displayName == "" {
		displayName = foundCipher.ID
	}

	// Conflict detection: compare local RevisionDate with the server's.
	if !force {
		var serverCipher *client.Cipher
		if err := withAutoLogin(func() error {
			var err error
			serverCipher, err = apiClient.GetCipher(foundCipher.ID)
			return err
		}); err != nil {
			return fmt.Errorf("conflict check failed: %w", err)
		}
		if serverCipher.RevisionDate != foundCipher.RevisionDate {
			return fmt.Errorf(
				"conflict detected for %q: local revision %q differs from server revision %q — run 'bx fetch' to sync before retrying",
				pattern, foundCipher.RevisionDate, serverCipher.RevisionDate,
			)
		}
	}

	// Confirmation prompt for destructive operations (skip with --force).
	if !force {
		action := "move to Trash"
		if permanent {
			action = "PERMANENTLY DELETE"
		}
		fmt.Printf("About to %s: %q\n", action, displayName)
		fmt.Print("Type the item name to confirm: ")
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("failed to read confirmation: %w", err)
			}
			return fmt.Errorf("confirmation failed: unexpected end of input")
		}
		typed := strings.TrimSpace(scanner.Text())
		if typed != displayName {
			return fmt.Errorf("confirmation failed: you typed %q but the item name is %q", typed, displayName)
		}
	}

	if permanent {
		if err := withAutoLogin(func() error {
			return apiClient.HardDeleteCipher(foundCipher.ID)
		}); err != nil {
			return fmt.Errorf("failed to delete item: %w", err)
		}
		if err := vault.PatchCipher(vault.PatchCipherHardDelete, foundCipher); err != nil {
			fmt.Fprintf(os.Stderr, "warning: item deleted on server but local cache update failed: %v\n", err)
			fmt.Fprintf(os.Stderr, "Run 'bx fetch' to sync the local cache.\n")
		}
		fmt.Printf("Permanently deleted: %s\n", displayName)
	} else {
		var updatedCipher *client.Cipher
		if err := withAutoLogin(func() error {
			var err error
			updatedCipher, err = apiClient.SoftDeleteCipher(foundCipher.ID)
			return err
		}); err != nil {
			return fmt.Errorf("failed to move item to Trash: %w", err)
		}
		if err := vault.PatchCipher(vault.PatchCipherEdit, updatedCipher); err != nil {
			fmt.Fprintf(os.Stderr, "warning: item moved to Trash on server but local cache update failed: %v\n", err)
			fmt.Fprintf(os.Stderr, "Run 'bx fetch' to sync the local cache.\n")
		}
		fmt.Printf("Moved to Trash: %s\n", displayName)
	}

	return nil
}

func init() {
	deleteCmd.Flags().Bool("permanent", false, "Hard delete (irreversible; item must already be in Trash)")
	deleteCmd.Flags().BoolP("force", "f", false, "Skip the confirmation prompt")
	rootCmd.AddCommand(deleteCmd)
}
