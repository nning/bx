package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
)

// findFolder searches the folder list for a match by ID (exact or short form)
// or decrypted name (case-insensitive). For short-ID matches (first UUID
// segment), an error is returned when multiple folders share the same prefix so
// callers can prompt the user to supply the full UUID. Returns nil, nil when no
// match is found.
func findFolder(pattern string, folders []client.Folder, accountKey []byte) (*client.Folder, error) {
	// Exact ID pass.
	for _, f := range folders {
		if f.ID == pattern {
			folder := f
			return &folder, nil
		}
	}
	// Short-ID pass: collect all matches before deciding.
	var shortMatches []client.Folder
	for _, f := range folders {
		if shortID(f.ID) == pattern {
			shortMatches = append(shortMatches, f)
		}
	}
	if len(shortMatches) == 1 {
		folder := shortMatches[0]
		return &folder, nil
	}
	if len(shortMatches) > 1 {
		return nil, fmt.Errorf("ambiguous short ID %q: use the full UUID to disambiguate", pattern)
	}
	// Name pass.
	for _, f := range folders {
		nameBytes, err := crypto.Decrypt(f.Name, accountKey)
		if err != nil {
			continue
		}
		if strings.EqualFold(string(nameBytes), pattern) {
			folder := f
			return &folder, nil
		}
	}
	return nil, nil
}

var folderListCmd = &cobra.Command{
	Use:   "list",
	Short: "List vault folders",
	RunE:  runFolderList,
}

type folderRow struct {
	id        string
	name      string
	lowerName string
}

func sortFolderRows(rows []folderRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].lowerName != rows[j].lowerName {
			return rows[i].lowerName < rows[j].lowerName
		}
		if rows[i].name != rows[j].name {
			return rows[i].name < rows[j].name
		}
		return rows[i].id < rows[j].id
	})
}

func runFolderList(_ *cobra.Command, _ []string) error {
	v, accountKey, _, _, err := vault.LoadVaultWithSession(unlockTimeoutMinutes(), readPassword)
	if err != nil {
		return err
	}

	rows := make([]folderRow, 0, len(v.Folders))
	for _, folder := range v.Folders {
		nameBytes, decErr := crypto.Decrypt(folder.Name, accountKey)
		name := string(nameBytes)
		if decErr != nil {
			name = "[Decryption Error]"
		}
		rows = append(rows, folderRow{shortID(folder.ID), name, strings.ToLower(name)})
	}

	sortFolderRows(rows)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "ID\tNAME"); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", row.id, row.name); err != nil {
			return err
		}
	}

	return w.Flush()
}

var folderCmd = &cobra.Command{
	Use:   "folder",
	Short: "Manage vault folders",
}

var folderCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new folder",
	RunE:  runFolderCreate,
}

var folderDeleteCmd = &cobra.Command{
	Use:   "delete <id|name>",
	Short: "Delete a folder",
	Args:  cobra.ExactArgs(1),
	RunE:  runFolderDelete,
}

var folderRenameCmd = &cobra.Command{
	Use:   "rename <id|name>",
	Short: "Rename a folder",
	Args:  cobra.ExactArgs(1),
	RunE:  runFolderRename,
}

// runFolderRename renames a folder: the new name is encrypted with the account
// key, written to the server with UpdateFolder, and the local cache is patched.
func runFolderRename(cmd *cobra.Command, args []string) error {
	if apiClient == nil {
		return fmt.Errorf("api client not initialized. Run 'bx setup' or 'bx account add <name>'")
	}
	if apiClient.Token == "" {
		return fmt.Errorf("not logged in. Run 'bx login'")
	}

	pattern := args[0]
	newName, _ := cmd.Flags().GetString("name")
	if newName == "" {
		return fmt.Errorf("--name is required")
	}

	v, accountKey, _, _, err := vault.LoadVaultWithSession(unlockTimeoutMinutes(), readPassword)
	if err != nil {
		return err
	}

	found, err := findFolder(pattern, v.Folders, accountKey)
	if err != nil {
		return err
	}
	if found == nil {
		return fmt.Errorf("folder not found: %s", pattern)
	}

	oldNameBytes, _ := crypto.Decrypt(found.Name, accountKey)
	oldName := string(oldNameBytes)
	if oldName == "" {
		oldName = found.ID
	}
	if oldName == newName {
		fmt.Printf("Folder %s is already named %s\n", oldName, newName)
		return nil
	}

	encName, err := encryptField("folder name", newName, accountKey)
	if err != nil {
		return err
	}

	var folder *client.Folder
	if err := withAutoLogin(func() error {
		var err error
		folder, err = apiClient.UpdateFolder(found.ID, client.FolderRequest{Name: encName})
		return err
	}); err != nil {
		return fmt.Errorf("failed to rename folder: %w", err)
	}

	if err := vault.PatchFolder(vault.PatchFolderEdit, folder); err != nil {
		fmt.Fprintf(os.Stderr, "warning: folder renamed on server but local cache update failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run 'bx fetch' to sync the local cache.\n")
	}

	fmt.Printf("Renamed folder: %s → %s\n", oldName, newName)
	return nil
}

func runFolderCreate(cmd *cobra.Command, _ []string) error {
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

	_, accountKey, _, _, err := vault.LoadVaultWithSession(unlockTimeoutMinutes(), readPassword)
	if err != nil {
		return err
	}

	encName, err := encryptField("folder name", name, accountKey)
	if err != nil {
		return err
	}

	var folder *client.Folder
	if err := withAutoLogin(func() error {
		var err error
		folder, err = apiClient.CreateFolder(client.FolderRequest{Name: encName})
		return err
	}); err != nil {
		return fmt.Errorf("failed to create folder: %w", err)
	}

	if err := vault.PatchFolder(vault.PatchFolderCreate, folder); err != nil {
		fmt.Fprintf(os.Stderr, "warning: folder created on server but local cache update failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run 'bx fetch' to sync the local cache.\n")
	}

	fmt.Printf("Created folder: %s (ID: %s)\n", name, folder.ID)
	return nil
}

func runFolderDelete(cmd *cobra.Command, args []string) error {
	if apiClient == nil {
		return fmt.Errorf("api client not initialized. Run 'bx setup' or 'bx account add <name>'")
	}
	if apiClient.Token == "" {
		return fmt.Errorf("not logged in. Run 'bx login'")
	}

	pattern := args[0]
	force, _ := cmd.Flags().GetBool("force")

	v, accountKey, _, _, err := vault.LoadVaultWithSession(unlockTimeoutMinutes(), readPassword)
	if err != nil {
		return err
	}

	found, err := findFolder(pattern, v.Folders, accountKey)
	if err != nil {
		return err
	}
	if found == nil {
		return fmt.Errorf("folder not found: %s", pattern)
	}

	// Decrypt the name for display / confirmation.
	nameBytes, _ := crypto.Decrypt(found.Name, accountKey)
	displayName := string(nameBytes)
	if displayName == "" {
		displayName = found.ID
	}

	if !force {
		fmt.Printf("About to delete folder: %q\n", displayName)
		fmt.Print("Type the folder name to confirm: ")
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("failed to read confirmation: %w", err)
			}
			return fmt.Errorf("confirmation failed: unexpected end of input")
		}
		typed := strings.TrimSpace(scanner.Text())
		if typed != displayName {
			return fmt.Errorf("confirmation failed: you typed %q but the folder name is %q", typed, displayName)
		}
	}

	if err := withAutoLogin(func() error {
		return apiClient.DeleteFolder(found.ID)
	}); err != nil {
		return fmt.Errorf("failed to delete folder: %w", err)
	}

	if err := vault.PatchFolder(vault.PatchFolderDelete, found); err != nil {
		fmt.Fprintf(os.Stderr, "warning: folder deleted on server but local cache update failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run 'bx fetch' to sync the local cache.\n")
	}

	fmt.Printf("Deleted folder: %s\n", displayName)
	return nil
}

func init() {
	folderCreateCmd.Flags().StringP("name", "n", "", "Folder name (required)")
	folderDeleteCmd.Flags().BoolP("force", "f", false, "Skip the confirmation prompt")
	folderRenameCmd.Flags().StringP("name", "n", "", "New folder name (required)")

	folderCmd.AddCommand(folderCreateCmd)
	folderCmd.AddCommand(folderDeleteCmd)
	folderCmd.AddCommand(folderRenameCmd)
	folderCmd.AddCommand(folderListCmd)
	rootCmd.AddCommand(folderCmd)
}
