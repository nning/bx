package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
)

// writeFileAtomic writes data to path using a temp file + rename.
// On POSIX systems the rename is atomic, so readers never observe a partially-
// written file.  On Windows os.Rename fails when the destination already exists,
// so the existing file is removed first and the rename is retried; this
// introduces a brief window where the file is absent, but the write is still
// never partial.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".bx_fetch_*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return replaceFile(tmpPath, path)
}

// replaceFile moves the file at tmpPath to path, replacing whatever is there.
// os.Rename is atomic on POSIX; on Windows fall back to remove-then-rename.
func replaceFile(tmpPath, path string) error {
	if err := os.Rename(tmpPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("failed to replace %q: %w (also failed to remove existing: %v)", path, err, removeErr)
		}
		if retryErr := os.Rename(tmpPath, path); retryErr != nil {
			return fmt.Errorf("failed to replace %q: %w", path, retryErr)
		}
	}
	return nil
}

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch the vault from the server",
	Run: func(_ *cobra.Command, _ []string) {
		if err := performFetch(); err != nil {
			cobra.CheckErr(err)
		}
	},
}

// performFetch syncs the vault from the server using apiClient and saves it to disk.
func performFetch() error {
	if apiClient == nil {
		return fmt.Errorf("api client not initialized. Run 'bx setup' or 'bx account add <name>'")
	}
	if apiClient.Token == "" {
		return fmt.Errorf("not logged in. Run 'bx login'")
	}

	fmt.Println("Fetching vault...")
	var syncResp *client.SyncResponse
	var raw []byte
	if err := withAutoLogin(func() error {
		var err error
		syncResp, raw, err = apiClient.Sync()
		return err
	}); err != nil {
		return err
	}

	vaultPath, err := vault.VaultPath()
	if err != nil {
		return err
	}

	if err := writeFileAtomic(vaultPath, raw); err != nil {
		return err
	}

	fmt.Printf("Vault fetched! %d ciphers, %d folders.\n", len(syncResp.Ciphers), len(syncResp.Folders))
	fmt.Printf("Vault saved to %s\n", vaultPath)
	return nil
}

func init() {
	rootCmd.AddCommand(fetchCmd)
}
