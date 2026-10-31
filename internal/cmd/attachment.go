package cmd

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// maxAttachmentBytes caps the size of an attachment file read into memory,
// matching the cap on API responses.
const maxAttachmentBytes = 100*1024*1024 - 65

var attachmentCmd = &cobra.Command{
	Use:   "attachment",
	Short: "Manage item attachments",
}

var attachmentListCmd = &cobra.Command{
	Use:   "list <id|name>",
	Short: "List an item's attachments",
	Args:  cobra.ExactArgs(1),
	RunE:  runAttachmentList,
}

var attachmentGetCmd = &cobra.Command{
	Use:   "get <id|name> <file>",
	Short: "Download and decrypt an attachment",
	Args:  cobra.ExactArgs(2),
	RunE:  runAttachmentGet,
}

var attachmentAddCmd = &cobra.Command{
	Use:   "add <id|name> <file>",
	Short: "Attach a file to an item",
	Args:  cobra.ExactArgs(2),
	RunE:  runAttachmentAdd,
}

// loadItemForAttachments loads the vault, finds the item an attachment
// command acts on, and resolves its key.
func loadItemForAttachments(pattern string) (*client.Cipher, []byte, error) {
	v, accountKey, orgKeys, _, err := vault.LoadVaultWithSession(unlockTimeoutMinutes(), readPassword)
	if err != nil {
		return nil, nil, err
	}
	found, err := findCipher(pattern, v.Ciphers, accountKey, orgKeys)
	if err != nil {
		return nil, nil, err
	}
	if found == nil {
		return nil, nil, fmt.Errorf("item not found: %s", pattern)
	}
	return found, cipherKey(*found, accountKey, orgKeys), nil
}

// findAttachment resolves an attachment by ID or by its decrypted file name
// (both case-insensitive).  Returns nil when nothing matches.
func findAttachment(c *client.Cipher, itemKey []byte, pattern string) (*client.CipherAttachment, error) {
	for i := range c.Attachments {
		a := &c.Attachments[i]
		if strings.EqualFold(a.ID, pattern) {
			return a, nil
		}
		name, err := crypto.Decrypt(a.FileName, itemKey)
		if err == nil && strings.EqualFold(string(name), pattern) {
			return a, nil
		}
	}
	return nil, nil
}

// humanSize formats a byte count for humans (e.g. "1.5 MiB").  The units stop
// at exabytes: a size beyond that clamps to the last unit instead of indexing
// past the end of the lookup, so a tampered vault cache cannot crash bx.
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	const units = "KMGTPE"
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < len(units)-1; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), units[exp])
}

func runAttachmentList(cmd *cobra.Command, args []string) error {
	found, itemKey, err := loadItemForAttachments(args[0])
	if err != nil {
		return err
	}

	if len(found.Attachments) == 0 {
		return fmt.Errorf("item has no attachments: %s", args[0])
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "ID\tNAME\tSIZE"); err != nil {
		return err
	}
	for _, a := range found.Attachments {
		name, err := crypto.Decrypt(a.FileName, itemKey)
		if err != nil {
			name = []byte("[Decryption Error]")
		}
		size, _ := a.Size.Int64()
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", a.ID, string(name), humanSize(size)); err != nil {
			return err
		}
	}
	return w.Flush()
}

// attachmentKey decrypts the attachment's own key with the item key.
func attachmentKey(att *client.CipherAttachment, itemKey []byte) ([]byte, error) {
	raw, err := crypto.Decrypt(att.Key, itemKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt the attachment key: %w", err)
	}
	key, err := crypto.NormalizeSymmetricKey(raw)
	if err != nil {
		return nil, fmt.Errorf("attachment key: %w", err)
	}
	return key, nil
}

// safeAttachmentName returns the basename of an attachment's file name, and
// rejects names that reduce to nothing or to a directory reference, so that a
// tampered vault cache cannot write outside the chosen directory.
func safeAttachmentName(name string) (string, error) {
	base := filepath.Base(name)
	if base == "." || base == ".." || base == "/" || base == "" {
		return "", fmt.Errorf("attachment has an unusable file name: %q", name)
	}
	return base, nil
}

func runAttachmentGet(cmd *cobra.Command, args []string) error {
	if apiClient == nil {
		return fmt.Errorf("api client not initialized. Run 'bx setup' or 'bx account add <name>'")
	}
	found, itemKey, err := loadItemForAttachments(args[0])
	if err != nil {
		return err
	}

	att, err := findAttachment(found, itemKey, args[1])
	if err != nil {
		return err
	}
	if att == nil {
		return fmt.Errorf("attachment not found: %s", args[1])
	}

	key, err := attachmentKey(att, itemKey)
	if err != nil {
		return err
	}

	var data []byte
	if err := withAutoLogin(func() error {
		var err error
		data, err = apiClient.GetAttachment(found.ID, att.ID)
		return err
	}); err != nil {
		return fmt.Errorf("failed to download attachment: %w", err)
	}

	plaintext, err := crypto.DecryptAttachment(data, key)
	crypto.Wipe(key)
	if err != nil {
		return fmt.Errorf("failed to decrypt attachment: %w", err)
	}

	output, _ := cmd.Flags().GetString("output")
	force, _ := cmd.Flags().GetBool("force")
	return writeAttachment(plaintext, att, itemKey, output, force)
}

// writeAttachment writes the decrypted attachment to --output, to stdout when
// it is piped and no --output was given (or --output -), or to a file named
// after the attachment in the working directory.  Files are written with 0600
// and an existing file is only overwritten with --force.
func writeAttachment(plaintext []byte, att *client.CipherAttachment, itemKey []byte, output string, force bool) error {
	if output == "-" {
		if _, err := os.Stdout.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write attachment to stdout: %w", err)
		}
		return nil
	}
	if output != "" {
		return writeAttachmentFile(plaintext, output, force)
	}

	if !term.IsTerminal(int(os.Stdout.Fd())) {
		if _, err := os.Stdout.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write attachment to stdout: %w", err)
		}
		return nil
	}

	name, err := crypto.Decrypt(att.FileName, itemKey)
	if err != nil || len(name) == 0 {
		name = []byte(att.ID)
	}
	base, err := safeAttachmentName(string(name))
	if err != nil {
		return err
	}
	return writeAttachmentFile(plaintext, base, force)
}

// writeAttachmentFile writes privately and publishes the complete file atomically.
// Replacing a path never follows its symlink or modifies a hard-linked inode.
func writeAttachmentFile(plaintext []byte, path string, force bool) error {
	if info, err := os.Lstat(path); err == nil {
		if !force {
			return fmt.Errorf("%s already exists; use --force to overwrite it", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file (symlinks are refused)", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".bx_attachment_*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer func() { _ = os.Remove(temp) }()
	if _, err := f.Write(plaintext); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if force {
		if err := os.Rename(temp, path); err != nil {
			return fmt.Errorf("failed to replace attachment: %w", err)
		}
	} else {
		// Link publishes without replacing a path created by another process.
		if err := os.Link(temp, path); err != nil {
			return fmt.Errorf("failed to create attachment (destination must not exist): %w", err)
		}
	}
	fmt.Printf("Saved attachment: %s\n", path)
	return nil
}

// runAttachmentAdd attaches a file to an item using the server's two-step v2
// flow: a random 64-byte attachment key is generated, encrypted with the item
// key and registered with the encrypted file name; then the encrypted file is
// uploaded to the URL the server returned.
func runAttachmentAdd(cmd *cobra.Command, args []string) error {
	if apiClient == nil {
		return fmt.Errorf("api client not initialized. Run 'bx setup' or 'bx account add <name>'")
	}
	if apiClient.Token == "" {
		return fmt.Errorf("not logged in. Run 'bx login'")
	}

	itemPattern, filePath := args[0], args[1]

	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", filePath, err)
	}
	if info.Size() > maxAttachmentBytes {
		return fmt.Errorf("%s is too large: %d bytes (at most %d are supported)", filePath, info.Size(), maxAttachmentBytes)
	}
	// The file is read with the size cap applied, so a file that grows between
	// Stat and the read cannot blow past the limit.
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", filePath, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxAttachmentBytes+1))
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("could not read %s: %w", filePath, err)
	}
	if len(data) > maxAttachmentBytes {
		return fmt.Errorf("%s is too large: at most %d bytes are supported", filePath, maxAttachmentBytes)
	}

	v, accountKey, orgKeys, _, err := vault.LoadVaultWithSession(unlockTimeoutMinutes(), readPassword)
	if err != nil {
		return err
	}
	found, err := findCipher(itemPattern, v.Ciphers, accountKey, orgKeys)
	if err != nil {
		return err
	}
	if found == nil {
		return fmt.Errorf("item not found: %s", itemPattern)
	}
	itemKey := cipherKey(*found, accountKey, orgKeys)

	itemName := itemPattern
	if nameBytes, err := crypto.Decrypt(cipherName(found), itemKey); err == nil && len(nameBytes) > 0 {
		itemName = string(nameBytes)
	}

	// The attachment key is a fresh 64-byte key (32 enc + 32 mac), wrapped
	// with the item key like the official clients wrap it.
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate the attachment key: %w", err)
	}
	defer crypto.Wipe(key)

	encKey, err := crypto.Encrypt(key, itemKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt the attachment key: %w", err)
	}
	encFileName, err := crypto.Encrypt([]byte(filepath.Base(filePath)), itemKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt the file name: %w", err)
	}

	encData, err := crypto.EncryptAttachment(data, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt the file: %w", err)
	}

	var upload *client.AttachmentFileUploadResponse
	if err := withAutoLogin(func() error {
		var err error
		upload, err = apiClient.CreateAttachmentV2(found.ID, client.AttachmentUploadRequest{
			FileName: encFileName,
			FileSize: int64(len(encData)),
			Key:      encKey,
		})
		return err
	}); err != nil {
		return fmt.Errorf("failed to register the attachment: %w", err)
	}

	if err := withAutoLogin(func() error {
		return apiClient.UploadAttachmentFile(upload, encData)
	}); err != nil {
		return fmt.Errorf("failed to upload the attachment: %w", err)
	}

	// Refresh the cached item from the server so that the attachment shows up
	// in `bx attachment list` without a fetch.
	updated, err := fetchCipherForCache(found.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: attachment uploaded but the local cache update failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run 'bx fetch' to sync the local cache.\n")
	} else if err := vault.PatchCipher(vault.PatchCipherEdit, updated); err != nil {
		fmt.Fprintf(os.Stderr, "warning: attachment uploaded but the local cache update failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run 'bx fetch' to sync the local cache.\n")
	}

	fmt.Printf("Attached: %s (%s) to %s\n", filepath.Base(filePath), humanSize(int64(len(data))), itemName)
	return nil
}

// fetchCipherForCache fetches a cipher from the server for the local cache,
// refreshing the session if it expired.
func fetchCipherForCache(id string) (*client.Cipher, error) {
	var updated *client.Cipher
	if err := withAutoLogin(func() error {
		var err error
		updated, err = apiClient.GetCipher(id)
		return err
	}); err != nil {
		return nil, err
	}
	return updated, nil
}

func init() {
	attachmentGetCmd.Flags().StringP("output", "o", "", "Write the file to this path instead of the working directory (use \"-\" for stdout)")
	attachmentGetCmd.Flags().BoolP("force", "f", false, "Overwrite an existing file")
	attachmentGetCmd.ValidArgsFunction = attachmentNameCompletions
	attachmentListCmd.ValidArgsFunction = itemCompletions(false)
	attachmentAddCmd.ValidArgsFunction = itemCompletions(false)

	attachmentCmd.AddCommand(attachmentListCmd)
	attachmentCmd.AddCommand(attachmentGetCmd)
	attachmentCmd.AddCommand(attachmentAddCmd)
	rootCmd.AddCommand(attachmentCmd)
}

// attachmentNameCompletions completes attachment names for the second argument
// of `bx attachment get`, using the cached vault.
func attachmentNameCompletions(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return itemCompletions(false)(nil, args, toComplete)
	}
	if len(args) > 1 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	v, accountKey, orgKeys, ok := loadVaultForCompletion()
	if !ok {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	found, err := findCipher(args[0], v.Ciphers, accountKey, orgKeys)
	if err != nil || found == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	itemKey := cipherKey(*found, accountKey, orgKeys)
	prefix := strings.ToLower(toComplete)
	var names []string
	for _, a := range found.Attachments {
		b, err := crypto.Decrypt(a.FileName, itemKey)
		if err != nil || len(b) == 0 {
			continue
		}
		name := string(b)
		if strings.HasPrefix(strings.ToLower(name), prefix) {
			names = append(names, name)
		}
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}
