package cmd

import (
	"fmt"
	"strings"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/crypto"
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
)

// lockedForCompletion is the password function used while completing: it
// never prompts, so an interactive completion offers nothing instead of
// blocking the shell on a password prompt.
func lockedForCompletion() (string, error) {
	return "", fmt.Errorf("vault is locked")
}

// loadVaultForCompletion loads the vault with a cached session only.  Without
// an unlocked session — or when the vault file is missing — it returns
// ok=false, and the caller completes nothing.
func loadVaultForCompletion() (*client.SyncResponse, []byte, map[string][]byte, bool) {
	v, accountKey, orgKeys, _, err := vault.LoadVaultWithSession(unlockTimeoutMinutes(), lockedForCompletion)
	if err != nil {
		return nil, nil, nil, false
	}
	return v, accountKey, orgKeys, true
}

// itemCompletions completes item names for commands that take one item as
// their first argument.  It completes active items unless deleted is set, in
// which case it completes Trash items.  Without an unlocked session it
// completes nothing rather than prompting; names are decrypted in memory only
// and nothing else about the item is exposed.
func itemCompletions(deleted bool) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		v, accountKey, orgKeys, ok := loadVaultForCompletion()
		if !ok {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		resolver := newCipherKeyResolver(accountKey, orgKeys)
		prefix := strings.ToLower(toComplete)
		var names []string
		seen := map[string]bool{}
		for _, c := range v.Ciphers {
			if (c.DeletedDate != nil) != deleted {
				continue
			}
			nameBytes, err := crypto.Decrypt(cipherName(&c), resolver.key(c))
			if err != nil || len(nameBytes) == 0 {
				continue
			}
			name := string(nameBytes)
			if seen[name] || !strings.HasPrefix(strings.ToLower(name), prefix) {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

// folderNamesWithPrefix returns the decrypted names of all folders with the
// given (case-insensitive) prefix.
func folderNamesWithPrefix(folders []client.Folder, accountKey []byte, prefix string) []string {
	var names []string
	for _, f := range folders {
		b, err := crypto.Decrypt(f.Name, accountKey)
		if err != nil || len(b) == 0 {
			continue
		}
		name := string(b)
		if strings.HasPrefix(strings.ToLower(name), prefix) {
			names = append(names, name)
		}
	}
	return names
}

// folderCompletions completes folder names for commands that take one folder
// as their first argument.
func folderCompletions(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	v, accountKey, _, ok := loadVaultForCompletion()
	if !ok {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return folderNamesWithPrefix(v.Folders, accountKey, strings.ToLower(toComplete)), cobra.ShellCompDirectiveNoFileComp
}

// flagFolderCompletions completes folder names for the --folder flags.
func flagFolderCompletions(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	v, accountKey, _, ok := loadVaultForCompletion()
	if !ok {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return folderNamesWithPrefix(v.Folders, accountKey, strings.ToLower(toComplete)), cobra.ShellCompDirectiveNoFileComp
}

// registerFolderFlagCompletion registers flagFolderCompletions for cmd's
// --folder flag, which must already exist.  A missing flag is a wiring error
// and panics.
func registerFolderFlagCompletion(cmd *cobra.Command) {
	if err := cmd.RegisterFlagCompletionFunc("folder", flagFolderCompletions); err != nil {
		panic(err)
	}
}

func init() {
	getCmd.ValidArgsFunction = itemCompletions(false)
	editCmd.ValidArgsFunction = itemCompletions(false)
	deleteCmd.ValidArgsFunction = itemCompletions(false)
	restoreCmd.ValidArgsFunction = itemCompletions(true)
	folderRenameCmd.ValidArgsFunction = folderCompletions
	folderDeleteCmd.ValidArgsFunction = folderCompletions
}
