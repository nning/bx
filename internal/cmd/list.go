package cmd

import (
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

// cipherMatchesPattern reports whether cipher should be included when the list
// is filtered by pattern. pattern, lowerName and lowerUsername are already
// lower-cased and decrypted. It checks the name first, then the username, and
// only decrypts the URIs when neither matches. An empty pattern always returns
// true.
func cipherMatchesPattern(lowerName, lowerUsername string, cipher *client.Cipher, key []byte, pattern string) bool {
	if pattern == "" {
		return true
	}
	if strings.Contains(lowerName, pattern) {
		return true
	}
	if strings.Contains(lowerUsername, pattern) {
		return true
	}
	var uris []string
	for _, u := range cipherURIs(cipher) {
		uriBytes, err := crypto.Decrypt(u.URI, key)
		if err == nil && len(uriBytes) > 0 {
			uris = append(uris, string(uriBytes))
		}
	}
	return matchByURL(uris, pattern)
}

type listRow struct {
	id           string // full UUID
	short        string // first UUID segment, for the table
	typeName     string
	name         string
	lowerName    string
	username     string
	hasPasskey   bool
	favorite     bool
	folderID     string
	organization string
	revisionDate string
	deletedDate  *string
}

func sortListRows(rows []listRow) {
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

// jsonListEntries turns sorted rows into the entries printed by
// `bx list --json`, resolving folder IDs to their decrypted names.
func jsonListEntries(rows []listRow, folderNames map[string]string) []jsonListEntry {
	entries := make([]jsonListEntry, 0, len(rows))
	for _, row := range rows {
		e := jsonListEntry{
			ID:           row.id,
			Type:         row.typeName,
			Name:         row.name,
			Username:     row.username,
			HasPasskey:   row.hasPasskey,
			Favorite:     row.favorite,
			Organization: row.organization,
			RevisionDate: row.revisionDate,
			DeletedDate:  row.deletedDate,
		}
		if row.folderID != "" {
			e.Folder = folderNames[row.folderID]
			if e.Folder == "" {
				e.Folder = shortID(row.folderID)
			}
		}
		entries = append(entries, e)
	}
	return entries
}

var listCmd = &cobra.Command{
	Use:     "list [pattern]",
	Aliases: []string{"find"},
	Short:   "List vault items (alias: find)",
	Args:    cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var pattern string
		if len(args) == 1 {
			pattern = strings.ToLower(args[0])
		}
		deleted, _ := cmd.Flags().GetBool("deleted")
		v, accountKey, orgKeys, _, err := vault.LoadVaultWithSession(unlockTimeoutMinutes(), readPassword)
		if err != nil {
			cobra.CheckErr(err)
		}

		rows := make([]listRow, 0, len(v.Ciphers))
		resolver := newCipherKeyResolver(accountKey, orgKeys)
		jsonOut, _ := cmd.Flags().GetBool("json")
		var folderNames map[string]string
		if jsonOut {
			folderNames = folderNamesForJSON(v.Folders, accountKey)
		}

		for _, cipher := range v.Ciphers {
			if deleted {
				if cipher.DeletedDate == nil {
					continue
				}
			} else {
				if cipher.DeletedDate != nil {
					continue
				}
			}

			keyToUse := resolver.key(cipher)

			nameBytes, err := crypto.Decrypt(cipherName(&cipher), keyToUse)
			name := string(nameBytes)
			if err != nil {
				name = "[Decryption Error]"
			}

			var username string
			usernameBytes, err := crypto.Decrypt(cipherUsername(&cipher), keyToUse)
			if err != nil {
				username = "[Decryption Error]"
			} else {
				username = string(usernameBytes)
			}

			lowerName := strings.ToLower(name)
			if !cipherMatchesPattern(lowerName, strings.ToLower(username), &cipher, keyToUse, pattern) {
				continue
			}

			row := listRow{
				id:           cipher.ID,
				short:        shortID(cipher.ID),
				typeName:     cipherTypeName(cipher.Type),
				name:         name,
				lowerName:    lowerName,
				username:     username,
				hasPasskey:   len(cipherFido2Credentials(&cipher)) > 0,
				favorite:     cipher.Favorite,
				revisionDate: cipher.RevisionDate,
				deletedDate:  cipher.DeletedDate,
			}
			if cipher.FolderID != nil {
				row.folderID = *cipher.FolderID
			}
			if cipher.OrganizationID != nil {
				row.organization = orgNameByID(v.Profile.Organizations, *cipher.OrganizationID)
			}
			rows = append(rows, row)
		}

		sortListRows(rows)

		if jsonOut {
			printJSON(jsonListEntries(rows, folderNames))
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if _, err := fmt.Fprintln(w, "ID\tTYPE\tNAME\tUSERNAME\tPASSKEY"); err != nil {
			cobra.CheckErr(err)
		}
		for _, row := range rows {
			pk := "-"
			if row.hasPasskey {
				pk = "yes"
			}
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", row.short, row.typeName, row.name, row.username, pk); err != nil {
				cobra.CheckErr(err)
			}
		}
		if err := w.Flush(); err != nil {
			cobra.CheckErr(err)
		}
	},
}

func init() {
	listCmd.Flags().Bool("deleted", false, "List only Trash items (soft-deleted)")
	listCmd.Flags().Bool("json", false, "Print the list as JSON (stable schema; see README)")
	rootCmd.AddCommand(listCmd)
}
