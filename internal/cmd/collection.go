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

// orgNameByID returns the plaintext name of the organization with the given ID.
// Falls back to the short ID when the organization is not part of the profile
// (e.g. the vault cache predates joining it).  Returns "" for an empty ID.
func orgNameByID(orgs []client.ProfileOrganization, id string) string {
	if id == "" {
		return ""
	}
	for _, org := range orgs {
		if org.ID == id {
			if org.Name != "" {
				return org.Name
			}
			break
		}
	}
	return shortID(id)
}

// findOrganization resolves an organization flag value to a profile
// organization.  The value may be a full UUID, the short form (first UUID
// segment), or the organization name (case-insensitive).  An error is returned
// when a short ID matches more than one organization; nil, nil is returned when
// nothing matches.
func findOrganization(flagVal string, orgs []client.ProfileOrganization) (*client.ProfileOrganization, error) {
	// Exact ID pass.
	for _, org := range orgs {
		if org.ID == flagVal {
			match := org
			return &match, nil
		}
	}
	// Short-ID pass: collect all matches before deciding.
	var shortMatches []client.ProfileOrganization
	for _, org := range orgs {
		if shortID(org.ID) == flagVal {
			shortMatches = append(shortMatches, org)
		}
	}
	if len(shortMatches) == 1 {
		return &shortMatches[0], nil
	}
	if len(shortMatches) > 1 {
		return nil, fmt.Errorf("ambiguous short ID %q: use the full UUID to disambiguate", flagVal)
	}
	// Name pass.
	for _, org := range orgs {
		if org.Name != "" && strings.EqualFold(org.Name, flagVal) {
			match := org
			return &match, nil
		}
	}
	return nil, nil
}

// collectionName returns the decrypted name of a collection.  Collection names
// are encrypted with the owning organization's symmetric key, so orgKeys must
// contain a key for the collection's organization.  Returns "" when the key is
// missing or decryption fails.
func collectionName(col client.Collection, orgKeys map[string][]byte) string {
	orgKey, ok := orgKeys[col.OrganizationID]
	if !ok {
		return ""
	}
	nameBytes, err := crypto.Decrypt(col.Name, orgKey)
	if err != nil {
		return ""
	}
	return string(nameBytes)
}

// collectionNames maps collection IDs to their decrypted names, preserving the
// order of ids.  IDs that are unknown locally (or whose name cannot be
// decrypted) fall back to their short ID so that output is never empty.
func collectionNames(ids []string, cols []client.Collection, orgKeys map[string][]byte) []string {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		name := ""
		for _, col := range cols {
			if col.ID == id {
				name = collectionName(col, orgKeys)
				break
			}
		}
		if name == "" {
			name = shortID(id)
		}
		names = append(names, name)
	}
	return names
}

// findCollections resolves collection flag values to collections of the given
// organization.  Each value may be a full UUID, the short form (first UUID
// segment), or the decrypted collection name (case-insensitive).  Duplicate
// values are collapsed while preserving the order in which they were given.
//
// Only collections belonging to orgID are considered, so a name that exists in
// several organizations is never ambiguous across them.  An error is returned
// for values that match nothing or more than one collection.
func findCollections(flagVals []string, cols []client.Collection, orgID string, orgKeys map[string][]byte) ([]client.Collection, error) {
	orgCols := make([]client.Collection, 0, len(cols))
	for _, col := range cols {
		if col.OrganizationID == orgID {
			orgCols = append(orgCols, col)
		}
	}

	resolved := make([]client.Collection, 0, len(flagVals))
	seen := make(map[string]struct{}, len(flagVals))

	for _, val := range flagVals {
		val = strings.TrimSpace(val)
		if val == "" {
			return nil, fmt.Errorf("empty collection name")
		}

		match, err := matchCollection(val, orgCols, orgKeys)
		if err != nil {
			return nil, err
		}
		if match == nil {
			return nil, fmt.Errorf("collection not found in this organization: %s (run 'bx collection list' to see available collections)", val)
		}
		if _, dup := seen[match.ID]; dup {
			continue
		}
		seen[match.ID] = struct{}{}
		resolved = append(resolved, *match)
	}

	return resolved, nil
}

// matchCollection resolves a single collection value against orgCols by ID,
// short ID, and finally decrypted name.  Returns nil, nil when nothing matches.
func matchCollection(val string, orgCols []client.Collection, orgKeys map[string][]byte) (*client.Collection, error) {
	// Exact ID pass.
	for _, col := range orgCols {
		if col.ID == val {
			match := col
			return &match, nil
		}
	}
	// Short-ID pass: collect all matches before deciding.
	var shortMatches []client.Collection
	for _, col := range orgCols {
		if shortID(col.ID) == val {
			shortMatches = append(shortMatches, col)
		}
	}
	if len(shortMatches) == 1 {
		return &shortMatches[0], nil
	}
	if len(shortMatches) > 1 {
		return nil, fmt.Errorf("ambiguous short ID %q: use the full UUID to disambiguate", val)
	}
	// Name pass: reject duplicate names rather than picking one at random.
	var nameMatches []client.Collection
	for _, col := range orgCols {
		if name := collectionName(col, orgKeys); name != "" && strings.EqualFold(name, val) {
			nameMatches = append(nameMatches, col)
		}
	}
	if len(nameMatches) == 1 {
		return &nameMatches[0], nil
	}
	if len(nameMatches) > 1 {
		return nil, fmt.Errorf("ambiguous collection name %q: %d collections share it, use the ID instead", val, len(nameMatches))
	}
	return nil, nil
}

type collectionRow struct {
	id        string
	org       string
	lowerOrg  string
	name      string
	lowerName string
}

func sortCollectionRows(rows []collectionRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].lowerOrg != rows[j].lowerOrg {
			return rows[i].lowerOrg < rows[j].lowerOrg
		}
		if rows[i].lowerName != rows[j].lowerName {
			return rows[i].lowerName < rows[j].lowerName
		}
		return rows[i].id < rows[j].id
	})
}

var collectionCmd = &cobra.Command{
	Use:     "collection",
	Aliases: []string{"collections"},
	Short:   "Manage organization collections (alias: collections)",
}

var collectionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List organization collections",
	RunE:  runCollectionList,
}

func runCollectionList(cmd *cobra.Command, _ []string) error {
	orgFlag, _ := cmd.Flags().GetString("organization")

	v, _, orgKeys, _, err := vault.LoadVaultWithSession(unlockTimeoutMinutes(), readPassword)
	if err != nil {
		return err
	}

	filterOrgID := ""
	if orgFlag != "" {
		org, err := findOrganization(orgFlag, v.Profile.Organizations)
		if err != nil {
			return err
		}
		if org == nil {
			return fmt.Errorf("organization not found: %s", orgFlag)
		}
		filterOrgID = org.ID
	}

	rows := make([]collectionRow, 0, len(v.Collections))
	for _, col := range v.Collections {
		if filterOrgID != "" && col.OrganizationID != filterOrgID {
			continue
		}
		name := collectionName(col, orgKeys)
		if name == "" {
			name = "[Decryption Error]"
		}
		org := orgNameByID(v.Profile.Organizations, col.OrganizationID)
		rows = append(rows, collectionRow{
			id:        shortID(col.ID),
			org:       org,
			lowerOrg:  strings.ToLower(org),
			name:      name,
			lowerName: strings.ToLower(name),
		})
	}

	sortCollectionRows(rows)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "ID\tORGANIZATION\tNAME"); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", row.id, row.org, row.name); err != nil {
			return err
		}
	}

	return w.Flush()
}

func init() {
	collectionListCmd.Flags().StringP("organization", "o", "", "Only list collections of this organization (name or ID)")

	collectionCmd.AddCommand(collectionListCmd)
	rootCmd.AddCommand(collectionCmd)
}
