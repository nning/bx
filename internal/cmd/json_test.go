package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nning/bx/internal/client"
)

// ---------------------------------------------------------------------------
// buildJSONCipher
// ---------------------------------------------------------------------------

// makeLoginCipher builds an encrypted login cipher with a URI, TOTP, a custom
// field and a folder, using the given key.
func makeLoginCipher(t *testing.T, key []byte) client.Cipher {
	t.Helper()
	c := makeCipherWithUsername(t, "item-1", "GitHub", "alice@example.com", "https://github.com", key)
	c.Type = client.CipherTypeLogin
	c.Favorite = true
	c.RevisionDate = "2000-10-01T00:00:00Z"
	c.Login = &client.CipherLogin{
		Username: encryptStr(t, key, "alice@example.com"),
		URIs:     []client.CipherURI{{URI: encryptStr(t, key, "https://github.com")}},
	}
	totp := encryptStr(t, key, "JBSWY3DPEHPK3PXP")
	c.Login.Totp = &totp
	name := encryptStr(t, key, "API key")
	value := encryptStr(t, key, "ghp_secret")
	c.Fields = []client.CipherField{{Type: client.FieldTypeText, Name: &name, Value: value}}
	folderID := "folder-1"
	c.FolderID = &folderID
	return c
}

func TestBuildJSONCipher_Login(t *testing.T) {
	key := testKey()
	c := makeLoginCipher(t, key)

	j, err := buildJSONCipher(&c, key, key, &client.SyncResponse{}, nil, map[string]string{"folder-1": "Work"})
	if err != nil {
		t.Fatalf("buildJSONCipher: %v", err)
	}

	if j.ID != "item-1" || j.Type != "login" || j.Name != "GitHub" {
		t.Errorf("id/type/name: %q %q %q", j.ID, j.Type, j.Name)
	}
	if j.Username != "alice@example.com" {
		t.Errorf("username: %q", j.Username)
	}
	if j.Password != "" {
		t.Errorf("password: %q, want empty (no password set)", j.Password)
	}
	if j.TOTP != "JBSWY3DPEHPK3PXP" {
		t.Errorf("totp: %q", j.TOTP)
	}
	if len(j.URIs) != 1 || j.URIs[0].URI != "https://github.com" {
		t.Errorf("uris: %+v", j.URIs)
	}
	if len(j.Fields) != 1 || j.Fields[0].Name != "API key" || j.Fields[0].Value != "ghp_secret" || j.Fields[0].Type != "text" {
		t.Errorf("fields: %+v", j.Fields)
	}
	if !j.Favorite {
		t.Error("favorite: got false, want true")
	}
	if j.Folder != "Work" {
		t.Errorf("folder: %q", j.Folder)
	}
	if j.RevisionDate != "2000-10-01T00:00:00Z" {
		t.Errorf("revisionDate: %q", j.RevisionDate)
	}
}

func TestBuildJSONCipher_Password(t *testing.T) {
	key := testKey()
	c := makeCipherWithUsername(t, "item-1", "GitHub", "user", "", key)
	c.Type = client.CipherTypeLogin
	c.Login = &client.CipherLogin{Password: encryptStr(t, key, "s3cret")}

	j, err := buildJSONCipher(&c, key, key, &client.SyncResponse{}, nil, nil)
	if err != nil {
		t.Fatalf("buildJSONCipher: %v", err)
	}
	if j.Password != "s3cret" {
		t.Errorf("password: %q", j.Password)
	}
}

func TestBuildJSONCipher_Passkeys(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "GitHub", "", key)
	c.Type = client.CipherTypeLogin
	cred := client.Fido2Credential{
		CredentialId: encryptStr(t, key, "cred-1"),
		RpId:         encryptStr(t, key, "example.com"),
		RpName:       strPtr(encryptStr(t, key, "Example")),
		UserName:     strPtr(encryptStr(t, key, "alice@example.com")),
		Counter:      encryptStr(t, key, "3"),
		Discoverable: encryptStr(t, key, "true"),
		CreationDate: "2000-01-01T00:00:00Z",
	}
	c.Login = &client.CipherLogin{Fido2Credentials: []client.Fido2Credential{cred}}

	j, err := buildJSONCipher(&c, key, key, &client.SyncResponse{}, nil, nil)
	if err != nil {
		t.Fatalf("buildJSONCipher: %v", err)
	}
	if len(j.Passkeys) != 1 {
		t.Fatalf("passkeys: %+v", j.Passkeys)
	}
	p := j.Passkeys[0]
	if p.CredentialID != "cred-1" || p.RPID != "example.com" || p.Username != "alice@example.com" {
		t.Errorf("passkey: %+v", p)
	}
	if !p.Discoverable {
		t.Error("discoverable: got false, want true")
	}
	if p.Created != "2000-01-01T00:00:00Z" {
		t.Errorf("created: %q", p.Created)
	}
}

func TestBuildJSONCipher_Note(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "My note", "", key)
	c.Type = client.CipherTypeNote
	notes := encryptStr(t, key, "some secret notes")
	c.Notes = &notes

	j, err := buildJSONCipher(&c, key, key, &client.SyncResponse{}, nil, nil)
	if err != nil {
		t.Fatalf("buildJSONCipher: %v", err)
	}
	if j.Type != "note" || j.Notes != "some secret notes" {
		t.Errorf("type/notes: %q %q", j.Type, j.Notes)
	}
	if j.Username != "" || j.Password != "" {
		t.Errorf("a note must not carry login fields: %q %q", j.Username, j.Password)
	}
}

func TestBuildJSONCipher_Card(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "My card", "", key)
	c.Type = client.CipherTypeCard
	c.Card = &client.CipherCard{
		CardholderName: encryptStr(t, key, "John Doe"),
		Brand:          encryptStr(t, key, "Visa"),
		Number:         encryptStr(t, key, "4111111111111111"),
		ExpMonth:       encryptStr(t, key, "12"),
		ExpYear:        encryptStr(t, key, "2027"),
		Code:           encryptStr(t, key, "123"),
	}

	j, err := buildJSONCipher(&c, key, key, &client.SyncResponse{}, nil, nil)
	if err != nil {
		t.Fatalf("buildJSONCipher: %v", err)
	}
	if j.Card == nil {
		t.Fatal("card: got nil")
	}
	if j.Card.CardholderName != "John Doe" || j.Card.Brand != "Visa" ||
		j.Card.Number != "4111111111111111" || j.Card.ExpMonth != "12" ||
		j.Card.ExpYear != "2027" || j.Card.Code != "123" {
		t.Errorf("card: %+v", j.Card)
	}
}

func TestBuildJSONCipher_Identity(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "My identity", "", key)
	c.Type = client.CipherTypeIdentity
	c.Identity = &client.CipherIdentity{
		FirstName: encryptStr(t, key, "John"),
		LastName:  encryptStr(t, key, "Doe"),
		SSN:       encryptStr(t, key, "123-45-6789"),
	}

	j, err := buildJSONCipher(&c, key, key, &client.SyncResponse{}, nil, nil)
	if err != nil {
		t.Fatalf("buildJSONCipher: %v", err)
	}
	if j.Identity == nil {
		t.Fatal("identity: got nil")
	}
	if j.Identity.FirstName != "John" || j.Identity.LastName != "Doe" || j.Identity.SSN != "123-45-6789" {
		t.Errorf("identity: %+v", j.Identity)
	}
}

func TestBuildJSONCipher_SshKey(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "My key", "", key)
	c.Type = client.CipherTypeSshKey
	c.SshKey = &client.CipherSshKey{
		PrivateKey:     encryptStr(t, key, "synthetic-private-key"),
		PublicKey:      encryptStr(t, key, "ssh-ed25519 AAAA"),
		KeyFingerprint: encryptStr(t, key, "SHA256:abcdefgh"),
	}

	j, err := buildJSONCipher(&c, key, key, &client.SyncResponse{}, nil, nil)
	if err != nil {
		t.Fatalf("buildJSONCipher: %v", err)
	}
	if j.SSHKey == nil {
		t.Fatal("sshKey: got nil")
	}
	if j.SSHKey.PrivateKey != "synthetic-private-key" ||
		j.SSHKey.PublicKey != "ssh-ed25519 AAAA" ||
		j.SSHKey.Fingerprint != "SHA256:abcdefgh" {
		t.Errorf("sshKey: %+v", j.SSHKey)
	}
}

func TestBuildJSONCipher_AttachmentsAndLinkedField(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "Item", "", key)
	c.Type = client.CipherTypeLogin
	linkedName := encryptStr(t, key, "Account")
	linkedID := linkedIDUsername
	c.Fields = []client.CipherField{
		{Type: client.FieldTypeLinked, Name: &linkedName, Value: "", LinkedID: &linkedID},
	}
	c.Attachments = []client.CipherAttachment{
		{ID: "att-1", FileName: encryptStr(t, key, "report.pdf"), Size: json.Number("511")},
	}

	j, err := buildJSONCipher(&c, key, key, &client.SyncResponse{}, nil, nil)
	if err != nil {
		t.Fatalf("buildJSONCipher: %v", err)
	}
	if len(j.Fields) != 1 || j.Fields[0].Type != "linked" || j.Fields[0].Value != "username" {
		t.Errorf("linked field: %+v", j.Fields)
	}
	if len(j.Attachments) != 1 || j.Attachments[0].FileName != "report.pdf" || j.Attachments[0].Size != 511 {
		t.Errorf("attachments: %+v", j.Attachments)
	}
}

func TestBuildJSONCipher_DecryptErrorAborts(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "GitHub", "", key)
	c.Type = client.CipherTypeLogin
	c.Login = &client.CipherLogin{Username: "not-a-valid-cipher-string"}

	if _, err := buildJSONCipher(&c, key, key, &client.SyncResponse{}, nil, nil); err == nil {
		t.Fatal("expected an error for an undecryptable value, got nil")
	}
}

func TestBuildJSONCipher_CollectionsAndOrg(t *testing.T) {
	key := testKey()
	orgs, cols, orgKeys := familyVault(t)
	orgKey := orgKeys[orgs[0].ID]

	c := makeCipher(t, "item-1", "Example Service", "", orgKey)
	c.Type = client.CipherTypeLogin
	c.OrganizationID = &orgs[0].ID
	c.CollectionIDs = []string{cols[0].ID}

	j, err := buildJSONCipher(&c, orgKey, key, &client.SyncResponse{
		Profile:     client.Profile{Organizations: orgs},
		Collections: cols,
	}, orgKeys, nil)
	if err != nil {
		t.Fatalf("buildJSONCipher: %v", err)
	}
	if j.Organization != "Family" {
		t.Errorf("organization: %q", j.Organization)
	}
	if len(j.Collections) != 1 || j.Collections[0] != "Wife" {
		t.Errorf("collections: %v", j.Collections)
	}
}

// ---------------------------------------------------------------------------
// jsonListEntries
// ---------------------------------------------------------------------------

func TestJSONListEntries(t *testing.T) {
	rows := []listRow{
		{
			id:           "item-2",
			short:        "item-2",
			typeName:     "login",
			name:         "GitHub",
			lowerName:    "github",
			username:     "user",
			hasPasskey:   true,
			favorite:     true,
			folderID:     "folder-1",
			organization: "Family",
			revisionDate: "2000-10-01T00:00:00Z",
		},
		{
			id:           "item-1",
			short:        "item-1",
			typeName:     "note",
			name:         "Note",
			lowerName:    "note",
			revisionDate: "2000-09-01T00:00:00Z",
		},
	}

	entries := jsonListEntries(rows, map[string]string{"folder-1": "Work"})
	if len(entries) != 2 {
		t.Fatalf("entries: %d", len(entries))
	}
	first := entries[0]
	if first.ID != "item-2" || first.Type != "login" || first.Folder != "Work" ||
		first.Organization != "Family" || !first.Favorite || !first.HasPasskey {
		t.Errorf("entry 0: %+v", first)
	}
	second := entries[1]
	if second.Username != "" || second.Favorite || second.Folder != "" {
		t.Errorf("entry 1: %+v", second)
	}
}

func TestJSONListEntries_UnknownFolderFallsBackToShortID(t *testing.T) {
	rows := []listRow{{id: "item-1", short: "item-1", folderID: "unknown-folder", name: "X", lowerName: "x"}}
	entries := jsonListEntries(rows, nil)
	if entries[0].Folder != shortID("unknown-folder") {
		t.Errorf("folder: %q", entries[0].Folder)
	}
}

// ---------------------------------------------------------------------------
// cipherTypeName / jsonFieldType / buildHistoryJSON
// ---------------------------------------------------------------------------

func TestCipherTypeName(t *testing.T) {
	tests := []struct {
		typ  int
		want string
	}{
		{client.CipherTypeLogin, "login"},
		{client.CipherTypeNote, "note"},
		{client.CipherTypeCard, "card"},
		{client.CipherTypeIdentity, "identity"},
		{client.CipherTypeSshKey, "ssh-key"},
		{9, "type-9"},
	}
	for _, tc := range tests {
		if got := cipherTypeName(tc.typ); got != tc.want {
			t.Errorf("cipherTypeName(%d) = %q, want %q", tc.typ, got, tc.want)
		}
	}
}

func TestJSONFieldType(t *testing.T) {
	tests := []struct {
		typ  int
		want string
	}{
		{client.FieldTypeText, "text"},
		{client.FieldTypeHidden, "hidden"},
		{client.FieldTypeBoolean, "boolean"},
		{client.FieldTypeLinked, "linked"},
		{42, "text"},
	}
	for _, tc := range tests {
		if got := jsonFieldType(tc.typ); got != tc.want {
			t.Errorf("jsonFieldType(%d) = %q, want %q", tc.typ, got, tc.want)
		}
	}
}

func TestBuildHistoryJSON(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "GitHub", "", key)
	c.Type = client.CipherTypeLogin
	c.PasswordHistory = []client.CipherPasswordHistory{
		{Password: encryptStr(t, key, "old-pass"), LastUsedDate: "2000-09-25T00:00:00.000Z"},
		{Password: encryptStr(t, key, "older-pass"), LastUsedDate: "2000-08-25T00:00:00.000Z"},
	}

	entries, err := buildHistoryJSON(&c, key)
	if err != nil {
		t.Fatalf("buildHistoryJSON: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries: %d", len(entries))
	}
	if entries[0].Password != "old-pass" || entries[0].Date != "2000-09-25T00:00:00.000Z" {
		t.Errorf("entry 0: %+v", entries[0])
	}
	if entries[1].Password != "older-pass" {
		t.Errorf("entry 1: %+v", entries[1])
	}
}

func TestBuildHistoryJSON_NoHistory(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "GitHub", "", key)
	if _, err := buildHistoryJSON(&c, key); err == nil {
		t.Fatal("expected error for item without password history, got nil")
	}
}

func TestBuildHistoryJSON_DecryptError(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "GitHub", "", key)
	c.PasswordHistory = []client.CipherPasswordHistory{
		{Password: "not-a-valid-cipher-string", LastUsedDate: "2000-09-25T00:00:00.000Z"},
	}
	if _, err := buildHistoryJSON(&c, key); err == nil {
		t.Fatal("expected error for undecryptable history entry, got nil")
	}
}

// ---------------------------------------------------------------------------
// Output shape
// ---------------------------------------------------------------------------

// TestJSONCipherMarshalStable verifies that the marshalled record only
// contains the documented fields and that absent values are omitted.
func TestJSONCipherMarshalStable(t *testing.T) {
	key := testKey()
	c := makeLoginCipher(t, key)
	j, err := buildJSONCipher(&c, key, key, &client.SyncResponse{}, nil, map[string]string{"folder-1": "Work"})
	if err != nil {
		t.Fatalf("buildJSONCipher: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(compactJSONObj(t, j)), &raw); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, k := range []string{"id", "type", "name", "favorite", "revisionDate"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("missing key %q in JSON output", k)
		}
	}
	for _, k := range []string{"password", "deletedDate", "organization", "collections", "passkeys", "card"} {
		if _, ok := raw[k]; ok {
			t.Errorf("absent value %q must be omitted, got %v", k, raw[k])
		}
	}
}

// compactJSONObj marshals v to compact JSON for a stable comparison.
func compactJSONObj(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// TestJSONListEntriesMarshalsArray verifies that the list JSON is an array of
// objects.
func TestJSONListEntriesMarshalsArray(t *testing.T) {
	rows := []listRow{{id: "item-1", short: "item-1", name: "X", lowerName: "x", typeName: "login", revisionDate: "2000-10-01"}}
	b := compactJSONObj(t, jsonListEntries(rows, nil))
	if !strings.HasPrefix(b, "[") || !strings.Contains(b, `"type":"login"`) {
		t.Errorf("unexpected list JSON: %s", b)
	}
}
