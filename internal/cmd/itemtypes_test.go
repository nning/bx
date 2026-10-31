package cmd

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nning/bx/internal/client"
	"github.com/spf13/cobra"
)

// newCreateTestCmd builds a fresh create command with its flags registered.
func newCreateTestCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "create", RunE: runCreate}
	addCreateFlags(cmd)
	return cmd
}

// newEditTestCmd builds a fresh edit command with its flags registered.
func newEditTestCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "edit", RunE: runEdit}
	cmd.Flags().StringP("name", "n", "", "")
	cmd.Flags().StringP("username", "u", "", "")
	cmd.Flags().StringP("password", "p", "", "")
	cmd.Flags().Bool("password-stdin", false, "")
	cmd.Flags().StringArrayP("url", "U", nil, "")
	cmd.Flags().StringArray("remove-url", nil, "")
	cmd.Flags().String("notes", "", "")
	cmd.Flags().StringP("organization", "o", "", "")
	cmd.Flags().StringArrayP("collection", "c", nil, "")
	cmd.Flags().StringP("totp", "t", "", "")
	cmd.Flags().String("folder", "", "")
	cmd.Flags().BoolP("force", "f", false, "")
	cmd.Flags().Bool("generate", false, "")
	addTypeFlags(cmd)
	cmd.Flags().BoolP("interactive", "i", false, "")
	return cmd
}

// ---------------------------------------------------------------------------
// validateTypeFlags
// ---------------------------------------------------------------------------

func TestValidateTypeFlags_CardRejectsLoginFlags(t *testing.T) {
	cmd := newCreateTestCmd(t)
	for _, f := range []string{"name", "brand", "number", "password"} {
		if err := cmd.Flags().Set(f, "x"); err != nil {
			t.Fatal(err)
		}
	}
	err := validateTypeFlags(cmd, client.CipherTypeCard, alwaysAllowedForCreate)
	if err == nil {
		t.Fatal("expected an error for --password on a card, got nil")
	}
	if !strings.Contains(err.Error(), "--password") || !strings.Contains(err.Error(), "card") {
		t.Errorf("error should name the flag and the type, got: %v", err)
	}
}

func TestValidateTypeFlags_CardAllowsOwnFlags(t *testing.T) {
	cmd := newCreateTestCmd(t)
	for _, f := range []string{"name", "cardholder", "brand", "number", "exp-month", "exp-year", "code", "notes"} {
		if err := cmd.Flags().Set(f, "x"); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateTypeFlags(cmd, client.CipherTypeCard, alwaysAllowedForCreate); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateTypeFlags_LoginAcceptsEverything(t *testing.T) {
	cmd := newCreateTestCmd(t)
	for _, f := range []string{"name", "username", "password", "url", "totp"} {
		if err := cmd.Flags().Set(f, "x"); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmd.Flags().Set("generate", "true"); err != nil {
		t.Fatal(err)
	}
	if err := validateTypeFlags(cmd, client.CipherTypeLogin, alwaysAllowedForCreate); err != nil {
		t.Errorf("login items accept every flag, got: %v", err)
	}
}

func TestValidateTypeFlags_IdentityAllowsUsername(t *testing.T) {
	cmd := newCreateTestCmd(t)
	for _, f := range []string{"name", "username", "email", "first-name"} {
		if err := cmd.Flags().Set(f, "x"); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateTypeFlags(cmd, client.CipherTypeIdentity, alwaysAllowedForCreate); err != nil {
		t.Errorf("identity items accept --username/--email, got: %v", err)
	}
}

func TestValidateTypeFlags_SshKeyAllowsPrivateKeyStdin(t *testing.T) {
	cmd := newCreateTestCmd(t)
	for _, f := range []string{"name", "private-key-stdin", "public-key"} {
		if err := cmd.Flags().Set(f, "true"); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateTypeFlags(cmd, client.CipherTypeSshKey, alwaysAllowedForCreate); err != nil {
		t.Errorf("ssh keys accept --private-key-stdin, got: %v", err)
	}
}

func TestValidateTypeFlags_EditAllowsFolderAndForce(t *testing.T) {
	cmd := newEditTestCmd(t)
	for _, f := range []string{"name", "folder", "cardholder"} {
		if err := cmd.Flags().Set(f, "x"); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmd.Flags().Set("force", "true"); err != nil {
		t.Fatal(err)
	}
	if err := validateTypeFlags(cmd, client.CipherTypeCard, alwaysAllowedForEdit); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// collectTypeFields / readSSHPrivateKeyStdin
// ---------------------------------------------------------------------------

func TestCollectTypeFields(t *testing.T) {
	cmd := newCreateTestCmd(t)
	for _, f := range []string{"name", "cardholder", "number", "exp-month", "code"} {
		if err := cmd.Flags().Set(f, "v-"+f); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmd.Flags().Set("type", "card"); err != nil {
		t.Fatal(err)
	}

	got := collectTypeFields(cmd, client.CipherTypeCard)
	if len(got) != 4 {
		t.Fatalf("got %d values, want 4: %v", len(got), got)
	}
	if got["cardholderName"] != "v-cardholder" || got["number"] != "v-number" ||
		got["expMonth"] != "v-exp-month" || got["code"] != "v-code" {
		t.Errorf("values: %v", got)
	}
	if _, ok := got["brand"]; ok {
		t.Error("unset flags must not appear")
	}
}

func TestCollectTypeFields_LoginReturnsEmpty(t *testing.T) {
	cmd := newCreateTestCmd(t)
	if got := collectTypeFields(cmd, client.CipherTypeLogin); len(got) != 0 {
		t.Errorf("login items have no type fields: %v", got)
	}
}

// ---------------------------------------------------------------------------
// buildEditCipher with a type object
// ---------------------------------------------------------------------------

// serverCardCipher builds the raw JSON of a card item as the server returns it.
func serverCardCipher(t *testing.T, key []byte) json.RawMessage {
	t.Helper()
	obj := map[string]any{
		"id":             "cipher-id",
		"organizationId": nil,
		"folderId":       nil,
		"type":           client.CipherTypeCard,
		"name":           encryptStr(t, key, "My card"),
		"notes":          nil,
		"favorite":       false,
		"reprompt":       0,
		"key":            nil,
		"revisionDate":   "2000-09-01T00:00:00.000000Z",
		"card": map[string]any{
			"cardholderName": encryptStr(t, key, "John Doe"),
			"brand":          encryptStr(t, key, "Visa"),
			"number":         encryptStr(t, key, "4111111111111111"),
			"expMonth":       encryptStr(t, key, "12"),
			"expYear":        encryptStr(t, key, "2027"),
			"code":           encryptStr(t, key, "123"),
		},
	}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBuildEditCipher_CardChange(t *testing.T) {
	key := testKey()
	raw := serverCardCipher(t, key)

	body, err := buildEditCipher(raw, cipherUpdate{
		TypeObj: "card",
		TypeFields: map[string]*string{
			"number": strPtr("5555444433332222"),
			"code":   strPtr("456"),
		},
	}, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	in, out := decodeObject(t, raw), decodeObject(t, body)

	card := decodeObject(t, out["card"])
	inCard := decodeObject(t, in["card"])
	if got := decryptJSONString(t, key, card["number"]); got != "5555444433332222" {
		t.Errorf("number: got %q", got)
	}
	if got := decryptJSONString(t, key, card["code"]); got != "456" {
		t.Errorf("code: got %q", got)
	}
	// Unchanged card fields keep their ciphertext.
	if compactJSON(t, card["cardholderName"]) != compactJSON(t, inCard["cardholderName"]) {
		t.Errorf("cardholderName re-encrypted although unchanged")
	}
	if compactJSON(t, card["brand"]) != compactJSON(t, inCard["brand"]) {
		t.Errorf("brand re-encrypted although unchanged")
	}
	// Everything outside the card object is untouched.
	if compactJSON(t, out["name"]) != compactJSON(t, in["name"]) {
		t.Errorf("name changed")
	}
}

func TestBuildEditCipher_CardClearField(t *testing.T) {
	key := testKey()
	raw := serverCardCipher(t, key)

	body, err := buildEditCipher(raw, cipherUpdate{
		TypeObj:    "card",
		TypeFields: map[string]*string{"code": strPtr("")},
	}, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	code := decodeObject(t, decodeObject(t, body)["card"])["code"]
	if string(code) != "null" {
		t.Errorf("code: got %s, want null", code)
	}
}

func TestBuildEditCipher_SshKeyChange(t *testing.T) {
	key := testKey()
	obj := map[string]any{
		"id":           "ssh-id",
		"type":         client.CipherTypeSshKey,
		"name":         encryptStr(t, key, "My key"),
		"revisionDate": "2000-09-01T00:00:00.000000Z",
		"sshKey": map[string]any{
			"privateKey":     encryptStr(t, key, "old-key"),
			"publicKey":      encryptStr(t, key, "ssh-ed25519 AAAA"),
			"keyFingerprint": encryptStr(t, key, "SHA256:old"),
		},
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	body, err := buildEditCipher(raw, cipherUpdate{
		TypeObj: "sshKey",
		TypeFields: map[string]*string{
			"privateKey":     strPtr("synthetic-private-key"),
			"keyFingerprint": strPtr("SHA256:new"),
		},
	}, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	ssh := decodeObject(t, decodeObject(t, body)["sshKey"])
	if got := decryptJSONString(t, key, ssh["privateKey"]); got != "synthetic-private-key" {
		t.Errorf("privateKey: got %q", got)
	}
	if got := decryptJSONString(t, key, ssh["keyFingerprint"]); got != "SHA256:new" {
		t.Errorf("keyFingerprint: got %q", got)
	}
	if got := decryptJSONString(t, key, ssh["publicKey"]); got != "ssh-ed25519 AAAA" {
		t.Errorf("publicKey: got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Editor round trip for non-login types
// ---------------------------------------------------------------------------

// makeCardCipher builds an encrypted card cipher for editor tests.
func makeCardCipher(t *testing.T, key []byte) client.Cipher {
	t.Helper()
	c := makeCipher(t, "card-id", "My card", "", key)
	c.Type = client.CipherTypeCard
	c.Card = &client.CipherCard{
		CardholderName: encryptStr(t, key, "John Doe"),
		Brand:          encryptStr(t, key, "Visa"),
		Number:         encryptStr(t, key, "4111111111111111"),
		ExpMonth:       encryptStr(t, key, "12"),
		ExpYear:        encryptStr(t, key, "2027"),
		Code:           encryptStr(t, key, "123"),
	}
	return c
}

func TestEditorRoundTrip_Card(t *testing.T) {
	key := testKey()
	c := makeCardCipher(t, key)

	original, err := decryptCipherToFields(&c, key)
	if err != nil {
		t.Fatalf("decryptCipherToFields: %v", err)
	}
	if original.TypeFields["number"] != "4111111111111111" || original.TypeFields["cardholderName"] != "John Doe" {
		t.Fatalf("type fields not decrypted: %v", original.TypeFields)
	}

	content := formatCipherForEditor(original)
	if !strings.Contains(content, "number: 4111111111111111\n") {
		t.Errorf("editor content missing number:\n%s", content)
	}
	if strings.Contains(content, "password:") || strings.Contains(content, "url:") {
		t.Errorf("a card must not show login fields:\n%s", content)
	}

	// Change the number and the CVV; everything else stays.
	edited := strings.Replace(content, "number: 4111111111111111", "number: 5555", 1)
	edited = strings.Replace(edited, "code: 123", "code: 456", 1)
	u := diffEditFields(parseCipherFromEditor(content, client.CipherTypeCard), parseCipherFromEditor(edited, client.CipherTypeCard))
	if u.TypeObj != "card" || u.TypeFields == nil {
		t.Fatalf("no type changes detected: %+v", u)
	}
	if len(u.TypeFields) != 2 || *u.TypeFields["number"] != "5555" || *u.TypeFields["code"] != "456" {
		t.Fatalf("type fields: %v", u.TypeFields)
	}
	if u.Name != nil || u.CustomFields != nil {
		t.Errorf("unexpected other changes: %+v", u)
	}

	body, err := buildEditCipher(serverCardCipher(t, key), u, testUserID, key, testNow)
	if err != nil {
		t.Fatalf("buildEditCipher: %v", err)
	}
	card := decodeObject(t, decodeObject(t, body)["card"])
	if got := decryptJSONString(t, key, card["number"]); got != "5555" {
		t.Errorf("number: got %q", got)
	}
	if got := decryptJSONString(t, key, card["cardholderName"]); got != "John Doe" {
		t.Errorf("cardholderName: got %q", got)
	}
}

func TestEditorRoundTrip_CardUnchangedHasNoDiff(t *testing.T) {
	key := testKey()
	c := makeCardCipher(t, key)

	original, err := decryptCipherToFields(&c, key)
	if err != nil {
		t.Fatalf("decryptCipherToFields: %v", err)
	}
	content := formatCipherForEditor(original)
	u := diffEditFields(parseCipherFromEditor(content, client.CipherTypeCard), parseCipherFromEditor(content, client.CipherTypeCard))
	if !u.isEmpty() {
		t.Errorf("an unedited card must produce no changes: %+v", u)
	}
}

func TestEditorRoundTrip_Identity(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "id-1", "My identity", "", key)
	c.Type = client.CipherTypeIdentity
	c.Identity = &client.CipherIdentity{
		FirstName: encryptStr(t, key, "John"),
		LastName:  encryptStr(t, key, "Doe"),
		Username:  encryptStr(t, key, "jdoe"),
	}

	original, err := decryptCipherToFields(&c, key)
	if err != nil {
		t.Fatalf("decryptCipherToFields: %v", err)
	}
	if original.TypeFields["firstName"] != "John" || original.TypeFields["username"] != "jdoe" {
		t.Fatalf("type fields: %v", original.TypeFields)
	}

	content := formatCipherForEditor(original)
	if !strings.Contains(content, "firstName: John\n") {
		t.Errorf("editor content missing firstName:\n%s", content)
	}

	edited := strings.Replace(content, "firstName: John", "firstName: Jane", 1)
	u := diffEditFields(parseCipherFromEditor(content, client.CipherTypeIdentity), parseCipherFromEditor(edited, client.CipherTypeIdentity))
	if u.TypeObj != "identity" || len(u.TypeFields) != 1 || *u.TypeFields["firstName"] != "Jane" {
		t.Fatalf("type fields: %v", u.TypeFields)
	}
}

func TestEditorRoundTrip_SshKeyMultilinePrivateKey(t *testing.T) {
	key := testKey()
	privateKey := "line one\nline two\nline three"
	c := makeCipher(t, "id-1", "My key", "", key)
	c.Type = client.CipherTypeSshKey
	c.SshKey = &client.CipherSshKey{
		PrivateKey: encryptStr(t, key, privateKey),
		PublicKey:  encryptStr(t, key, "ssh-ed25519 AAAA"),
	}

	original, err := decryptCipherToFields(&c, key)
	if err != nil {
		t.Fatalf("decryptCipherToFields: %v", err)
	}
	content := formatCipherForEditor(original)

	// A multi-line private key is written quoted and survives the round trip.
	if !strings.Contains(content, `privateKey: "line one\nline two\nline three"`) {
		t.Errorf("editor content missing quoted private key:\n%s", content)
	}

	u := diffEditFields(parseCipherFromEditor(content, client.CipherTypeSshKey), parseCipherFromEditor(content, client.CipherTypeSshKey))
	if !u.isEmpty() {
		t.Errorf("an unedited SSH key must produce no changes: %+v", u)
	}
}

// ---------------------------------------------------------------------------
// Editor against the server for a card
// ---------------------------------------------------------------------------

func TestEdit_AgainstServer_CardEdit(t *testing.T) {
	key := testKey()
	cardRaw := serverCardCipher(t, key)

	fake := &fakeCipherServer{t: t, state: decodeObject(t, cardRaw)}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	oldClient := apiClient
	apiClient = client.New(srv.URL)
	apiClient.Token = "test-token"
	t.Cleanup(func() { apiClient = oldClient })

	var local client.Cipher
	if err := json.Unmarshal(cardRaw, &local); err != nil {
		t.Fatal(err)
	}

	raw, serverCipher, editKey, err := fetchEditBase("My card", &local, false, key, nil)
	if err != nil {
		t.Fatalf("fetchEditBase: %v", err)
	}
	if err := sendEdit(&local, raw, cipherUpdate{
		TypeObj:    "card",
		TypeFields: map[string]*string{"number": strPtr("5555")},
	}, testUserID, editKey); err != nil {
		t.Fatalf("sendEdit: %v", err)
	}

	if got := decryptJSONString(t, key, decodeObject(t, fake.state["card"])["number"]); got != "5555" {
		t.Errorf("number: got %q", got)
	}
	if serverCipher == nil {
		t.Error("expected the server copy")
	}
}
