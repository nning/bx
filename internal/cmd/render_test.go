package cmd

import (
	"strings"
	"testing"

	"github.com/nning/bx/internal/client"
)

// TestRenderRecord_Login verifies the login record layout, including URLs,
// notes and custom fields.
func TestRenderRecord_Login(t *testing.T) {
	key := testKey()
	c := makeLoginCipher(t, key)
	notes := encryptStr(t, key, "work account")
	c.Notes = &notes

	out := renderRecord(&c, key, &client.SyncResponse{}, nil, "fallback")
	for _, want := range []string{
		"Name:     GitHub\n",
		"Username: alice@example.com\n",
		"Password: \n",
		"URL:      https://github.com\n",
		"Notes:    work account\n",
		"API key:  ghp_secret\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderRecord_LoginOwnerLine(t *testing.T) {
	orgs, cols, orgKeys := familyVault(t)
	orgKey := orgKeys[orgs[0].ID]

	c := makeCipher(t, "item-1", "Example Service", "", orgKey)
	c.Type = client.CipherTypeLogin
	c.OrganizationID = &orgs[0].ID
	c.CollectionIDs = []string{cols[0].ID}

	out := renderRecord(&c, orgKey, &client.SyncResponse{
		Profile:     client.Profile{Organizations: orgs},
		Collections: cols,
	}, orgKeys, "fallback")
	if !strings.Contains(out, "Owner:    Family (Wife)\n") {
		t.Errorf("missing owner line in:\n%s", out)
	}
}

func TestRenderRecord_Note(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "My note", "", key)
	c.Type = client.CipherTypeNote
	notes := encryptStr(t, key, "secret note body")
	c.Notes = &notes

	out := renderRecord(&c, key, &client.SyncResponse{}, nil, "fallback")
	if !strings.Contains(out, "Name:     My note\n") {
		t.Errorf("missing name in:\n%s", out)
	}
	if !strings.Contains(out, "Notes:    secret note body\n") {
		t.Errorf("missing notes in:\n%s", out)
	}
	if strings.Contains(out, "Password") || strings.Contains(out, "Username") {
		t.Errorf("a note must not print login fields:\n%s", out)
	}
}

func TestRenderRecord_Card(t *testing.T) {
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

	out := renderRecord(&c, key, &client.SyncResponse{}, nil, "fallback")
	for _, want := range []string{
		"Cardholder: John Doe\n",
		"Brand:    Visa\n",
		"Number:   4111111111111111\n",
		"Expiry:   12/2027\n",
		"Code:     123\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderRecord_Identity(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "My identity", "", key)
	c.Type = client.CipherTypeIdentity
	c.Identity = &client.CipherIdentity{
		Title:     encryptStr(t, key, "Dr."),
		FirstName: encryptStr(t, key, "John"),
		LastName:  encryptStr(t, key, "Doe"),
		City:      encryptStr(t, key, "Berlin"),
		SSN:       encryptStr(t, key, "123-45-6789"),
	}

	out := renderRecord(&c, key, &client.SyncResponse{}, nil, "fallback")
	for _, want := range []string{
		"Title:    Dr.\n",
		"First name: John\n",
		"Last name: Doe\n",
		"City:     Berlin\n",
		"SSN:      123-45-6789\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderRecord_SshKey(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "My key", "", key)
	c.Type = client.CipherTypeSshKey
	c.SshKey = &client.CipherSshKey{
		PrivateKey:     encryptStr(t, key, "synthetic-private-key"),
		PublicKey:      encryptStr(t, key, "ssh-ed25519 AAAA"),
		KeyFingerprint: encryptStr(t, key, "SHA256:abcdefgh"),
	}

	out := renderRecord(&c, key, &client.SyncResponse{}, nil, "fallback")
	for _, want := range []string{
		"Fingerprint: SHA256:abcdefgh\n",
		"Public key: ssh-ed25519 AAAA\n",
		"Private key: synthetic-private-key\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderRecord_DecryptErrorsAreSkipped(t *testing.T) {
	key := testKey()
	c := makeCipher(t, "item-1", "My key", "", key)
	c.Type = client.CipherTypeSshKey
	c.SshKey = &client.CipherSshKey{
		PrivateKey: "not-a-valid-cipher-string",
		PublicKey:  encryptStr(t, key, "ssh-ed25519 AAAA"),
	}

	out := renderRecord(&c, key, &client.SyncResponse{}, nil, "fallback")
	if !strings.Contains(out, "Public key: ssh-ed25519 AAAA\n") {
		t.Errorf("public key missing:\n%s", out)
	}
	if strings.Contains(out, "Private key") {
		t.Errorf("broken private key must be skipped:\n%s", out)
	}
}
