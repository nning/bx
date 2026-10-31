package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nning/bx/internal/crypto"
)

// Run only against a disposable local server: this creates a synthetic account.
func TestVaultwardenAttachmentIntegration(t *testing.T) {
	server := os.Getenv("BX_TEST_VAULTWARDEN_URL")
	if server == "" {
		t.Skip("set BX_TEST_VAULTWARDEN_URL to a disposable local Vaultwarden")
	}
	u, err := url.Parse(server)
	if err != nil || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() {
		t.Fatal("integration server must use a loopback IP address")
	}
	email := uuid.NewString() + "@example.com"
	password := "synthetic integration password"
	master, err := crypto.DeriveMasterKey(password, email, crypto.KdfConfig{Iterations: 600000})
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := crypto.ExpandKey(master)
	if err != nil {
		t.Fatal(err)
	}
	accountKey := make([]byte, 64)
	if _, err := rand.Read(accountKey); err != nil {
		t.Fatal(err)
	}
	protectedKey, err := crypto.Encrypt(accountKey, expanded)
	if err != nil {
		t.Fatal(err)
	}
	c := New(server)
	verification, err := json.Marshal(map[string]string{"email": email, "name": "Integration test"})
	if err != nil {
		t.Fatal(err)
	}
	verificationReq, err := http.NewRequest(http.MethodPost, server+"/identity/accounts/register/send-verification-email", bytes.NewReader(verification))
	if err != nil {
		t.Fatal(err)
	}
	verificationReq.Header.Set("Content-Type", "application/json")
	verificationReq.Header.Set("Accept", "application/json")
	verificationResp, err := c.httpClient.Do(verificationReq)
	if err != nil {
		t.Fatal(err)
	}
	var emailToken string
	err = json.NewDecoder(verificationResp.Body).Decode(&emailToken)
	_ = verificationResp.Body.Close()
	if err != nil || verificationResp.StatusCode != http.StatusOK || emailToken == "" {
		t.Fatalf("registration token status %d: %v", verificationResp.StatusCode, err)
	}
	registration, err := json.Marshal(map[string]any{
		"email": email, "name": "Integration test", "masterPasswordHash": crypto.HashMasterPassword(master, password),
		"key": protectedKey, "kdf": 0, "kdfIterations": 600000, "emailVerificationToken": emailToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, server+"/identity/accounts/register/finish", bytes.NewReader(registration))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("registration status: %d", resp.StatusCode)
	}
	if _, err := c.Login(email, password, uuid.NewString(), "", ""); err != nil {
		t.Fatal(err)
	}
	vault, _, err := c.Sync()
	if err != nil {
		t.Fatal(err)
	}
	encrypt := func(value []byte) string {
		t.Helper()
		encoded, err := crypto.Encrypt(value, accountKey)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	item, err := c.CreateCipher(CipherRequest{Type: CipherTypeLogin, Name: encrypt([]byte("Integration item")),
		EncryptedFor: vault.Profile.ID, Login: &CipherLoginReq{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := c.HardDeleteCipher(item.ID); err != nil {
			t.Errorf("clean up test item: %v", err)
		}
	}()
	fileKey := bytes.Repeat([]byte{0x24}, 64)
	plaintext := []byte("synthetic attachment contents")
	for _, independent := range []bool{false, true} {
		var encrypted []byte
		if independent {
			// Produce the official layout independently of EncryptAttachment.
			value, err := crypto.Encrypt(plaintext, fileKey)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(strings.TrimPrefix(value, "2."), "|")
			iv, _ := base64.StdEncoding.DecodeString(parts[0])
			ct, _ := base64.StdEncoding.DecodeString(parts[1])
			mac, _ := base64.StdEncoding.DecodeString(parts[2])
			encrypted = append([]byte{2}, iv...)
			encrypted = append(encrypted, mac...)
			encrypted = append(encrypted, ct...)
		} else {
			encrypted, err = crypto.EncryptAttachment(plaintext, fileKey)
			if err != nil {
				t.Fatal(err)
			}
		}
		upload, err := c.CreateAttachmentV2(item.ID, AttachmentUploadRequest{
			FileName: encrypt([]byte("synthetic.txt")), FileSize: int64(len(encrypted)), Key: encrypt(fileKey),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.UploadAttachmentFile(upload, encrypted); err != nil {
			t.Fatal(err)
		}
		downloaded, err := c.GetAttachment(item.ID, upload.AttachmentID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := crypto.DecryptAttachment(downloaded, fileKey)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("downloaded attachment: %q, %v", got, err)
		}
	}
}
