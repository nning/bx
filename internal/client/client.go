package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nning/bx/internal/crypto"
)

// ErrUnauthorized is returned when the server responds with HTTP 401,
// indicating that the session has expired and the user must log in again.
var ErrUnauthorized = errors.New("session expired")

// maxResponseBytes caps the size of any single HTTP response body read into
// memory.  100 MiB is generous for any realistic vault or API response.
const maxResponseBytes = 100 * 1024 * 1024

type Client struct {
	ServerURL  string
	Token      string
	httpClient *http.Client
}

func New(serverURL string) *Client {
	// Configure secure TLS client
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Start from the default transport so that bx keeps its connection
	// pooling, dial and TLS handshake timeouts, HTTP/2 support and
	// HTTPS_PROXY/NO_PROXY handling, and only tighten the TLS settings.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	httpClient := &http.Client{
		Timeout:       30 * time.Second,
		Transport:     secureTransport{base: transport},
		CheckRedirect: checkRedirect,
	}

	return &Client{
		ServerURL:  strings.TrimRight(serverURL, "/"),
		httpClient: httpClient,
	}
}

func (c *Client) Login(email, password, deviceID, twoFactorToken, twoFactorProvider string) (tokenResp *TokenResponse, err error) {
	// 1. Prelogin
	preloginURL := c.ServerURL + "/identity/accounts/prelogin"
	preReq := PreloginRequest{Email: email}
	preReqBytes, err := json.Marshal(preReq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", preloginURL, bytes.NewBuffer(preReqBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prelogin request failed: %w", err)
	}
	// Older Vaultwarden versions exposed prelogin under /api instead.
	if resp.StatusCode == http.StatusNotFound {
		if err := resp.Body.Close(); err != nil {
			return nil, err
		}
		req, err = http.NewRequest(http.MethodPost, c.ServerURL+"/api/accounts/prelogin", bytes.NewReader(preReqBytes))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("prelogin request failed: %w", err)
		}
	}
	defer closeResponseBody(resp.Body, &err)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prelogin failed with status %d (check server URL and try again)", resp.StatusCode)
	}

	var preResp PreloginResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&preResp); err != nil {
		return nil, fmt.Errorf("failed to decode prelogin response: %w", err)
	}

	// 2. Derive Master Key
	kdfConfig := crypto.KdfConfig{
		Type:        crypto.KdfType(preResp.Kdf),
		Iterations:  preResp.KdfIterations,
		Memory:      preResp.KdfMemory,
		Parallelism: preResp.KdfParallelism,
	}

	masterKey, err := crypto.DeriveMasterKey(password, email, kdfConfig)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// 3. Hash Master Password
	masterPasswordHash := crypto.HashMasterPassword(masterKey, password)
	crypto.Wipe(masterKey)

	// 4. Authenticate
	tokenURL := c.ServerURL + "/identity/connect/token"
	formData := url.Values{}
	formData.Set("grant_type", "password")
	formData.Set("username", email)
	formData.Set("password", masterPasswordHash)
	formData.Set("scope", "api offline_access")
	// bx identifies as the web vault (client_id "web", device type 9 =
	// ChromeBrowser), which every Bitwarden and Vaultwarden server accepts.
	// The official CLI uses client_id "cli" with device types 23-25; moving
	// to that needs testing against both servers first (see ROADMAP.md).
	formData.Set("client_id", "web")
	formData.Set("deviceType", "9")
	formData.Set("deviceIdentifier", deviceID)
	formData.Set("deviceName", "bx-cli")

	if twoFactorToken != "" {
		formData.Set("twoFactorToken", twoFactorToken)
		formData.Set("twoFactorProvider", twoFactorProvider)
		formData.Set("twoFactorRemember", "1")
	}

	req, err = http.NewRequest("POST", tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	tokenHTTPResp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	defer closeResponseBody(tokenHTTPResp.Body, &err)

	if tokenHTTPResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(tokenHTTPResp.Body, maxResponseBytes))
		var tfr TwoFactorResponse
		if err := json.Unmarshal(body, &tfr); err == nil && tfr.Error == "invalid_grant" && tfr.ErrorDescription == "Two factor required." {
			return nil, &ErrTwoFactorRequired{Response: tfr}
		}
		if tokenHTTPResp.StatusCode == http.StatusBadRequest && strings.Contains(string(body), "invalid_grant") {
			return nil, fmt.Errorf("login failed: invalid credentials")
		}
		return nil, fmt.Errorf("login failed with status %d", tokenHTTPResp.StatusCode)
	}

	var token TokenResponse
	if err := json.NewDecoder(io.LimitReader(tokenHTTPResp.Body, maxResponseBytes)).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	c.Token = token.AccessToken
	tokenResp = &token
	return tokenResp, nil
}

// RefreshToken exchanges a stored refresh token for a new access token.
// It returns the new TokenResponse so the caller can persist both the
// updated access token and the (possibly rotated) refresh token.
func (c *Client) RefreshToken(refreshToken, deviceID string) (tokenResp *TokenResponse, err error) {
	tokenURL := c.ServerURL + "/identity/connect/token"
	formData := url.Values{}
	formData.Set("grant_type", "refresh_token")
	formData.Set("refresh_token", refreshToken)
	formData.Set("client_id", "web")
	formData.Set("deviceType", "9")
	formData.Set("deviceIdentifier", deviceID)
	formData.Set("deviceName", "bx-cli")

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token refresh request failed: %w", err)
	}
	defer closeResponseBody(resp.Body, &err)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		bodySnippet := strings.TrimSpace(string(body))
		const maxSnippet = 200
		if len(bodySnippet) > maxSnippet {
			bodySnippet = bodySnippet[:maxSnippet] + "..."
		}
		return nil, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, bodySnippet)
	}

	var token TokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	c.Token = token.AccessToken
	return &token, nil
}

func (c *Client) Sync() (syncResponse *SyncResponse, raw []byte, err error) {
	if c.Token == "" {
		return nil, nil, fmt.Errorf("client not authenticated")
	}

	syncURL := c.ServerURL + "/api/sync"
	req, err := http.NewRequest("GET", syncURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("sync request failed: %w", err)
	}
	defer closeResponseBody(resp.Body, &err)

	if resp.StatusCode == http.StatusUnauthorized {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return nil, nil, ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("sync failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, nil, err
	}

	var syncData SyncResponse
	if err := json.Unmarshal(body, &syncData); err != nil {
		return nil, nil, fmt.Errorf("failed to decode sync response: %w", err)
	}

	return &syncData, body, nil
}

func closeResponseBody(body io.Closer, errPtr *error) {
	if body == nil {
		return
	}
	if errPtr == nil {
		_ = body.Close()
		return
	}
	if closeErr := body.Close(); closeErr != nil && *errPtr == nil {
		*errPtr = closeErr
	}
}

// newAuthenticatedRequest creates an authenticated JSON request.
func (c *Client) newAuthenticatedRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// doJSONRequest executes an authenticated request, checks the status against
// expectedStatus, and (if dst is non-nil) JSON-decodes the response body into
// dst.
func (c *Client) doJSONRequest(method, url string, payload any, expectedStatus int, dst any) (err error) {
	if c.Token == "" {
		return fmt.Errorf("client not authenticated")
	}

	var bodyReader io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		bodyReader = bytes.NewBuffer(b)
	}

	req, err := c.newAuthenticatedRequest(method, url, bodyReader)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer closeResponseBody(resp.Body, &err)

	if resp.StatusCode != expectedStatus {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		if resp.StatusCode == http.StatusConflict {
			return fmt.Errorf("conflict: server rejected the request (HTTP 409) — run 'bx fetch' to refresh the local cache, then retry")
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return ErrUnauthorized
		}
		// Truncate the response body to avoid leaking potentially sensitive
		// server-side details (stack traces, internal identifiers, etc.) into
		// error messages that may be logged or displayed.
		bodySnippet := strings.TrimSpace(string(body))
		const maxSnippet = 200
		if len(bodySnippet) > maxSnippet {
			bodySnippet = bodySnippet[:maxSnippet] + "..."
		}
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, bodySnippet)
	}

	if dst != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(dst); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}
	return nil
}

// GetCipher retrieves a single cipher by ID from the server. This is used for
// conflict detection: comparing the server's RevisionDate with the local cache.
func (c *Client) GetCipher(id string) (*Cipher, error) {
	var cipher Cipher
	if err := c.doJSONRequest("GET", c.ServerURL+"/api/ciphers/"+id, nil, http.StatusOK, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

// GetCipherRaw retrieves a single cipher by ID as undecoded JSON. It is used by
// the ownership-change flow, which must forward every field the server knows
// about — including fields bx does not model — back to the server.
func (c *Client) GetCipherRaw(id string) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := c.doJSONRequest("GET", c.ServerURL+"/api/ciphers/"+id, nil, http.StatusOK, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// ShareCipher transfers a personal cipher to an organization and assigns it to
// the given collections.  req.Cipher must already be encrypted with the target
// organization's key.
//
// Vaultwarden and Bitwarden return different response shapes on this endpoint
// (and older Vaultwarden versions return an empty body), so the response body is
// ignored and the updated cipher is fetched afterwards.  It is returned as raw
// JSON because sharing re-encrypts fields bx does not model, all of which have
// to reach the local cache.
func (c *Client) ShareCipher(id string, req ShareCipherRequest) (json.RawMessage, error) {
	if err := c.doJSONRequest("PUT", c.ServerURL+"/api/ciphers/"+id+"/share", req, http.StatusOK, nil); err != nil {
		return nil, err
	}
	return c.GetCipherRaw(id)
}

// UpdateCipherCollections replaces the collections an organization cipher
// belongs to.  As with ShareCipher the response body is ignored — it is empty on
// some server versions — and the updated cipher is fetched afterwards.
func (c *Client) UpdateCipherCollections(id string, req CipherCollectionsRequest) (json.RawMessage, error) {
	if err := c.doJSONRequest("PUT", c.ServerURL+"/api/ciphers/"+id+"/collections", req, http.StatusOK, nil); err != nil {
		return nil, err
	}
	return c.GetCipherRaw(id)
}

// CreateCipher POSTs a new cipher to the server and returns the created cipher.
func (c *Client) CreateCipher(req CipherRequest) (*Cipher, error) {
	var cipher Cipher
	if err := c.doJSONRequest("POST", c.ServerURL+"/api/ciphers", req, http.StatusOK, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

// UpdateCipherRaw PUTs an updated cipher to the server and returns the server's
// copy of the result.  Both are raw JSON: the server replaces the item with
// whatever the request contains, so the request must carry every field of the
// item — including fields bx does not model — and the response is cached
// without passing through bx's typed Cipher.
func (c *Client) UpdateCipherRaw(id string, cipher json.RawMessage) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := c.doJSONRequest("PUT", c.ServerURL+"/api/ciphers/"+id, cipher, http.StatusOK, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// SoftDeleteCipher moves a cipher to the Trash and returns the updated cipher
// with DeletedDate set.  Vaultwarden returns HTTP 200 with an empty body on
// this endpoint, so we skip body decoding and fetch the cipher afterwards.
func (c *Client) SoftDeleteCipher(id string) (*Cipher, error) {
	if err := c.doJSONRequest("PUT", c.ServerURL+"/api/ciphers/"+id+"/delete", nil, http.StatusOK, nil); err != nil {
		return nil, err
	}
	return c.GetCipher(id)
}

// HardDeleteCipher permanently deletes a cipher from the server.
func (c *Client) HardDeleteCipher(id string) error {
	return c.doJSONRequest("DELETE", c.ServerURL+"/api/ciphers/"+id, nil, http.StatusOK, nil)
}

// RestoreCipher restores a soft-deleted cipher from the Trash and returns the
// updated cipher with DeletedDate cleared.
func (c *Client) RestoreCipher(id string) (*Cipher, error) {
	var cipher Cipher
	if err := c.doJSONRequest("PUT", c.ServerURL+"/api/ciphers/"+id+"/restore", nil, http.StatusOK, &cipher); err != nil {
		return nil, err
	}
	return &cipher, nil
}

// CreateFolder POSTs a new folder to the server and returns the created folder.
func (c *Client) CreateFolder(req FolderRequest) (*Folder, error) {
	var folder Folder
	if err := c.doJSONRequest("POST", c.ServerURL+"/api/folders", req, http.StatusOK, &folder); err != nil {
		return nil, err
	}
	return &folder, nil
}

// UpdateFolder PUTs an updated folder to the server and returns the updated folder.
func (c *Client) UpdateFolder(id string, req FolderRequest) (*Folder, error) {
	var folder Folder
	if err := c.doJSONRequest("PUT", c.ServerURL+"/api/folders/"+id, req, http.StatusOK, &folder); err != nil {
		return nil, err
	}
	return &folder, nil
}

// DeleteFolder permanently deletes a folder from the server.
func (c *Client) DeleteFolder(id string) error {
	return c.doJSONRequest("DELETE", c.ServerURL+"/api/folders/"+id, nil, http.StatusOK, nil)
}

// CreateAttachmentV2 registers an attachment before its file is uploaded.  The
// response names the attachment and carries the URL to upload the encrypted
// file to, together with the upload type (0 = direct, 1 = Azure blob).
func (c *Client) CreateAttachmentV2(cipherID string, req AttachmentUploadRequest) (*AttachmentFileUploadResponse, error) {
	var upload AttachmentFileUploadResponse
	if err := c.doJSONRequest("POST", c.ServerURL+"/api/ciphers/"+cipherID+"/attachment/v2", req, http.StatusOK, &upload); err != nil {
		return nil, err
	}
	return &upload, nil
}
