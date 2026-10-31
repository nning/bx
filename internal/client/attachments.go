package client

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
)

// attachmentURL resolves direct upload paths against the API base. Signed
// download and blob URLs may use another HTTPS origin, without vault tokens.
func (c *Client) attachmentURL(raw string, direct bool) (*url.URL, error) {
	if err := ValidateServerURL(c.ServerURL); err != nil {
		return nil, err
	}
	base, _ := url.Parse(c.ServerURL + "/")
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return nil, fmt.Errorf("invalid attachment URL")
	}
	if !u.IsAbs() {
		if u.Host != "" {
			return nil, fmt.Errorf("protocol-relative attachment URL is not allowed")
		}
		if direct {
			// Vaultwarden returns /ciphers/... relative to the API base.
			// Also accept an explicitly API-prefixed relative URL.
			base.Path = strings.TrimRight(base.Path, "/") + "/api/"
			u.Path = strings.TrimPrefix(strings.TrimPrefix(u.Path, "/"), "api/")
		}
		u = base.ResolveReference(u)
	}
	checked := *u
	checked.RawQuery, checked.Fragment = "", ""
	if err := ValidateServerURL(checked.String()); err != nil {
		return nil, err
	}
	if base.Scheme == "https" && u.Scheme != "https" {
		return nil, fmt.Errorf("refusing insecure attachment URL")
	}
	if direct && !sameOrigin(base, u) {
		return nil, fmt.Errorf("direct attachment upload must use the vault server origin")
	}
	return u, nil
}

func readAttachment(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("encrypted attachment exceeds %d bytes", maxResponseBytes)
	}
	return data, nil
}

// GetAttachment fetches metadata, then downloads the encrypted file from its
// signed URL. The file request never contains a vault Authorization header.
func (c *Client) GetAttachment(cipherID, attachmentID string) (data []byte, err error) {
	var metadata struct {
		URL string `json:"url"`
	}
	if err := c.doJSONRequest(http.MethodGet, c.ServerURL+"/api/ciphers/"+cipherID+"/attachment/"+attachmentID,
		nil, http.StatusOK, &metadata); err != nil {
		return nil, err
	}
	u, err := c.attachmentURL(metadata.URL, false)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attachment download failed: %w", err)
	}
	defer closeResponseBody(resp.Body, &err)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attachment download failed with status %d", resp.StatusCode)
	}
	return readAttachment(resp.Body)
}

// UploadAttachmentFile posts multipart data to the direct API endpoint or
// puts raw bytes to a signed Azure URL. Only direct uploads use vault tokens.
func (c *Client) UploadAttachmentFile(upload *AttachmentFileUploadResponse, data []byte) (err error) {
	if upload == nil || (upload.FileUploadType != 0 && upload.FileUploadType != 1) {
		return fmt.Errorf("unsupported attachment upload type")
	}
	direct := upload.FileUploadType == 0
	u, err := c.attachmentURL(upload.URL, direct)
	if err != nil {
		return err
	}
	method := http.MethodPut
	var body bytes.Buffer
	contentType := "application/octet-stream"
	if direct {
		if c.Token == "" {
			return fmt.Errorf("client not authenticated")
		}
		method = http.MethodPost
		writer := multipart.NewWriter(&body)
		part, err := writer.CreateFormFile("data", "attachment.bin")
		if err != nil {
			return err
		}
		if _, err := part.Write(data); err != nil {
			return err
		}
		if err := writer.Close(); err != nil {
			return err
		}
		contentType = writer.FormDataContentType()
	} else {
		body.Write(data)
	}
	req, err := http.NewRequest(method, u.String(), &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if direct {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	} else {
		req.Header.Set("x-ms-blob-type", "BlockBlob")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("attachment upload failed: %w", err)
	}
	defer closeResponseBody(resp.Body, &err)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("attachment upload failed with status %d", resp.StatusCode)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	return err
}
