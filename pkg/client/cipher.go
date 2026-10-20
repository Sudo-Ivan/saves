// SPDX-License-Identifier: 0BSD

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
)

// Cipher encrypts chunks and metadata client side. pkg/vault satisfies it.
type Cipher interface {
	KID() string
	SealChunk(plain []byte) []byte
	OpenChunk(ct []byte) ([]byte, error)
	SealInline(plain []byte) []byte
	OpenInline(ct []byte) ([]byte, error)
	PathID(path string) string
	SealMeta(plain []byte) []byte
	OpenMeta(ct []byte) ([]byte, error)
}

// KeyMismatchError is returned when the snapshot uses a different key.
type KeyMismatchError struct{ Want, Have string }

func (e *KeyMismatchError) Error() string {
	return fmt.Sprintf("client: snapshot kid %s does not match key %s", e.Want, e.Have)
}

// EncryptedError is returned when a cipher is required but unset.
type EncryptedError struct{ Hint string }

func (e *EncryptedError) Error() string { return "client: snapshot is encrypted; " + e.Hint }

// EncryptionRequiredError is returned when the server policy requires vault.
type EncryptionRequiredError struct{}

func (e *EncryptionRequiredError) Error() string {
	return "client: server requires encrypted snapshots"
}

// GetVault fetches the stored header and its ETag.
func (c *Client) GetVault(ctx context.Context) ([]byte, string, error) {
	resp, err := c.req(ctx, "GET", "/v1/vault", nil, nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, "", nil
	}
	if resp.StatusCode != 200 {
		return nil, "", c.decode(resp, nil)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8192+1))
	if err != nil {
		return nil, "", err
	}
	return b, resp.Header.Get("ETag"), nil
}

// PutVault stores the header; ifMatch is the ETag of the current header or "".
func (c *Client) PutVault(ctx context.Context, header []byte, ifMatch string) (string, error) {
	hdr := map[string]string{"Content-Type": "application/octet-stream"}
	if ifMatch != "" {
		hdr["If-Match"] = ifMatch
	}
	resp, err := c.req(ctx, "PUT", "/v1/vault", bytes.NewReader(header), hdr)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", c.decode(resp, nil)
	}
	return resp.Header.Get("ETag"), nil
}

// DeleteVault removes the stored header.
func (c *Client) DeleteVault(ctx context.Context) error {
	resp, err := c.req(ctx, "DELETE", "/v1/vault", nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		return c.decode(resp, nil)
	}
	return nil
}

var _ = sha256.Sum256
