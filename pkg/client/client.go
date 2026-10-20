// SPDX-License-Identifier: 0BSD

// Package client is the saves sync engine: push and pull of save trees
// over the saves wire protocol with content-defined chunking and
// portable cross-OS manifests.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/pkg/api"
	"github.com/Sudo-Ivan/saves/pkg/cdc"
	"github.com/quic-go/quic-go/http3"
)

// Config controls a Client.
type Config struct {
	BandwidthLimit int64 // bytes/sec, 0 unlimited
	BaseURL        string
	Token          string
	HTTP           *http.Client
	Concurrency    int
	CDC            cdc.Params
	UserAgent      string
	Retries        int
	// HTTP3 selects the HTTP/3 transport when HTTP is nil.
	HTTP3 bool
	// TLS is the client TLS configuration for the HTTP/3 transport; nil
	// uses the system roots with full certificate verification.
	TLS *tls.Config
	// Cipher enables vault encryption (pkg/vault).
	Cipher Cipher
}

// Client talks to a saves server.
type Client struct {
	cfg   Config
	http  *http.Client
	h3    *http3.Transport
	agent string
}

// New builds a Client.
func New(c Config) (*Client, error) {
	if c.BaseURL == "" {
		return nil, errors.New("client: BaseURL required")
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 8
	}
	if c.Retries <= 0 {
		c.Retries = 3
	}
	if c.CDC.Validate() != nil {
		c.CDC = cdc.DefaultParams()
	}
	cl := &Client{cfg: c, agent: c.UserAgent}
	if c.HTTP != nil {
		cl.http = c.HTTP
	} else if c.HTTP3 {
		tc := c.TLS
		if tc == nil {
			tc = &tls.Config{MinVersion: tls.VersionTLS13}
		}
		h3 := &http3.Transport{TLSClientConfig: tc}
		cl.h3 = h3
		cl.http = &http.Client{Transport: h3}
	} else {
		cl.http = &http.Client{Transport: netx.NewTransport()}
	}
	if cl.agent == "" {
		cl.agent = "savesctl/1.0"
	}
	return cl, nil
}

// Close releases transport resources.
func (c *Client) Close() {
	if c.h3 != nil {
		_ = c.h3.Close()
	}
}

// APIError is a decoded problem+json response.
type APIError struct {
	Status int
	Code   string
	Detail string
}

func (e *APIError) Error() string { return fmt.Sprintf("api: %s (status %d)", e.Code, e.Status) }

// ConflictError reports a head mismatch on commit.
type ConflictError struct{ Head string }

func (e *ConflictError) Error() string { return "conflict: head is " + e.Head }

// QuotaError reports a quota rejection.
type QuotaError struct{ APIError }

// ErrUnauthorized marks a 401.
var ErrUnauthorized = errors.New("client: unauthorized")

func (c *Client) req(ctx context.Context, method, path string, body io.Reader, hdr map[string]string) (*http.Response, error) {
	// Buffer the body once so every retry replays identical bytes.
	var payload []byte
	if body != nil {
		var err error
		payload, err = io.ReadAll(io.LimitReader(body, 1<<30))
		if err != nil {
			return nil, err
		}
	}
	var lastErr error
	for i := 0; i <= c.cfg.Retries; i++ {
		var req *http.Request
		var err error
		if payload != nil {
			req, err = http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, bytes.NewReader(payload))
			if err == nil {
				req.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(payload)), nil
				}
				req.ContentLength = int64(len(payload))
			}
		} else {
			req, err = http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, nil)
		}
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", c.agent)
		if c.cfg.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
		} else if resp.StatusCode == 429 && i < c.cfg.Retries && !nonRetryable(resp) {
			wait := retryAfter(resp)
			_ = resp.Body.Close()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		} else {
			return resp, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff(i)):
		}
	}
	return nil, lastErr
}

// nonRetryable reports whether a problem response must not be retried
// even at 429 or 5xx (quota and conflict are terminal).
func nonRetryable(resp *http.Response) bool {
	if resp.Header.Get("Content-Type") != "application/problem+json" &&
		resp.Header.Get("Content-Type") != "application/json" {
		return false
	}
	if resp.Body == nil {
		return false
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return false
	}
	// Restore the body for the caller.
	resp.Body = io.NopCloser(bytes.NewReader(buf))
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(buf, &p)
	return p.Code == api.CodeQuotaExceeded || p.Code == api.CodeConflict
}

func retryAfter(r *http.Response) time.Duration {
	if v := r.Header.Get("Retry-After"); v != "" {
		if n, err := json.Number(v).Int64(); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return backoff(0)
}

func backoff(i int) time.Duration {
	d := time.Duration(100*(1<<i)) * time.Millisecond
	if d > 3*time.Second {
		d = 3 * time.Second
	}
	return d
}

func (c *Client) decode(resp *http.Response, v any) error {
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var p api.Problem
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = json.Unmarshal(b, &p)
		if resp.StatusCode == 401 {
			return ErrUnauthorized
		}
		if p.Code == api.CodeQuotaExceeded || resp.StatusCode == 413 {
			return &QuotaError{APIError{Status: resp.StatusCode, Code: p.Code, Detail: p.Detail}}
		}
		if p.Code == api.CodeEncryptionRequired {
			return &EncryptionRequiredError{}
		}
		return &APIError{Status: resp.StatusCode, Code: p.Code, Detail: p.Detail}
	}
	if v == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// Me returns the user, usage and limits (limits cached for the client).
func (c *Client) Me(ctx context.Context) (*MeOut, error) {
	resp, err := c.req(ctx, "GET", "/v1/me", nil, nil)
	if err != nil {
		return nil, err
	}
	var out MeOut
	if err := c.decode(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MeOut is the /v1/me response.
type MeOut struct {
	User              json.RawMessage `json:"user"`
	Tier              string          `json:"tier"`
	Usage             json.RawMessage `json:"usage"`
	Scopes            string          `json:"scopes"`
	Anonymous         bool            `json:"anonymous"`
	RequireEncryption bool            `json:"require_encryption"`
}

// ListApps lists apps.
func (c *Client) ListApps(ctx context.Context) ([]meta.AppSummary, error) {
	resp, err := c.req(ctx, "GET", "/v1/apps", nil, nil)
	if err != nil {
		return nil, err
	}
	var out []meta.AppSummary
	err = c.decode(resp, &out)
	return out, err
}

// ListSlots lists slots for an app.
func (c *Client) ListSlots(ctx context.Context, app string) ([]string, error) {
	resp, err := c.req(ctx, "GET", "/v1/apps/"+app+"/slots", nil, nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Slots []string `json:"slots"`
	}
	err = c.decode(resp, &out)
	return out.Slots, err
}

// Snapshot is a remote snapshot summary.
type Snapshot struct {
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	Device      string    `json:"device"`
	CommittedAt time.Time `json:"committed_at"`
	TotalBytes  int64     `json:"total_bytes"`
	FileCount   int64     `json:"file_count"`
}

// ListSnapshots returns an iterator over slot snapshots.
func (c *Client) ListSnapshots(ctx context.Context, app, slot string) (func(func(Snapshot) bool), error) {
	resp, err := c.req(ctx, "GET", fmt.Sprintf("/v1/apps/%s/slots/%s/snapshots", app, slot), nil, nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Snapshots []Snapshot `json:"snapshots"`
	}
	if err := c.decode(resp, &out); err != nil {
		return nil, err
	}
	return func(yield func(Snapshot) bool) {
		for _, s := range out.Snapshots {
			if !yield(s) {
				return
			}
		}
	}, nil
}

// GetManifest fetches a manifest by snapshot id (or latest).
func (c *Client) GetManifest(ctx context.Context, app, slot, id string) (*api.Manifest, error) {
	resp, err := c.req(ctx, "GET", fmt.Sprintf("/v1/apps/%s/slots/%s/snapshots/%s", app, slot, id), nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, c.decode(resp, nil)
	}
	m, err := api.DecodeManifest(resp.Body, 64<<20)
	return m, err
}

// DeleteSlot deletes a slot.
func (c *Client) DeleteSlot(ctx context.Context, app, slot string) error {
	resp, err := c.req(ctx, "DELETE", fmt.Sprintf("/v1/apps/%s/slots/%s", app, slot), nil, nil)
	if err != nil {
		return err
	}
	return c.decode(resp, nil)
}

// DeleteSnapshot deletes a snapshot.
func (c *Client) DeleteSnapshot(ctx context.Context, app, slot, id string) error {
	resp, err := c.req(ctx, "DELETE", fmt.Sprintf("/v1/apps/%s/slots/%s/snapshots/%s", app, slot, id), nil, nil)
	if err != nil {
		return err
	}
	return c.decode(resp, nil)
}

// Chunk fetches raw chunk bytes, verifying the hash.
func (c *Client) chunk(ctx context.Context, app string, h api.Hash) ([]byte, error) {
	resp, err := c.req(ctx, "GET", fmt.Sprintf("/v1/apps/%s/chunks/%s", app, hex.EncodeToString(h[:])), nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, c.decode(resp, nil)
	}
	b, err := io.ReadAll(io.LimitReader(newLimitReader(resp.Body, c.cfg.BandwidthLimit), 8<<20))
	if err != nil {
		return nil, err
	}
	if got := api.HashBytes(b); got != h {
		return nil, fmt.Errorf("client: chunk hash mismatch")
	}
	return b, nil
}

var _ = bytes.NewReader
var _ = strings.TrimSpace

// Register creates an account and returns a token.
func (c *Client) Register(ctx context.Context, invite string) (string, string, error) {
	body := `{"invite":` + `"` + invite + `"}`
	resp, err := c.req(ctx, "POST", "/v1/register", strings.NewReader(body),
		map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return "", "", err
	}
	var out struct {
		UserID string `json:"user_id"`
		Token  string `json:"token"`
	}
	if err := c.decode(resp, &out); err != nil {
		return "", "", err
	}
	return out.UserID, out.Token, nil
}
