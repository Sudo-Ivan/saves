// SPDX-License-Identifier: 0BSD

package server

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestVaultHTTP(t *testing.T) {
	fx := setup(t)
	tok := fx.tokenFor(t, "u1", []string{"read", "write"}, nil)
	srv := fx.srv
	get := func(tok string) (*http.Response, []byte) {
		r, _ := http.NewRequest("GET", srv.URL+"/v1/vault", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		resp, err := fx.cli.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	put := func(tok, etag string, body []byte) (*http.Response, []byte) {
		r, _ := http.NewRequest("PUT", srv.URL+"/v1/vault", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tok)
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		resp, err := fx.cli.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	// empty -> 404
	r, _ := get(tok)
	if r.StatusCode != 404 {
		t.Fatalf("get empty: %d", r.StatusCode)
	}
	// create
	hdr := []byte(`{"v":1,"kid":"k1"}`)
	r, _ = put(tok, "", hdr)
	if r.StatusCode != 200 {
		t.Fatalf("put: %d", r.StatusCode)
	}
	etag := r.Header.Get("ETag")
	// get back
	r, b := get(tok)
	if r.StatusCode != 200 || !bytes.Equal(b, hdr) {
		t.Fatalf("get: %d %s", r.StatusCode, b)
	}
	// update without if-match -> 412
	r, _ = put(tok, "", []byte(`{"v":1,"kid":"k2"}`))
	if r.StatusCode != 412 {
		t.Fatalf("no if-match: %d", r.StatusCode)
	}
	// stale etag -> 412
	r, _ = put(tok, `"99"`, []byte(`{"v":1,"kid":"k2"}`))
	if r.StatusCode != 412 {
		t.Fatalf("stale: %d", r.StatusCode)
	}
	// correct etag -> ok
	r, _ = put(tok, etag, []byte(`{"v":1,"kid":"k2"}`))
	if r.StatusCode != 200 {
		t.Fatalf("update: %d", r.StatusCode)
	}
	// oversize -> 413
	r, _ = put(tok, r.Header.Get("ETag"), bytes.Repeat([]byte("x"), 9000))
	if r.StatusCode != 413 {
		t.Fatalf("big: %d", r.StatusCode)
	}
	// wrong token -> 401/403
	r, _ = get("bogus")
	if r.StatusCode != 401 && r.StatusCode != 403 {
		t.Fatalf("bad token: %d", r.StatusCode)
	}
	// delete
	rq, _ := http.NewRequest("DELETE", srv.URL+"/v1/vault", nil)
	rq.Header.Set("Authorization", "Bearer "+tok)
	resp, _ := http.DefaultClient.Do(rq)
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	r, _ = get(tok)
	if r.StatusCode != 404 {
		t.Fatalf("after delete: %d", r.StatusCode)
	}
	_ = strings.TrimSpace
}
