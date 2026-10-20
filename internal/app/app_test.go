// SPDX-License-Identifier: 0BSD

package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthcheck(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nope" {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()
	if got := cmdHealthcheck([]string{"-url", ts.URL}); got != 0 {
		t.Fatalf("want 0 got %d", got)
	}
	if got := cmdHealthcheck([]string{"-url", ts.URL + "/nope", "-timeout", "2s"}); got != 1 {
		t.Fatalf("want 1 got %d", got)
	}
}
