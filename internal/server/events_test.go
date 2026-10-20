// SPDX-License-Identifier: 0BSD

package server

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/events"
)

func TestSSE(t *testing.T) {
	fx := setup(t)
	fx.s2.Svc.Events = events.New(8, 16)
	tok := fx.tokenFor(t, "u1", []string{"read", "write"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", fx.srv.URL+"/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := fx.cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("events status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("ct %q", ct)
	}
	// Commit a head event; publish under the real user id.
	go func() {
		time.Sleep(50 * time.Millisecond)
		u, _, _ := fx.m.UpsertUser(ctx, "u1", "free")
		fx.s2.Svc.Events.Publish(u.ID, "head", []byte(`{"app":"a","slot":"s"}`))
	}()
	sc := bufio.NewScanner(resp.Body)
	deadline := time.After(3 * time.Second)
	got := make(chan string, 8)
	go func() {
		for sc.Scan() {
			got <- sc.Text()
		}
	}()
	var head bool
	for !head {
		select {
		case ln := <-got:
			if strings.HasPrefix(ln, "event: head") {
				head = true
			}
		case <-deadline:
			t.Fatal("no head event in 3s")
		}
	}
	// cross-user isolation: subscriber u2 must not get u1 events
	u1, _, _ := fx.m.UpsertUser(ctx, "u1", "free")
	ch, drop2, _ := fx.s2.Svc.Events.Subscribe("u2")
	fx.s2.Svc.Events.Publish(u1.ID, "head", []byte(`x`))
	select {
	case ev := <-ch:
		t.Fatalf("u2 got %v", ev)
	case <-time.After(150 * time.Millisecond):
	}
	drop2()
	// cap
	var drops []func()
	for i := 0; i < 8; i++ {
		_, d, err := fx.s2.Svc.Events.Subscribe("cap")
		if err != nil {
			t.Fatal(err)
		}
		drops = append(drops, d)
	}
	if _, _, err := fx.s2.Svc.Events.Subscribe("cap"); err == nil {
		t.Fatal("cap not enforced")
	}
	for _, d := range drops {
		d()
	}
}
