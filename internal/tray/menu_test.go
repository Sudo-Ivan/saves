// SPDX-License-Identifier: 0BSD

package tray

import (
	"testing"
)

func TestMenuStates(t *testing.T) {
	for _, tc := range []struct {
		s    Status
		want string
	}{
		{Status{Running: true, ServerReachable: true}, "Up to date"},
		{Status{Running: false}, "Daemon stopped"},
		{Status{Running: true, ServerReachable: false}, "Server unreachable"},
		{Status{Running: true, ServerReachable: true, Conflicts: []string{"g/s"}}, "1 conflicts"},
		{Status{Running: true, ServerReachable: true, Paused: true}, "Paused"},
		{Status{Running: true, ServerReachable: true,
			Games: map[string]GameState{"g/s": {ID: "g/s", State: "syncing"}}}, "Syncing 1"},
	} {
		m := BuildMenu(tc.s)
		if m[0].Label != tc.want {
			t.Fatalf("state %v: got %q", tc, m[0].Label)
		}
	}
	m := BuildMenu(Status{Running: true, ServerReachable: true,
		Games: map[string]GameState{"a/w": {ID: "a/w", State: "error", LastError: "x"}}})
	var games *Item
	for i := range m {
		if m[i].ID == "games" {
			games = &m[i]
		}
	}
	if games == nil || len(games.Sub) != 1 {
		t.Fatal("games submenu missing")
	}
	if len(games.Sub[0].Sub) != 4 {
		t.Fatalf("game submenu %d items", len(games.Sub[0].Sub))
	}
	if AggregateState(Status{Running: true, ServerReachable: true,
		Conflicts: []string{"x"}}) != "conflict" {
		t.Fatal("aggregate")
	}
}
