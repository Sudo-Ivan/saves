// SPDX-License-Identifier: 0BSD

// Package tray renders the daemon status into a systray menu model.
package tray

import (
	"fmt"
	"strings"
)

// Status is the daemon status snapshot the tray renders.
type Status struct {
	Paused          bool
	ServerReachable bool
	Running         bool
	Games           map[string]GameState
	Conflicts       []string
}

// GameState mirrors daemon.GameStatus.
type GameState struct {
	ID, Slot, State, LastError string
}

// Item is one menu entry.
type Item struct {
	ID       string
	Label    string
	Disabled bool
	Checked  bool
	Sub      []Item
}

// BuildMenu renders the full menu for the given status.
func BuildMenu(s Status) []Item {
	var out []Item
	line := "Up to date"
	switch {
	case !s.Running:
		line = "Daemon stopped"
	case !s.ServerReachable:
		line = "Server unreachable"
	case len(s.Conflicts) > 0:
		line = fmt.Sprintf("%d conflicts", len(s.Conflicts))
	case s.Paused:
		line = "Paused"
	default:
		n := 0
		for _, g := range s.Games {
			if g.State == "syncing" {
				n++
			}
		}
		if n > 0 {
			line = fmt.Sprintf("Syncing %d", n)
		}
	}
	out = append(out, Item{ID: "status", Label: line, Disabled: true})
	out = append(out, Item{ID: "sync-all", Label: "Sync now", Disabled: !s.Running})
	if s.Paused {
		out = append(out, Item{ID: "resume-all", Label: "Resume all", Disabled: !s.Running})
	} else {
		out = append(out, Item{ID: "pause-all", Label: "Pause all", Disabled: !s.Running})
	}
	// games submenu
	var gs []Item
	for _, g := range s.Games {
		glyph := ""
		switch g.State {
		case "error":
			glyph = " !"
		case "conflict":
			glyph = " ?"
		case "syncing":
			glyph = " ~"
		case "paused":
			glyph = " ||"
		case "locked":
			glyph = " #"
		}
		sub := []Item{
			{ID: "sync:" + g.ID, Label: "Sync now"},
		}
		if g.State == "paused" {
			sub = append(sub, Item{ID: "resume:" + g.ID, Label: "Resume"})
		} else {
			sub = append(sub, Item{ID: "pause:" + g.ID, Label: "Pause"})
		}
		sub = append(sub, Item{ID: "open:" + g.ID, Label: "Open save folder"})
		if g.LastError != "" {
			sub = append(sub, Item{ID: "err:" + g.ID, Label: "Last error: " + g.LastError, Disabled: true})
		}
		gs = append(gs, Item{ID: "game:" + g.ID, Label: g.ID + glyph, Sub: sub})
	}
	if len(gs) > 0 {
		out = append(out, Item{ID: "games", Label: "Games", Sub: gs})
	}
	if len(s.Conflicts) > 0 {
		var cs []Item
		for _, c := range s.Conflicts {
			cs = append(cs, Item{ID: "conflict:" + c, Label: c, Sub: []Item{
				{ID: "resolve:" + c + ":keep-local", Label: "Keep local"},
				{ID: "resolve:" + c + ":keep-remote", Label: "Keep remote"},
				{ID: "resolve:" + c + ":keep-newest", Label: "Keep newest"},
			}})
		}
		out = append(out, Item{ID: "conflicts", Label: "Conflicts", Sub: cs})
	}
	out = append(out, Item{ID: "logs", Label: "Open logs"})
	out = append(out, Item{ID: "config", Label: "Open config folder"})
	out = append(out, Item{ID: "autostart", Label: "Start at login"})
	if s.Running {
		out = append(out, Item{ID: "stop", Label: "Stop daemon"})
	} else {
		out = append(out, Item{ID: "start", Label: "Start daemon"})
	}
	out = append(out, Item{ID: "quit", Label: "Quit tray"})
	return out
}

// AggregateState picks the tray icon state.
func AggregateState(s Status) string {
	switch {
	case !s.Running:
		return "offline"
	case !s.ServerReachable:
		return "offline"
	case len(s.Conflicts) > 0:
		return "conflict"
	case s.Paused:
		return "paused"
	default:
		for _, g := range s.Games {
			if g.State == "syncing" || strings.HasSuffix(g.ID, "~") {
				return "syncing"
			}
			if g.State == "error" {
				return "error"
			}
		}
		return "ok"
	}
}
