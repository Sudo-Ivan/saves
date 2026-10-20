// SPDX-License-Identifier: 0BSD

package tray

import (
	"fyne.io/systray"
)

// SysUI is the real systray implementation of UI.
type SysUI struct{}

// Run starts the tray; blocks until Quit.
func (SysUI) Run(onReady, onExit func()) { systray.Run(onReady, onExit) }

// sysItem wraps a systray MenuItem.
type sysItem struct{ mi *systray.MenuItem }

var _ ItemHandle = (*sysItem)(nil)

func (s *sysItem) SetSub(items []Item) []ItemHandle {
	var out []ItemHandle
	var build func(p *systray.MenuItem, its []Item)
	build = func(p *systray.MenuItem, its []Item) {
		for _, it := range its {
			mi := p.AddSubMenuItem(it.Label, "")
			if it.Disabled {
				mi.Disable()
			}
			if it.Checked {
				mi.Check()
			}
			if len(it.Sub) > 0 {
				build(mi, it.Sub)
			}
			out = append(out, &sysItem{mi: mi})
		}
	}
	build(s.mi, items)
	return out
}

func (s *sysItem) Click() <-chan struct{} { return s.mi.ClickedCh }

// Apply diffs and rebuilds the menu from a fresh model.
func Apply(ui *SysUI, items []Item, onClick func(string)) {
	systray.ResetMenu()
	var walk func(parent *systray.MenuItem, items []Item)
	buildOne := func(parent *systray.MenuItem, it Item) {
		var mi *systray.MenuItem
		if parent != nil {
			mi = parent.AddSubMenuItem(it.Label, "")
		} else {
			mi = systray.AddMenuItem(it.Label, "")
		}
		if it.Disabled {
			mi.Disable()
		}
		if it.Checked {
			mi.Check()
		}
		if len(it.Sub) == 0 {
			id := it.ID
			go func() {
				for range mi.ClickedCh {
					onClick(id)
				}
			}()
		}
		walk(mi, it.Sub)
	}
	walk = func(parent *systray.MenuItem, items []Item) {
		for _, it := range items {
			buildOne(parent, it)
		}
	}
	walk(nil, items)
}

// SetIcon sets the tray icon and tooltip.
func SetIconPNG(png []byte) { systray.SetIcon(png) }
func SetTooltip(s string)   { systray.SetTooltip(s) }
func Quit()                 { systray.Quit() }
