// SPDX-License-Identifier: 0BSD

package tray

// UI is the systray adapter surface so tests need no real tray.
type UI interface {
	SetIcon(png []byte)
	AddItem(label string, disabled, checked bool) ItemHandle
	AddSeparator()
	Quit()
}

// ItemHandle is one menu row.
type ItemHandle interface {
	SetSub(items []Item) []ItemHandle
	Click() <-chan struct{}
}

// Click maps item ids to handler actions.
func Click(id string) (action, game, choice string) {
	for _, pre := range []string{"sync:", "pause:", "resume:", "open:", "resolve:"} {
		if len(id) > len(pre) && id[:len(pre)] == pre {
			rest := id[len(pre):]
			return pre[:len(pre)-1], rest, ""
		}
	}
	return id, "", ""
}
