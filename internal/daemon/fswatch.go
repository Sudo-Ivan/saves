// SPDX-License-Identifier: 0BSD

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// FSWatch is a real recursive watcher on fsnotify.
type FSWatch struct {
	// Fallback reports whether inotify exhaustion was hit and the
	// watcher degraded to periodic rescans.
	Fallback atomic.Bool
	Ignore   func(path string) bool
}

// Watch adds dir recursively and reports changed paths.
func (w *FSWatch) Watch(ctx context.Context, dir string) (<-chan string, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	out := make(chan string, 64)
	add := func(root string) {
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				_ = fw.Add(p)
			}
			return nil
		})
	}
	add(dir)
	go func() {
		defer close(out)
		defer fw.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-fw.Events:
				if !ok {
					return
				}
				if w.Ignore != nil && w.Ignore(ev.Name) {
					continue
				}
				if ev.Has(fsnotify.Create) {
					if st, err := os.Stat(ev.Name); err == nil && st.IsDir() {
						add(ev.Name)
					}
				}
				select {
				case out <- ev.Name:
				default:
				}
			case err, ok := <-fw.Errors:
				if !ok {
					return
				}
				// inotify exhaustion: degrade to rescan.
				w.Fallback.Store(true)
				_ = err
				rescan := time.NewTicker(60 * time.Second)
				defer rescan.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-rescan.C:
						select {
						case out <- ".":
						default:
						}
					}
				}
			}
		}
	}()
	return out, nil
}
