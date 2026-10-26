// SPDX-License-Identifier: 0BSD

package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/internal/gc"
)

// opState is the outcome of a long admin operation.
type opState struct {
	Running bool
	At      time.Time
	Summary string
	Issues  []string
	Err     string
}

type adminOps struct {
	mu    sync.Mutex
	fsck  opState
	gcRun opState
}

// FsckState returns the last integrity check result.
func (s *Server) FsckState() opState {
	s.ops.mu.Lock()
	defer s.ops.mu.Unlock()
	return s.ops.fsck
}

// GCState returns the last admin-triggered GC result.
func (s *Server) GCState() opState {
	s.ops.mu.Lock()
	defer s.ops.mu.Unlock()
	return s.ops.gcRun
}

// RunFsck starts a background integrity check unless one is running.
func (s *Server) RunFsck() bool {
	s.ops.mu.Lock()
	if s.ops.fsck.Running {
		s.ops.mu.Unlock()
		return false
	}
	s.ops.fsck = opState{Running: true, At: s.now()}
	s.ops.mu.Unlock()
	go func() {
		rep, err := s.Meta.Fsck(context.Background(), false)
		st := opState{At: s.now()}
		if err != nil {
			st.Err = "The check could not complete."
			s.Log.Error("admin fsck", "err", err)
		} else {
			st.Issues = rep.Issues
			if len(rep.Issues) == 0 {
				st.Summary = "No problems found."
			} else {
				st.Summary = fmt.Sprintf("%d problems found.", len(rep.Issues))
			}
		}
		s.ops.mu.Lock()
		s.ops.fsck = st
		s.ops.mu.Unlock()
	}()
	return true
}

// RunGC runs one collection and records the report.
func (s *Server) RunGC(ctx context.Context) error {
	if s.gc == nil {
		return errors.New("gc unavailable")
	}
	rep, err := s.gc.RunOnce(ctx)
	st := opState{At: s.now()}
	if err != nil {
		st.Err = "Collection failed."
	} else {
		st.Summary = gcSummary(rep)
	}
	s.ops.mu.Lock()
	s.ops.gcRun = st
	s.ops.mu.Unlock()
	return err
}

func gcSummary(r gc.Report) string {
	if !r.LeaseHeld {
		return "Another node holds the collection lease."
	}
	return fmt.Sprintf("Removed %d chunks, %d manifests, %d expired uploads, %d purged users.",
		r.ChunksDeleted, r.ManifestsDeleted, r.ExpiredPending, r.UsersPurged)
}

// BackupEnabled reports whether a backup directory is configured for sqlite.
func (s *Server) BackupEnabled() bool {
	return s.Cfg.Storage.Meta.Driver == "sqlite" && s.Cfg.Admin.BackupDir != ""
}

// RunBackupMeta copies the sqlite database into the backup directory and
// keeps the newest seven files.
func (s *Server) RunBackupMeta(ctx context.Context) (string, error) {
	if !s.BackupEnabled() {
		return "", errors.New("backup directory is not configured")
	}
	dir := s.Cfg.Admin.BackupDir
	out := filepath.Join(dir, "saves-meta-"+s.now().UTC().Format("20060102T150405Z")+".db")
	db, err := sql.Open("sqlite", s.Cfg.Storage.Meta.SQLite.Path)
	if err != nil {
		return "", err
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", out); err != nil {
		return "", err
	}
	_ = os.Chmod(out, 0o600)
	ents, _ := filepath.Glob(filepath.Join(dir, "saves-meta-*.db"))
	sort.Strings(ents)
	for len(ents) > 7 {
		_ = os.Remove(ents[0])
		ents = ents[1:]
	}
	return strings.TrimPrefix(out, dir+string(filepath.Separator)), nil
}

// diskUsage reports free and total bytes of the filesystem holding path.
func diskUsage(path string) (free, total uint64, ok bool) { return statfs(path) }
