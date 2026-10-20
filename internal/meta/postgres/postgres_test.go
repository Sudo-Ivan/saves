// SPDX-License-Identifier: 0BSD

package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/metatest"
	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
)

func TestConformance(t *testing.T) {
	dsn := os.Getenv("SAVES_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SAVES_TEST_POSTGRES_DSN not set")
	}
	admin, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("no postgres: %v", err)
	}
	defer admin.Close()
	ctx := context.Background()
	boot, err := Open(ctx, dsn, 4, 1, meta.Options{})
	if err != nil {
		t.Skipf("no postgres: %v", err)
	}
	if err := boot.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	boot.Close()
	metatest.Run(t, func(t *testing.T, c *testclock.Clock) meta.Store {
		if _, err := admin.Exec(ctx, `TRUNCATE users, tokens, usage, slots, snapshots, snapshot_chunks, chunks, manifests, leases`); err != nil {
			t.Fatal(err)
		}
		s, err := Open(context.Background(), dsn, 8, 1, meta.Options{Clock: c.NowFunc()})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	})
}
