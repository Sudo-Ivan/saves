// SPDX-License-Identifier: 0BSD

package metatest

import (
	"context"
	"errors"
	"testing"

	"github.com/Sudo-Ivan/saves/internal/meta"
)

// vaultRoundTrip is shared by driver tests via metatest.
func VaultRoundTrip(t *testing.T, st meta.Store) {
	t.Helper()
	ctx := context.Background()
	u, _, _ := st.UpsertUser(ctx, "vu", "free")
	_, err := st.GetVault(ctx, u.ID)
	if !errors.Is(err, meta.ErrNotFound) {
		t.Fatal("want notfound")
	}
	v1, err := st.PutVault(ctx, u.ID, []byte(`{"kid":"k1"}`), "k1", nil)
	if err != nil || v1 != 1 {
		t.Fatalf("put %d %v", v1, err)
	}
	v2, err := st.PutVault(ctx, u.ID, []byte(`{"kid":"k2"}`), "k2", &v1)
	if err != nil || v2 != 2 {
		t.Fatalf("cas %d %v", v2, err)
	}
	// stale version
	bad := int64(1)
	if _, err := st.PutVault(ctx, u.ID, []byte(`x`), "k", &bad); !errors.Is(err, meta.ErrVersionMismatch) {
		t.Fatalf("want version mismatch got %v", err)
	}
	// big header
	if _, err := st.PutVault(ctx, u.ID, make([]byte, 8193), "k", &v2); err == nil {
		t.Fatal("accepted >8192")
	}
	// cross user
	u2, _, _ := st.UpsertUser(ctx, "vu2", "free")
	if _, err := st.GetVault(ctx, u2.ID); !errors.Is(err, meta.ErrNotFound) {
		t.Fatal("isolation")
	}
	if err := st.DeleteVault(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetVault(ctx, u.ID); !errors.Is(err, meta.ErrNotFound) {
		t.Fatal("after delete")
	}
}
