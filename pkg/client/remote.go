// SPDX-License-Identifier: 0BSD

package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"

	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Remote is a snapshot source: the saves server or a peer.
type Remote interface {
	Head(ctx context.Context, app, slot string) (string, error)
	Manifest(ctx context.Context, app, slot, id string) (*api.Manifest, error)
	Chunk(ctx context.Context, app string, h api.Hash, off, n int64) (io.ReadCloser, error)
}

// serverRemote adapts the client to the saves server API.
type serverRemote struct{ c *Client }

func (r serverRemote) Head(ctx context.Context, app, slot string) (string, error) {
	for s := range mustIter(r.c.ListSnapshots(ctx, app, slot)) {
		return s.ID, nil
	}
	return "", nil
}

func (r serverRemote) Manifest(ctx context.Context, app, slot, id string) (*api.Manifest, error) {
	return r.c.GetManifest(ctx, app, slot, id)
}

func (r serverRemote) Chunk(ctx context.Context, app string, h api.Hash, off, n int64) (io.ReadCloser, error) {
	b, err := r.c.chunk(ctx, app, h)
	if err != nil {
		return nil, err
	}
	lo := min64(off, int64(len(b)))
	hi := min64(off+n, int64(len(b)))
	return io.NopCloser(bytes.NewReader(b[lo:hi])), nil
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// remote is the default for all exported calls.
func (c *Client) remote() Remote { return serverRemote{c} }

var _ = hex.EncodeToString
