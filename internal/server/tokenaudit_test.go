package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/sqlite"
)

type countingStore struct {
	meta.Store
	mu      sync.Mutex
	upserts int
	batch   []meta.UsageRow
	events  []meta.TokenEvent
	gate    chan struct{}
}

func (c *countingStore) UpsertTokenUsage(ctx context.Context, b []meta.UsageRow) ([]meta.UsagePair, error) {
	c.mu.Lock()
	c.upserts++
	c.batch = b
	c.mu.Unlock()
	return c.Store.UpsertTokenUsage(ctx, b)
}
func (c *countingStore) InsertTokenEvent(ctx context.Context, e meta.TokenEvent) error {
	if c.gate != nil {
		<-c.gate
	}
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
	return c.Store.InsertTokenEvent(ctx, e)
}

func auditStore(t *testing.T) (*countingStore, meta.Store) {
	st, err := sqlite.Open(t.TempDir()+"/a.db", meta.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &countingStore{Store: st}, st
}

func (c *countingStore) nUpserts() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.upserts
}
func (c *countingStore) lastBatch() []meta.UsageRow {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.batch
}

func reqFrom(ip string) *http.Request {
	r := httptest.NewRequest("GET", "/v1/x", nil)
	r.RemoteAddr = ip + ":9"
	return r
}

func TestTokenAuditHotPathNoWrites(t *testing.T) {
	cs, _ := auditStore(t)
	a := NewTokenAudit(cs, nil, nil, "", time.Now)
	defer a.Close(context.Background())
	for i := 0; i < 1000; i++ {
		a.Add("t1", reqFrom("10.0.0.1"), time.Now())
	}
	if cs.nUpserts() != 0 {
		t.Fatalf("hot path wrote %d times", cs.nUpserts())
	}
}

func TestTokenAuditFlush(t *testing.T) {
	cs, _ := auditStore(t)
	now := time.Now()
	a := NewTokenAudit(cs, nil, nil, "", func() time.Time { return now })
	a.mu.Lock()
	a.interval = time.Hour // only explicit flushes
	a.mu.Unlock()
	for i := 0; i < 5; i++ {
		a.Add("t1", reqFrom("10.0.0.1"), now)
		a.Add("t1", reqFrom("10.0.0.2"), now)
	}
	a.Close(context.Background())
	if cs.nUpserts() != 1 {
		t.Fatalf("upserts=%d", cs.nUpserts())
	}
	var got3 int64
	for _, r := range cs.lastBatch() {
		if r.IP == "10.0.0.1" {
			got3 = r.Requests
		}
	}
	if got3 != 5 {
		t.Fatalf("requests=%d", got3)
	}
}
