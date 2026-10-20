// SPDX-License-Identifier: 0BSD

// Package events is a per-user publish/subscribe hub for server-sent
// events. With several nodes an event only reaches subscribers connected
// to the node that handled the commit; clients must also poll slowly.
package events

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

// Event is one SSE record.
type Event struct {
	ID   int64
	Type string
	Data []byte
}

// ErrLag is delivered as a "lag" event when a subscriber is dropped.
var ErrLag = errors.New("events: lagged behind")

// Hub fans events out to per-user subscriber channels.
type Hub struct {
	max    int
	buf    int
	mu     sync.Mutex
	subs   map[string]map[chan Event]struct{}
	nextID atomic.Int64
	open   atomic.Int64
	closed atomic.Bool
}

// New makes a hub with per-user subscriber cap and channel buffer.
func New(maxPerUser, buf int) *Hub {
	return &Hub{max: maxPerUser, buf: buf, subs: map[string]map[chan Event]struct{}{}}
}

// ErrFull is returned when the per-user cap is hit.
var ErrFull = errors.New("events: too many streams for user")

// Subscribe registers a buffered channel for user.
func (h *Hub) Subscribe(user string) (chan Event, func(), error) {
	if h.closed.Load() {
		return nil, nil, ErrLag
	}
	h.mu.Lock()
	set := h.subs[user]
	if set == nil {
		set = map[chan Event]struct{}{}
		h.subs[user] = set
	}
	if h.max > 0 && len(set) >= h.max {
		h.mu.Unlock()
		return nil, nil, ErrFull
	}
	ch := make(chan Event, h.buf)
	set[ch] = struct{}{}
	h.mu.Unlock()
	h.open.Add(1)
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(set, ch)
			if len(set) == 0 {
				delete(h.subs, user)
			}
			h.mu.Unlock()
			close(ch)
			h.open.Add(-1)
		})
	}, nil
}

// Publish delivers the event to every subscriber of user.
// Slow subscribers get the oldest buffer entry replaced by a lag event.
func (h *Hub) Publish(user, typ string, data []byte) {
	if h.closed.Load() {
		return
	}
	id := h.nextID.Add(1)
	h.mu.Lock()
	for ch := range h.subs[user] {
		select {
		case ch <- Event{ID: id, Type: typ, Data: data}:
		default:
			// Drop oldest, then inject a lag notice so the client resyncs.
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- Event{ID: id, Type: "lag"}:
			default:
			}
		}
	}
	h.mu.Unlock()
}

// Open reports current stream count.
func (h *Hub) Open() int64 { return h.open.Load() }

// Close shuts the hub; all subscriber channels close.
func (h *Hub) Close() {
	if h.closed.Swap(true) {
		return
	}
	h.mu.Lock()
	for user, set := range h.subs {
		for ch := range set {
			close(ch)
		}
		delete(h.subs, user)
	}
	h.mu.Unlock()
}

// WaitClosed blocks until ctx is done (used to drain streams).
func (h *Hub) WaitClosed(ctx context.Context) { <-ctx.Done() }
