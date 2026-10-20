// SPDX-License-Identifier: 0BSD

package client

import (
	"bufio"
	"context"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ServerEvent is one server-sent record.
type ServerEvent struct {
	ID   int64
	Type string
	Data []byte
}

// Events streams server events until ctx is done, reconnecting with
// exponential backoff (cap 60 s) and resuming from Last-Event-ID.
// The returned channel is closed when ctx ends or the stream errors.
func (c *Client) Events(ctx context.Context) <-chan ServerEvent {
	out := make(chan ServerEvent, 16)
	go func() {
		defer close(out)
		var lastID int64
		delay := 250 * time.Millisecond
		for {
			if ctx.Err() != nil {
				return
			}
			if err := c.eventsOnce(ctx, out, &lastID); err != nil {
				select {
				case out <- ServerEvent{Type: "error", Data: []byte(err.Error())}:
				case <-ctx.Done():
				}
			}
			j := time.Duration(rand.Int63n(int64(delay) / 4))
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay + j):
			}
			delay *= 2
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}
		}
	}()
	return out
}

// eventsOnce reads one SSE stream until it ends.
func (c *Client) eventsOnce(ctx context.Context, out chan<- ServerEvent, lastID *int64) error {
	r, err := http.NewRequestWithContext(ctx, "GET", c.cfg.BaseURL+"/v1/events", nil)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	if *lastID != 0 {
		r.Header.Set("Last-Event-ID", strconv.FormatInt(*lastID, 10))
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return decodeErrResp(resp)
	}
	sc := bufio.NewScanner(resp.Body)
	var typ string
	var data strings.Builder
	dispatch := func() bool {
		if typ == "" && data.Len() == 0 {
			return true
		}
		if typ != "" && typ != "lag" && typ != "head" && typ != "slot_deleted" && typ != "error" {
			typ, data = "", strings.Builder{}
			return true
		}
		id := *lastID
		select {
		case out <- ServerEvent{ID: id, Type: typ, Data: []byte(data.String())}:
		case <-ctx.Done():
			return false
		}
		typ, data = "", strings.Builder{}
		return true
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if !dispatch() {
				return ctx.Err()
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		k, v, _ := strings.Cut(line, ": ")
		switch k {
		case "id":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				*lastID = n
			}
		case "event":
			typ = v
		case "data":
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(v)
		}
	}
	return sc.Err()
}

func decodeErrResp(resp *http.Response) error {
	return &APIError{Status: resp.StatusCode}
}
