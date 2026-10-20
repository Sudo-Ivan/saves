// SPDX-License-Identifier: 0BSD

// Package ctl is the daemon's loopback control API.
package ctl

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/daemon"
)

// Server is the local control endpoint.
type Server struct {
	d     *daemon.Daemon
	token string
	srv   *http.Server
	ln    net.Listener
}

// Endpoint file data.
type Endpoint struct {
	PID     int    `json:"pid"`
	Addr    string `json:"addr"`
	Token   string `json:"token"`
	Version string `json:"version"`
}

// New creates a ctl server on a random loopback port.
func New(d *daemon.Daemon) *Server {
	return &Server{d: d, token: mustToken()}
}

func mustToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Start binds and serves, writing the endpoint file to runtimeDir.
func (s *Server) Start(runtimeDir string) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	s.ln = ln
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", s.guard(s.hStatus))
	mux.HandleFunc("GET /games", s.guard(s.hGames))
	mux.HandleFunc("GET /logs", s.guard(s.hLogs))
	mux.HandleFunc("POST /sync", s.guard(s.hSync))
	mux.HandleFunc("POST /pause", s.guard(s.hPause))
	mux.HandleFunc("POST /resume", s.guard(s.hResume))
	mux.HandleFunc("POST /stop", s.guard(s.hStop))
	mux.HandleFunc("GET /conflicts", s.guard(s.hConflicts))
	mux.HandleFunc("POST /conflicts/resolve", s.guard(s.hResolve))
	mux.HandleFunc("POST /rescan", s.guard(s.hRescan))
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}
	go s.srv.Serve(ln)
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return "", err
	}
	ep := filepath.Join(runtimeDir, "daemon.json")
	b, _ := json.Marshal(Endpoint{PID: os.Getpid(),
		Addr: ln.Addr().String(), Token: s.token, Version: "0"})
	if err := os.WriteFile(ep, b, 0o600); err != nil {
		return "", err
	}
	return ln.Addr().String(), nil
}

// Stop closes the listener.
func (s *Server) Stop() {
	_ = s.srv.Close()
	s.d.Stop()
}

// guard enforces loopback + bearer + host/origin checks.
func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" && subtle.ConstantTimeCompare(
			[]byte(r.Header.Get("Authorization")),
			[]byte("Bearer "+s.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			http.Error(w, "no origin allowed", http.StatusForbidden)
			return
		}
		host := r.Host
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if host != "127.0.0.1" && host != "localhost" && host != "" {
			http.Error(w, "bad host", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

func (s *Server) hStatus(w http.ResponseWriter, r *http.Request) {
	paused, games := s.d.Status()
	json.NewEncoder(w).Encode(map[string]any{ // #nosec G104 -- best effort, error is not actionable
		"paused": paused, "games": games, "server_reachable": s.d.Reachable()})
}
func (s *Server) hGames(w http.ResponseWriter, r *http.Request) {
	_, games := s.d.Status()
	_ = json.NewEncoder(w).Encode(games)
}
func (s *Server) hLogs(w http.ResponseWriter, r *http.Request) {
	if v := r.URL.Query().Get("since"); v != "" {
		var id int64
		_, _ = fmt.Sscanf(v, "%d", &id)
		_ = json.NewEncoder(w).Encode(s.d.LogsSince(id))
		return
	}
	n := 100
	_, _ = fmt.Sscanf(r.URL.Query().Get("n"), "%d", &n)
	_ = json.NewEncoder(w).Encode(s.d.Logs(n))
}
func (s *Server) hSync(w http.ResponseWriter, r *http.Request) {
	var b struct{ Game string }
	_ = json.NewDecoder(r.Body).Decode(&b)
	go s.d.SyncNow(b.Game)
	w.WriteHeader(202)
}
func (s *Server) hPause(w http.ResponseWriter, r *http.Request) {
	var b struct{ Game string }
	_ = json.NewDecoder(r.Body).Decode(&b)
	s.d.Pause(b.Game)
	w.WriteHeader(204)
}
func (s *Server) hResume(w http.ResponseWriter, r *http.Request) {
	var b struct{ Game string }
	_ = json.NewDecoder(r.Body).Decode(&b)
	s.d.Resume(b.Game)
	w.WriteHeader(204)
}
func (s *Server) hStop(w http.ResponseWriter, r *http.Request) {
	go s.Stop()
	w.WriteHeader(204)
}
func (s *Server) hResolve(w http.ResponseWriter, r *http.Request) {
	var b struct{ Game, Choice string }
	_ = json.NewDecoder(r.Body).Decode(&b)
	if err := s.d.Resolve(b.Game, b.Choice); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.WriteHeader(204)
}
func (s *Server) hRescan(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(202)
}
func (s *Server) hConflicts(w http.ResponseWriter, r *http.Request) {
	_, games := s.d.Status()
	var c []string
	for k, g := range games {
		if g.Conflict {
			c = append(c, k)
		}
	}
	_ = json.NewEncoder(w).Encode(c)
}
