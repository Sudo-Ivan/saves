// SPDX-License-Identifier: 0BSD

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net"
	"net/http"
	"net/http/pprof"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Runner serves the configured listeners and shuts down gracefully.
type Runner struct {
	srv *Server
	cfg *config.Config

	tlsCfg   *tls.Config
	certFile atomic.Pointer[tls.Certificate]
	acme     *autocert.Manager
	srvTCP   *http.Server
	lnTCP    net.Listener
	h3       *http3.Server // HTTP/3 server when enabled
	h3Addr   string        // bound UDP address
	notReady chan struct{} // closed when draining starts
}

// TLS material with hot reload support.
func (r *Runner) loadTLS(ctx context.Context) error {
	t := r.cfg.Listen.TLS
	minv := uint16(tls.VersionTLS12)
	switch t.MinVersion {
	case "1.3":
		minv = tls.VersionTLS13
	case "", "1.2":
	default:
		return fmt.Errorf("server: bad min_version %q", t.MinVersion)
	}
	switch t.Mode {
	case "none", "":
		if !isLoopback(r.cfg.Listen.Addr) {
			r.srv.Log.Warn("tls disabled on non-loopback listener", "addr", r.cfg.Listen.Addr)
		}
		return nil
	case "files":
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return fmt.Errorf("server: tls: %w", err)
		}
		r.certFile.Store(&cert)
		r.tlsCfg = &tls.Config{
			MinVersion: minv,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return r.certFile.Load(), nil
			},
			NextProtos: []string{"h2", "http/1.1", "h3"},
		}
		return nil
	case "acme":
		// The ACME account HTTP client goes through netx so MPTCP is
		// off for the Landlock profile.
		m := &autocert.Manager{
			Cache:      autocert.DirCache(t.ACME.CacheDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(t.ACME.Hosts...),
			Email:      t.ACME.Email,
			Client:     &acme.Client{HTTPClient: &http.Client{Transport: netx.NewTransport()}},
		}
		r.acme = m
		r.tlsCfg = m.TLSConfig()
		r.tlsCfg.MinVersion = minv
		return nil
	}
	return fmt.Errorf("server: unknown tls mode %q", t.Mode)
}

// ReloadCert re-reads cert files for mode files hot reload.
func (r *Runner) ReloadCert() error {
	t := r.cfg.Listen.TLS
	if t.Mode != "files" {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return err
	}
	r.certFile.Store(&cert)
	return nil
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" || host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Listen binds sockets and returns when all are serving.
func (r *Runner) Listen(ctx context.Context) error {
	lc := netx.ListenConfig()
	ln, err := lc.Listen(ctx, "tcp", r.cfg.Listen.Addr)
	if err != nil {
		return fmt.Errorf("server: listen %s: %w", r.cfg.Listen.Addr, err)
	}
	r.lnTCP = ln
	protos := new(http.Protocols)
	h1, h2, h2c, wantH3 := len(r.cfg.Listen.Protocols) == 0, false, false, false
	for _, p := range r.cfg.Listen.Protocols {
		switch p {
		case "h1":
			h1 = true
		case "h2":
			h2 = true
		case "h2c":
			h2c = true
		case "h3":
			wantH3 = true
		}
	}
	if h1 {
		protos.SetHTTP1(true)
	}
	if h2 {
		protos.SetHTTP2(true)
	}
	if h2c {
		protos.SetUnencryptedHTTP2(true)
	}
	if err := r.loadTLS(ctx); err != nil {
		return err
	}
	r.srvTCP = &http.Server{
		Handler:           r.srv.Handler(),
		Protocols:         protos,
		ReadHeaderTimeout: r.cfg.Listen.ReadHeaderTimeout.Duration(),
		IdleTimeout:       r.cfg.Listen.IdleTimeout.Duration(),
		MaxHeaderBytes:    int(r.cfg.Listen.MaxHeaderBytes.Int64()),
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: int(r.cfg.Listen.H2.MaxConcurrentStreams)},
	}
	if r.tlsCfg != nil {
		r.lnTCP = tls.NewListener(ln, r.tlsCfg)
	}
	if r.acme != nil {
		// HTTP-01 challenge responder bound through netx.
		chln, err := netx.ListenConfig().Listen(ctx, "tcp", ":80")
		if err != nil {
			return fmt.Errorf("server: acme http-01 listener: %w", err)
		}
		chsrv := &http.Server{Handler: r.acme.HTTPHandler(nil), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			_ = chsrv.Serve(chln)
		}()
	}
	if wantH3 {
		if r.tlsCfg == nil {
			return errors.New("server: h3 requires TLS")
		}
		uaddr := r.cfg.Listen.H3Addr
		if uaddr == "" {
			uaddr = r.cfg.Listen.Addr
		}
		uc, err := netx.ListenUDP(ctx, uaddr, int(r.cfg.Listen.UDPBufferBytes.Int64()))
		if err != nil {
			return fmt.Errorf("server: h3 listen %s: %w", uaddr, err)
		}
		h3s := &http3.Server{
			Handler:   r.srv.Handler(),
			TLSConfig: r.tlsCfg,
		}
		r.h3 = h3s
		r.h3Addr = uc.LocalAddr().String()
		go func() {
			_ = h3s.Serve(uc)
		}()
	}
	return nil
}

// Serve blocks until ctx is done or an error occurs, then drains.
func (r *Runner) Serve(ctx context.Context) error {
	errCh := make(chan error, 2)
	go func() {
		err := r.srvTCP.Serve(r.lnTCP)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	<-ctx.Done()
	close(r.notReady)
	r.srv.draining.Store(true)
	drain := r.cfg.Listen.ShutdownTimeout.Duration()
	if drain <= 0 {
		drain = 30 * time.Second
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), drain)
	defer cancel()
	_ = r.srvTCP.Shutdown(shutdownCtx)
	return <-errCh
}

// H3Addr returns the bound UDP address, or empty.
func (r *Runner) H3Addr() string { return r.h3Addr }

// Draining reports whether shutdown began.
func (r *Runner) Draining() bool {
	select {
	case <-r.notReady:
		return true
	default:
		return false
	}
}

// OpsMux returns the ops listener handler.
func (s *Server) OpsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", s.hReadyz)
	if s.Cfg.Metrics.Enabled {
		mux.Handle("GET /metrics", promhttp.HandlerFor(s.Met.Reg, promhttp.HandlerOpts{}))
	}
	if s.Cfg.Ops.Pprof {
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	}
	return mux
}

func (s *Server) hReadyz(w http.ResponseWriter, r *http.Request) {
	if s.draining.Load() {
		http.Error(w, "draining", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.Meta.Ping(ctx); err != nil {
		http.Error(w, "meta down", http.StatusServiceUnavailable)
		return
	}
	// Probe blob store with a stat on a nonexistent key (must return
	// ErrNotFound, not a real error).
	_, err := s.Blob.Stat(ctx, "u/__probe__/c/0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil && !errors.Is(err, blob.ErrNotFound) {
		http.Error(w, "blob down", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(200)
	_, _ = w.Write([]byte("ready"))
}

// NewRunner bundles server+config for the listener lifecycle.
func NewRunner(s *Server, cfg *config.Config) *Runner {
	return &Runner{srv: s, cfg: cfg, notReady: make(chan struct{})}
}

var _ = filepath.Join // reserved for acme cache paths
