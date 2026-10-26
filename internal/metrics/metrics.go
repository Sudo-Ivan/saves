// SPDX-License-Identifier: 0BSD

// Package metrics wires the service, blob, meta, auth, and gc
// instrumentation points to an isolated Prometheus registry.
package metrics

import (
	"context"
	"io"
	"time"

	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/pkg/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics is the shared collector set plus service.Metrics impl.
type Metrics struct {
	Reg            *prometheus.Registry
	opLatency      *prometheus.HistogramVec
	authFails      *prometheus.CounterVec
	gcRuns         *prometheus.CounterVec
	gcDeleted      *prometheus.CounterVec
	uploadInFlight prometheus.Gauge
	webLogins      *prometheus.CounterVec
}

// New builds a registry with go and process collectors plus build info.
func New(namespace, version string) *Metrics {
	if namespace == "" {
		namespace = "saves"
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(collectors.NewBuildInfoCollector())
	m := &Metrics{
		Reg: reg,
		opLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "service_op_seconds",
			Help:    "service operation latency",
			Buckets: prometheus.DefBuckets,
		}, []string{"op", "result"}),
		authFails: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "auth_failures_total",
			Help: "authentication failures by kind",
		}, []string{"kind"}),
		gcRuns: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "gc_runs_total",
			Help: "gc passes by outcome",
		}, []string{"result"}),
		gcDeleted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "gc_deleted_total",
			Help: "objects deleted by gc",
		}, []string{"kind"}),
		uploadInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "uploads_in_flight",
			Help: "chunk uploads in progress",
		}),
		webLogins: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "web_logins_total",
			Help: "web login attempts by result",
		}, []string{"result"}),
	}
	reg.MustRegister(m.opLatency, m.authFails, m.gcRuns, m.gcDeleted, m.uploadInFlight, m.webLogins)
	return m
}

// Observe implements service.Metrics.
func (m *Metrics) Observe(op string, err error, d time.Duration) {
	res := "ok"
	if err != nil {
		res = "error"
	}
	m.opLatency.WithLabelValues(op, res).Observe(d.Seconds())
}

// AuthFail records an auth failure kind.
func (m *Metrics) AuthFail(kind string) { m.authFails.WithLabelValues(kind).Inc() }

// GCRun records a gc pass outcome and deleted counts.
func (m *Metrics) GCRun(err error, chunks, manifests, users int) {
	res := "ok"
	if err != nil {
		res = "error"
	}
	m.gcRuns.WithLabelValues(res).Inc()
	m.gcDeleted.WithLabelValues("chunk").Add(float64(chunks))
	m.gcDeleted.WithLabelValues("manifest").Add(float64(manifests))
	m.gcDeleted.WithLabelValues("user").Add(float64(users))
}

// UploadsInFlight returns the in-flight upload gauge.
func (m *Metrics) UploadsInFlight() prometheus.Gauge { return m.uploadInFlight }

// WebLogin records a web login outcome.
func (m *Metrics) WebLogin(result string) { m.webLogins.WithLabelValues(result).Inc() }

// WrapBlob decorates a blob.Store with latency histograms.
func WrapBlob(b blob.Store, reg *prometheus.Registry, namespace string) blob.Store {
	if namespace == "" {
		namespace = "saves"
	}
	lat := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "blob_op_seconds", Help: "blob op latency",
		Buckets: prometheus.DefBuckets,
	}, []string{"op", "result"})
	reg.MustRegister(lat)
	return &blobWrap{b: b, lat: lat}
}

type blobWrap struct {
	b   blob.Store
	lat *prometheus.HistogramVec
}

func (w *blobWrap) time(op string, err error, t0 time.Time) {
	res := "ok"
	if err != nil {
		res = "error"
	}
	w.lat.WithLabelValues(op, res).Observe(time.Since(t0).Seconds())
}

func (w *blobWrap) Put(ctx context.Context, key string, r io.Reader, size int64, want *api.Hash) error {
	t0 := time.Now()
	err := w.b.Put(ctx, key, r, size, want)
	w.time("put", err, t0)
	return err
}

func (w *blobWrap) Open(ctx context.Context, key string) (blob.Object, error) {
	t0 := time.Now()
	o, err := w.b.Open(ctx, key)
	w.time("open", err, t0)
	return o, err
}

func (w *blobWrap) Stat(ctx context.Context, key string) (int64, error) {
	t0 := time.Now()
	n, err := w.b.Stat(ctx, key)
	w.time("stat", err, t0)
	return n, err
}

func (w *blobWrap) Delete(ctx context.Context, key string) error {
	t0 := time.Now()
	err := w.b.Delete(ctx, key)
	w.time("delete", err, t0)
	return err
}

func (w *blobWrap) List(ctx context.Context, prefix string, fn func(blob.Entry) error) error {
	t0 := time.Now()
	err := w.b.List(ctx, prefix, fn)
	w.time("list", err, t0)
	return err
}

func (w *blobWrap) Close() error { return w.b.Close() }

// WrapMeta decorates a meta.Store with latency histograms.
func WrapMeta(st meta.Store, reg *prometheus.Registry, namespace string) meta.Store {
	if namespace == "" {
		namespace = "saves"
	}
	lat := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "meta_op_seconds", Help: "meta op latency",
		Buckets: prometheus.DefBuckets,
	}, []string{"op", "result"})
	reg.MustRegister(lat)
	return &metaWrap{Store: st, lat: lat}
}

// metaWrap embeds the inner store and times the hot paths.
type metaWrap struct {
	meta.Store
	lat *prometheus.HistogramVec
}

func (w *metaWrap) time(op string, err error, t0 time.Time) {
	res := "ok"
	if err != nil {
		res = "error"
	}
	w.lat.WithLabelValues(op, res).Observe(time.Since(t0).Seconds())
}

func (w *metaWrap) BeginSnapshot(ctx context.Context, p meta.BeginParams) (meta.BeginResult, error) {
	t0 := time.Now()
	r, err := w.Store.BeginSnapshot(ctx, p)
	w.time("begin", err, t0)
	return r, err
}

func (w *metaWrap) MarkChunkStored(ctx context.Context, u, s string, h api.Hash, size int64) error {
	t0 := time.Now()
	err := w.Store.MarkChunkStored(ctx, u, s, h, size)
	w.time("mark_stored", err, t0)
	return err
}

func (w *metaWrap) CommitSnapshot(ctx context.Context, u, id string, o meta.CommitOptions) (meta.CommitResult, error) {
	t0 := time.Now()
	r, err := w.Store.CommitSnapshot(ctx, u, id, o)
	w.time("commit", err, t0)
	return r, err
}

func (w *metaWrap) GetToken(ctx context.Context, id string) (meta.Token, error) {
	t0 := time.Now()
	t, err := w.Store.GetToken(ctx, id)
	w.time("get_token", err, t0)
	return t, err
}
