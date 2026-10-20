// SPDX-License-Identifier: 0BSD

// Package s3 implements blob.Store on an S3 compatible object store
// using minio-go. ReadAt uses ranged GETs, writes are verified locally
// with SHA-256, and transient failures retry with backoff and jitter.
package s3

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Options configures an S3 store.
type Options struct {
	Endpoint       string
	Region         string
	Bucket         string
	Prefix         string
	AccessKey      string
	SecretKey      string
	PathStyle      bool
	Insecure       bool
	RequestTimeout time.Duration
	MaxRetries     int
}

// OptionsFromConfig maps the config storage.blob.s3 section.
func OptionsFromConfig(sc config.S3Config) Options {
	return Options{
		Endpoint:       strings.TrimPrefix(strings.TrimPrefix(sc.Endpoint, "https://"), "http://"),
		Region:         sc.Region,
		Bucket:         sc.Bucket,
		Prefix:         strings.Trim(sc.Prefix, "/"),
		AccessKey:      sc.AccessKey,
		SecretKey:      sc.SecretKey,
		PathStyle:      sc.PathStyle,
		Insecure:       sc.Insecure,
		RequestTimeout: sc.RequestTimeout.Duration(),
		MaxRetries:     sc.MaxRetries,
	}
}

// Store is an S3 blob store.
type Store struct {
	cli     *minio.Client
	bucket  string
	prefix  string
	timeout time.Duration
	retries int
}

var _ blob.Store = (*Store)(nil)

// New builds a store. It does not touch the network.
func New(opt Options) (*Store, error) {
	if opt.Bucket == "" {
		return nil, errors.New("blobs3: bucket is required")
	}
	lookup := minio.BucketLookupAuto
	if opt.PathStyle {
		lookup = minio.BucketLookupPath
	}
	cli, err := minio.New(opt.Endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(opt.AccessKey, opt.SecretKey, ""),
		Secure:       !opt.Insecure,
		Region:       opt.Region,
		BucketLookup: lookup,
		Transport:    netx.NewTransport(),
	})
	if err != nil {
		return nil, fmt.Errorf("blobs3: %w", err)
	}
	if opt.RequestTimeout <= 0 {
		opt.RequestTimeout = 30 * time.Second
	}
	if opt.MaxRetries < 0 {
		opt.MaxRetries = 0
	}
	return &Store{cli: cli, bucket: opt.Bucket, prefix: opt.Prefix, timeout: opt.RequestTimeout, retries: opt.MaxRetries}, nil
}

func (s *Store) key(k string) string {
	if s.prefix == "" {
		return k
	}
	return s.prefix + "/" + k
}

// withTimeout applies the per request deadline when the caller's context
// has none or a longer one.
func (s *Store) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.timeout)
}

// retry runs op with bounded exponential backoff and jitter for
// transient errors.
func (s *Store) retry(ctx context.Context, op func() error) error {
	var err error
	for attempt := 0; attempt <= s.retries; attempt++ {
		if err = op(); err == nil {
			return nil
		}
		if !transient(err) || attempt == s.retries {
			return err
		}
		backoff := time.Duration(50<<attempt) * time.Millisecond
		jitter := time.Duration(rand.Int64N(int64(backoff))) // #nosec G404 -- backoff jitter needs no cryptographic randomness
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff + jitter):
		}
	}
	return err
}

func transient(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var resp minio.ErrorResponse
	if errors.As(err, &resp) {
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden ||
			resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
			return false
		}
		return resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
	}
	return true
}

// Put implements blob.Store.Put. Content is hashed while streaming and
// compared to want before the call returns; the S3 API receives the
// same stream, so a checksum failure still uploads but is reported and
// the object is removed.
func (s *Store) Put(ctx context.Context, key string, r io.Reader, size int64, want *api.Hash) error {
	if err := blob.ValidKey(key); err != nil {
		return err
	}
	if size < 0 {
		return blob.ErrSizeMismatch
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	h := sha256.New()
	tr := io.TeeReader(io.LimitReader(r, size+1), h)
	cr := &countingReader{r: tr, max: size}
	// A retry is safe only while the upload consumed no bytes.
	var err error
	for attempt := 0; attempt <= s.retries; attempt++ {
		cctx, ccancel := s.withTimeout(ctx)
		_, err = s.cli.PutObject(cctx, s.bucket, s.key(key), cr, size,
			minio.PutObjectOptions{ContentType: "application/octet-stream", DisableContentSha256: true, DisableMultipart: true})
		ccancel()
		if err == nil || cr.n > 0 || !transient(err) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(50<<attempt)*time.Millisecond + time.Duration(rand.Int64N(50e6))): // #nosec G404 -- backoff jitter needs no cryptographic randomness
		}
	}
	if err != nil {
		if cr.n < size {
			return blob.ErrSizeMismatch
		}
		return fmt.Errorf("blobs3: put %s: %w", key, err)
	}
	// The upload consumed exactly size bytes; probe for extra input.
	var extra [1]byte
	if m, _ := tr.Read(extra[:]); m > 0 {
		_ = s.cli.RemoveObject(context.Background(), s.bucket, s.key(key), minio.RemoveObjectOptions{})
		return blob.ErrSizeMismatch
	}
	if want != nil {
		var sum api.Hash
		copy(sum[:], h.Sum(nil))
		if sum != *want {
			_ = s.cli.RemoveObject(context.Background(), s.bucket, s.key(key), minio.RemoveObjectOptions{})
			return blob.ErrChecksum
		}
	}
	return nil
}

// countingReader stops the stream early when the declared size is
// exceeded so PutObject reports a truncated or oversized body.
type countingReader struct {
	r   io.Reader
	max int64
	n   int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.n >= c.max {
		return 0, io.EOF
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// s3Error maps minio errors to package errors.
func s3Error(op, key string, err error) error {
	var resp minio.ErrorResponse
	if errors.As(err, &resp) && resp.StatusCode == http.StatusNotFound {
		return blob.ErrNotFound
	}
	if errors.As(err, &resp) && (resp.Code == "NoSuchKey" || resp.Code == "NoSuchBucket") {
		return blob.ErrNotFound
	}
	return fmt.Errorf("blobs3: %s %s: %w", op, key, err)
}

// object is a ranged GET backed Object.
type object struct {
	s    *Store
	key  string
	size int64
}

func (o *object) Size() int64  { return o.size }
func (o *object) Close() error { return nil }

// ReadAt issues a ranged GET for exactly len(p) bytes at off.
func (o *object) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if off < 0 {
		return 0, errors.New("blobs3: negative offset")
	}
	if off >= o.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	if off+want > o.size {
		want = o.size - off
	}
	var n int
	err := o.s.retry(context.Background(), func() error {
		ctx, cancel := o.s.withTimeout(context.Background())
		defer cancel()
		opts := minio.GetObjectOptions{}
		if err := opts.SetRange(off, off+want-1); err != nil {
			return err
		}
		obj, err := o.s.cli.GetObject(ctx, o.s.bucket, o.s.key(o.key), opts)
		if err != nil {
			return err
		}
		defer obj.Close()
		n = 0
		for int64(n) < want {
			m, rerr := obj.Read(p[n:want])
			n += m
			if rerr != nil {
				if rerr == io.EOF && int64(n) == want {
					return nil
				}
				return rerr
			}
		}
		return nil
	})
	if err != nil {
		return n, s3Error("get", o.key, err)
	}
	return n, nil
}

// Open implements blob.Store.Open.
func (s *Store) Open(ctx context.Context, key string) (blob.Object, error) {
	size, err := s.Stat(ctx, key)
	if err != nil {
		return nil, err
	}
	return &object{s: s, key: key, size: size}, nil
}

// Stat implements blob.Store.Stat.
func (s *Store) Stat(ctx context.Context, key string) (int64, error) {
	if err := blob.ValidKey(key); err != nil {
		return 0, err
	}
	var size int64
	err := s.retry(ctx, func() error {
		cctx, cancel := s.withTimeout(ctx)
		defer cancel()
		info, err := s.cli.StatObject(cctx, s.bucket, s.key(key), minio.StatObjectOptions{})
		if err != nil {
			return err
		}
		size = info.Size
		return nil
	})
	if err != nil {
		return 0, s3Error("stat", key, err)
	}
	return size, nil
}

// Delete implements blob.Store.Delete.
func (s *Store) Delete(ctx context.Context, key string) error {
	if err := blob.ValidKey(key); err != nil {
		return err
	}
	err := s.retry(ctx, func() error {
		cctx, cancel := s.withTimeout(ctx)
		defer cancel()
		return s.cli.RemoveObject(cctx, s.bucket, s.key(key), minio.RemoveObjectOptions{})
	})
	if err != nil {
		var resp minio.ErrorResponse
		if errors.As(err, &resp) && (resp.StatusCode == http.StatusNotFound || resp.Code == "NoSuchKey") {
			return nil
		}
		return s3Error("delete", key, err)
	}
	return nil
}

// List implements blob.Store.List using ListObjectsV2 pagination.
func (s *Store) List(ctx context.Context, prefix string, fn func(blob.Entry) error) error {
	full := s.key(prefix)
	done := ctx.Done()
	for obj := range s.cli.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{
		Prefix:    full,
		Recursive: true,
	}) {
		select {
		case <-done:
			return ctx.Err()
		default:
		}
		if obj.Err != nil {
			return s3Error("list", prefix, obj.Err)
		}
		key := strings.TrimPrefix(obj.Key, s.prefix+"/")
		if s.prefix == "" {
			key = obj.Key
		}
		if err := blob.ValidKey(key); err != nil {
			continue
		}
		if err := fn(blob.Entry{Key: key, Size: obj.Size, ModTime: obj.LastModified}); err != nil {
			return err
		}
	}
	return nil
}

// Close implements blob.Store.Close.
func (s *Store) Close() error { return nil }
