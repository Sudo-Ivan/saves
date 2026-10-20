// SPDX-License-Identifier: 0BSD

package s3

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/blob/blobtest"
)

// fakeS3 is an in-process S3 subset: PutObject, GetObject with Range,
// HeadObject, DeleteObject, and ListObjectsV2, path style only.
type fakeS3 struct {
	mu   sync.Mutex
	objs map[string]fakeObj
}

type fakeObj struct {
	data    []byte
	modTime time.Time
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objs: map[string]fakeObj{}}
}

type listResult struct {
	XMLName     xml.Name   `xml:"ListBucketResult"`
	Xmlns       string     `xml:"xmlns,attr"`
	Name        string     `xml:"Name"`
	Prefix      string     `xml:"Prefix"`
	KeyCount    int        `xml:"KeyCount"`
	MaxKeys     int        `xml:"MaxKeys"`
	IsTruncated bool       `xml:"IsTruncated"`
	Contents    []listItem `xml:"Contents"`
}

type listItem struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

func s3err(w http.ResponseWriter, code string, status int) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code></Error>`, code)
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	bucket := parts[0]
	key := ""
	if len(parts) == 2 {
		key = parts[1]
	}
	if r.URL.Query().Get("location") != "" || r.URL.Query().Has("location") {
		w.Header().Set("Content-Type", "application/xml")
		io.WriteString(w, `<?xml version="1.0"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`)
		return
	}
	if r.Method == http.MethodGet && key == "" && r.URL.Query().Get("list-type") == "2" {
		f.list(w, r, bucket)
		return
	}
	if key == "" {
		s3err(w, "NoSuchKey", 404)
		return
	}
	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			s3err(w, "InternalError", 500)
			return
		}
		f.mu.Lock()
		f.objs[key] = fakeObj{data: body, modTime: time.Now().UTC()}
		f.mu.Unlock()
		w.Header().Set("ETag", `"`+fmt.Sprintf("%x", len(body))+`"`)
		w.WriteHeader(200)
	case http.MethodGet:
		f.mu.Lock()
		o, ok := f.objs[key]
		f.mu.Unlock()
		if !ok {
			s3err(w, "NoSuchKey", 404)
			return
		}
		rng := r.Header.Get("Range")
		if rng == "" {
			w.Header().Set("Content-Length", strconv.Itoa(len(o.data)))
			w.Header().Set("ETag", `"x"`)
			w.Header().Set("Last-Modified", o.modTime.UTC().Format(http.TimeFormat))
			w.WriteHeader(200)
			w.Write(o.data)
			return
		}
		var lo, hi int64
		if _, err := fmt.Sscanf(rng, "bytes=%d-%d", &lo, &hi); err != nil {
			s3err(w, "InvalidRange", 416)
			return
		}
		if lo >= int64(len(o.data)) {
			s3err(w, "InvalidRange", 416)
			return
		}
		if hi >= int64(len(o.data)) {
			hi = int64(len(o.data)) - 1
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", lo, hi, len(o.data)))
		w.Header().Set("Last-Modified", o.modTime.UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Length", strconv.FormatInt(hi-lo+1, 10))
		w.WriteHeader(206)
		w.Write(o.data[lo : hi+1])
	case http.MethodHead:
		f.mu.Lock()
		o, ok := f.objs[key]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(o.data)))
		w.Header().Set("ETag", `"x"`)
		w.Header().Set("Last-Modified", o.modTime.UTC().Format(http.TimeFormat))
		w.WriteHeader(200)
	case http.MethodDelete:
		f.mu.Lock()
		delete(f.objs, key)
		f.mu.Unlock()
		w.WriteHeader(204)
	default:
		s3err(w, "NotImplemented", 501)
	}
}

func (f *fakeS3) list(w http.ResponseWriter, r *http.Request, bucket string) {
	prefix := r.URL.Query().Get("prefix")
	var items []listItem
	f.mu.Lock()
	for k, o := range f.objs {
		if strings.HasPrefix(k, prefix) {
			items = append(items, listItem{
				Key:          k,
				LastModified: o.modTime.UTC().Format("2006-01-02T15:04:05.000Z"),
				ETag:         `"x"`,
				Size:         int64(len(o.data)),
				StorageClass: "STANDARD",
			})
		}
	}
	f.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	res := listResult{
		Xmlns:    "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:     bucket,
		Prefix:   prefix,
		MaxKeys:  1000,
		KeyCount: len(items),
		Contents: items,
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(200)
	io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>`)
	xml.NewEncoder(w).Encode(res)
}

func fakeStore(t *testing.T) blob.Store {
	t.Helper()
	srv := httptest.NewServer(newFakeS3())
	t.Cleanup(srv.Close)
	s, err := New(Options{
		Endpoint:   strings.TrimPrefix(srv.URL, "http://"),
		Region:     "us-east-1",
		Bucket:     "testbucket",
		AccessKey:  "ak",
		SecretKey:  "sk",
		PathStyle:  true,
		Insecure:   true,
		MaxRetries: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConformance(t *testing.T) {
	blobtest.Run(t, fakeStore)
}

func TestConformanceRealS3(t *testing.T) {
	endpoint := os.Getenv("SAVES_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("SAVES_TEST_S3_ENDPOINT not set")
	}
	blobtest.Run(t, func(t *testing.T) blob.Store {
		s, err := New(Options{
			Endpoint:  endpoint,
			Region:    envOr("SAVES_TEST_S3_REGION", "us-east-1"),
			Bucket:    os.Getenv("SAVES_TEST_S3_BUCKET"),
			Prefix:    "blobtest-" + strconv.FormatInt(time.Now().UnixNano(), 36),
			AccessKey: os.Getenv("SAVES_TEST_S3_ACCESS_KEY"),
			SecretKey: os.Getenv("SAVES_TEST_S3_SECRET_KEY"),
			PathStyle: true,
			Insecure:  os.Getenv("SAVES_TEST_S3_INSECURE") == "1",
		})
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
