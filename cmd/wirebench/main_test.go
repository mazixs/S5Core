package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTransferRequiresSuccessfulStatusAndExactCount(t *testing.T) {
	for _, tc := range []struct {
		name, dir, body string
		status          int
		wantErr         bool
	}{
		{"upload unavailable", "up", "unavailable", 503, true},
		{"download unavailable", "down", "unavailable", 503, true},
		{"short download", "down", "abc", 200, true},
		{"long download", "down", "abcdef", 200, true},
		{"short upload ack", "up", "3\n", 200, true},
		{"invalid upload ack", "up", "ok", 200, true},
		{"upload", "up", "4\n", 200, false},
		{"download", "down", "abcd", 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			got := oneTransfer(context.Background(), srv.Client(), clientOpts{url: srv.URL, bytes: 4, dir: tc.dir})
			if (got.err != nil) != tc.wantErr {
				t.Fatalf("result: %+v", got)
			}
			if !tc.wantErr && got.bytes != 4 {
				t.Fatalf("count: %d", got.bytes)
			}
		})
	}
}

func TestPartialClientFailureFailsRun(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "abcd")
	}))
	defer srv.Close()
	if err := runClient(context.Background(), clientOpts{url: srv.URL, bytes: 4, conns: 2, dir: "down"}); err == nil {
		t.Fatal("partial failure passed")
	}
	for _, opts := range []clientOpts{{bytes: 4, dir: "down"}, {conns: 1, dir: "down"}, {conns: 1, bytes: 4, dir: "sideways"}} {
		if err := runClient(context.Background(), opts); err == nil {
			t.Fatalf("invalid options accepted: %+v", opts)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestEarlyUploadAcknowledgmentCannotInventTransferredBytes(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.Body.Close()
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("67108864\n")), Header: make(http.Header)}, nil
	})}
	got := oneTransfer(context.Background(), client, clientOpts{url: "http://test", dir: "up", bytes: 64 << 20})
	if got.err == nil {
		t.Fatalf("early acknowledgment counted as transfer: %+v", got)
	}
}

func TestUploadReaderUsesWholeRandomChunk(t *testing.T) {
	r := &randomReader{chunk: []byte("abcdefgh")}
	var got strings.Builder
	buf := make([]byte, 3)
	for got.Len() < 16 {
		n, err := r.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got.Write(buf[:n])
	}
	if got.String() != "abcdefghabcdefgh" {
		t.Fatalf("small transport buffers repeat only a prefix: %q", got.String())
	}
}
