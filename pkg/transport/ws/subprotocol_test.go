package ws

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestNamedSubprotocols(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nothing", nil, nil},
		{"an empty string is not a subprotocol", []string{""}, nil},
		{"only empties", []string{"", ""}, nil},
		{"a real one", []string{"chat"}, []string{"chat"}},
		{"a real one beside an empty", []string{"", "chat"}, []string{"chat"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := namedSubprotocols(c.in); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("namedSubprotocols(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// Plan task Ф6-5: the header this test forbids is the trace the task is
// about. An empty Sec-WebSocket-Protocol is something no browser sends, so a
// transport that sends one is distinguishable from the traffic it imitates -
// and it took one configuration field left at its default to produce it.
func TestAnEmptySubprotocolNeverReachesTheWire(t *testing.T) {
	seen := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Clone():
		default:
		}
		// Refuse the upgrade: the request headers are what this test reads.
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	wsURL := "ws" + srv.URL[len("http"):] + "/ws"
	if conn, err := Dial(DialOpts{URL: wsURL, Subprotocols: []string{""}}); err == nil {
		_ = conn.Close()
		t.Fatal("the upgrade succeeded against a handler that refuses it")
	}

	select {
	case headers := <-seen:
		if got, ok := headers["Sec-Websocket-Protocol"]; ok {
			t.Fatalf("the client sent Sec-WebSocket-Protocol: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request never arrived")
	}
}

func TestARealSubprotocolDoesReachTheWire(t *testing.T) {
	seen := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Clone():
		default:
		}
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	wsURL := "ws" + srv.URL[len("http"):] + "/ws"
	if conn, err := Dial(DialOpts{URL: wsURL, Subprotocols: []string{"chat"}}); err == nil {
		_ = conn.Close()
		t.Fatal("the upgrade succeeded against a handler that refuses it")
	}

	select {
	case headers := <-seen:
		if got := headers.Get("Sec-Websocket-Protocol"); got != "chat" {
			t.Fatalf("the client sent subprotocol %q, want chat", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request never arrived")
	}
}
