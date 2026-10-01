package ws_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/mazixs/S5Core/pkg/transport/ws"
)

func ExampleDial() {
	up := ws.NewUpgrader(ws.UpgraderOpts{Path: "/ws"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r)
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}))
	defer srv.Close()

	conn, err := ws.Dial(ws.DialOpts{URL: strings.Replace(srv.URL, "http", "ws", 1) + "/ws"})
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		fmt.Println("write:", err)
		return
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		fmt.Println("read:", err)
		return
	}
	fmt.Println(string(buf))
	// Output: ping
}
