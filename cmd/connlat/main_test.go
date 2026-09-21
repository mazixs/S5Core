package main

import (
	"net"
	"testing"
	"time"
)

func TestPartialProbeFailureFailsRun(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 3 {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if i != 0 {
				c.Write([]byte{1})
			}
			c.Close()
		}
	}()
	res, err := run(settings{target: ln.Addr().String(), count: 3, timeout: time.Second})
	if err == nil || res.failed != 1 || len(res.samples) != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	<-done
}
