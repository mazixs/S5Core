package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/veil"
)

func TestMemberOnlyConfiguration(t *testing.T) {
	good := clientParams{AuthMode: "member-only", Format: "v1", MemberID: "alice", MemberKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}
	if e := validateAuthMode(good); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*clientParams){func(c *clientParams) { c.MemberID = "" }, func(c *clientParams) { c.MemberKey = "bad" }, func(c *clientParams) { c.ProxyUser = "alice" }, func(c *clientParams) { c.ProxyPass = "secret" }} {
		c := good
		change(&c)
		if e := validateAuthMode(c); e == nil {
			t.Fatalf("accepted contradictory config: %+v", c)
		}
	}
	if e := validateAuthMode(clientParams{AuthMode: "password-fallback"}); e == nil {
		t.Fatal("fallback without credentials")
	}
}

// A deterministic delayed transport measures only the extra greeting exchange.
// It uses real obfs encryption and a server roster, with no wall-clock tolerance.
func TestMemberOnlySavesOneGreetingRTT(t *testing.T) {
	for _, rtt := range []time.Duration{20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond} {
		var elapsed [2]time.Duration
		for i, mode := range []string{"member-only", "password-fallback"} {
			t.Run(fmt.Sprintf("%s/%s", rtt, mode), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					cfg := testClientParams()
					cfg.Format = "v1"
					cfg.AuthMode = mode
					cfg.MemberID = "alice"
					key := bytes.Repeat([]byte{7}, 32)
					cfg.MemberKey = base64.StdEncoding.EncodeToString(key)
					if mode == "password-fallback" {
						cfg.ProxyUser = "alice"
						cfg.ProxyPass = "unused"
					}
					original := dialServer
					t.Cleanup(func() { dialServer = original })
					dialServer = func(clientParams) (net.Conn, error) {
						local, remote := net.Pipe()
						directory, e := veil.NewDirectory([]veil.Member{{ID: "alice", Key: key}})
						if e != nil {
							t.Fatal(e)
						}
						server, e := obfs.NewServerConn(&greetingDelayConn{Conn: remote, delay: rtt}, obfs.Config{PSK: []byte(cfg.PSK), Scheme: &veil.Roster{Members: directory}})
						if e != nil {
							t.Fatal(e)
						}
						t.Cleanup(func() { _ = local.Close(); _ = server.Close() })
						go func() {
							hdr := make([]byte, 2)
							if _, e := io.ReadFull(server, hdr); e != nil {
								t.Error(e)
								return
							}
							if _, e := io.ReadFull(server, make([]byte, int(hdr[1]))); e != nil {
								t.Error(e)
								return
							}
							if _, e := server.Write([]byte{5, 0}); e != nil {
								t.Error(e)
								return
							}
							if _, e := io.ReadFull(server, make([]byte, len(connectRequest()))); e != nil {
								t.Error(e)
								return
							}
							if _, e := server.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
								t.Error(e)
							}
						}()
						return local, nil
					}
					start := time.Now()
					c, e := dialObfsTunnel(cfg, connectRequest())
					if e != nil {
						t.Fatal(e)
					}
					defer c.Close()
					if _, e := io.ReadFull(c, make([]byte, 10)); e != nil {
						t.Fatal(e)
					}
					elapsed[i] = time.Since(start)
				})
			})
		}
		// Each additional network read costs one simulated exchange. The
		// pipelined CONNECT is already buffered when the greeting is answered.
		if elapsed[1]-elapsed[0] != rtt {
			t.Fatalf("RTT %v: member=%v fallback=%v", rtt, elapsed[0], elapsed[1])
		}
	}
}

type greetingDelayConn struct {
	net.Conn
	delay time.Duration
}

func (c *greetingDelayConn) Read(p []byte) (int, error) { time.Sleep(c.delay); return c.Conn.Read(p) }

func TestMemberOnlyRejectsUnusableServer(t *testing.T) {
	for _, reply := range [][]byte{{5, 2}, {5, 255}, {4, 0}} {
		t.Run(fmt.Sprintf("reply-%x", reply), func(t *testing.T) {
			cfg := testClientParams()
			cfg.Format = "v1"
			cfg.AuthMode = "member-only"
			cfg.MemberID = "alice"
			key := bytes.Repeat([]byte{7}, 32)
			cfg.MemberKey = base64.StdEncoding.EncodeToString(key)
			original := dialServer
			t.Cleanup(func() { dialServer = original })
			done := make(chan struct{})
			dialServer = func(clientParams) (net.Conn, error) {
				local, remote := net.Pipe()
				directory, e := veil.NewDirectory([]veil.Member{{ID: "alice", Key: key}})
				if e != nil {
					t.Fatal(e)
				}
				server, e := obfs.NewServerConn(remote, obfs.Config{PSK: []byte(cfg.PSK), Scheme: &veil.Roster{Members: directory}})
				if e != nil {
					t.Fatal(e)
				}
				go func() {
					defer close(done)
					defer server.Close()
					buf := make([]byte, 3+len(connectRequest()))
					if _, e := io.ReadFull(server, buf); e != nil {
						t.Error(e)
						return
					}
					if _, e := server.Write(reply); e != nil {
						t.Error(e)
					}
				}()
				return local, nil
			}
			c, e := dialObfsTunnel(cfg, connectRequest())
			if c != nil {
				_ = c.Close()
			}
			if e == nil || tunnelPhaseOf(e) != phaseAuthRejected {
				t.Fatalf("accepted server: %v", e)
			}
			<-done
		})
	}
}
