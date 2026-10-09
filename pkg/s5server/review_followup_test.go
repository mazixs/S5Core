package s5server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/internal/userstore"
	"github.com/mazixs/S5Core/pkg/nativeudp"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/veil"
)

func TestReplacingAnAccountRevokesItsExistingCONNECT(t *testing.T) {
	for _, door := range []string{"password", "member"} {
		t.Run(door, func(t *testing.T) {
			s, port, key, echo := memberStand(t, true)
			var c net.Conn
			if door == "member" {
				c = dialMember(t, port, &veil.Roster{Member: veil.Member{ID: "alice", Key: key}})
				if err := connectAsMember(c, echo); err != nil {
					t.Fatal(err)
				}
			} else {
				var err error
				c, err = net.Dial("tcp", "127.0.0.1:"+s.cfg.Port)
				if err != nil {
					t.Fatal(err)
				}
				if err = socks5Connect(c, "alice", "the password nobody should need", echo); err != nil {
					t.Fatal(err)
				}
			}
			defer c.Close()
			if err := echoThrough(c, "before-replacement"); err != nil {
				t.Fatal(err)
			}
			accounts := followupAccounts(t, s.cfg.UsersFile)
			for i := range accounts {
				if accounts[i].Username == "alice" {
					accounts[i].ID = "replacement"
					accounts[i].TunnelKey = base64.StdEncoding.EncodeToString(randomMemberKey(t))
					accounts[i].PasswordHash = ""
					accounts[i].Password = "a new password"
					accounts[i].TrafficUsedBytes = 0
					accounts[i].TrafficLimitBytes = 1
				}
			}
			writeUsers(t, s.cfg.UsersFile, accounts)
			if err := s.ReloadUsers(); err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			var b [1]byte
			n, err := c.Read(b[:])
			if n != 0 || err == nil {
				t.Fatal("old connection kept receiving after replacement")
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatal("old connection was not revoked within the account polling interval")
			}
			acc, ok := s.userStore.Lookup("alice")
			if !ok || acc.ID != "replacement" || acc.TrafficUsedBytes != 0 {
				t.Fatalf("replacement inherited old traffic: %+v", acc)
			}
		})
	}
}

func TestReplacingAnAccountDoesNotTransferAnAdminHandle(t *testing.T) {
	s := adminServer(t)
	old, err := s.As("root")
	if err != nil {
		t.Fatal(err)
	}
	accounts := followupAccounts(t, s.cfg.UsersFile)
	for i := range accounts {
		if accounts[i].Username == "root" {
			accounts[i].ID = "replacement"
			accounts[i].TunnelKey = base64.StdEncoding.EncodeToString(randomMemberKey(t))
		}
	}
	writeUsers(t, s.cfg.UsersFile, accounts)
	if err := s.ReloadUsers(); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Actor(); err == nil {
		t.Fatal("old handle became the replacement account")
	}
	if old.Can(ManageAccountsAction) {
		t.Fatal("old handle inherited replacement permissions")
	}
	if err := old.SetRole("alice", RoleAdmin); err == nil {
		t.Fatal("old handle promoted another account")
	}
	fresh, err := s.As("root")
	if err != nil {
		t.Fatal(err)
	}
	if !fresh.Can(ManageAccountsAction) {
		t.Fatal("fresh handle cannot manage the replacement")
	}
}

func TestRuntimeControlsSurviveServerRestart(t *testing.T) {
	s, err := NewServer(Config{Port: "0", ListenIP: "127.0.0.1", Logger: slog.New(slog.DiscardHandler), ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 3; round++ {
		done := make(chan error, 1)
		go func() { done <- s.Start(context.Background()) }()
		waitServerRun(t, s, true)
		if round == 0 {
			if err := s.UpdateWhitelist([]string{"192.0.2.1"}); err != nil {
				t.Fatal(err)
			}
			s.UpdateTimeouts(7*time.Second, 8*time.Second)
			s.UpdateHandshakeTimeout(9 * time.Second)
			s.UpdateSessionTimeouts(10*time.Second, 11*time.Second, 12*time.Second)
		}
		for _, p := range s.allPipelines() {
			sla := p.sla()
			if sla.ReadIdle != 7*time.Second || sla.WriteIdle != 8*time.Second || sla.Handshake != 9*time.Second || sla.Dial != 10*time.Second || sla.FrameBody != 11*time.Second || sla.Grace != 12*time.Second {
				t.Errorf("round %d lost budgets: %+v", round, sla)
			}
		}
		c, err := net.DialTimeout("tcp", s.allPipelines()[0].Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, _ = c.Write([]byte{5, 1, 0})
		var greeting [2]byte
		if _, err = io.ReadFull(c, greeting[:]); err == nil {
			t.Errorf("round %d allowed a forbidden address", round)
		}
		_ = c.Close()
		if err = s.Stop(); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestBootReadsAreSafeAcrossServerRuns(t *testing.T) {
	s, err := NewServer(Config{Port: "0", ListenIP: "127.0.0.1", Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if len(s.Boot()) != 8 {
					t.Error("invalid boot ID")
					return
				}
			}
		}
	}()
	defer func() { close(stop); wg.Wait() }()
	previous := s.Boot()
	for range 10 {
		done := make(chan error, 1)
		go func() { done <- s.Start(context.Background()) }()
		waitServerRun(t, s, true)
		boot := s.Boot()
		if boot == previous {
			t.Fatal("Start reused the previous run ID")
		}
		if err = s.Stop(); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err != nil {
			t.Fatal(err)
		}
		if s.Boot() != boot {
			t.Fatal("Stop changed the completed run ID")
		}
		previous = boot
	}
}

func followupAccounts(t *testing.T, path string) []userstore.UserAccount {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file userstore.UsersFile
	if err = json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	return file.Users
}

func TestReplacingAnAccountRevokesItsExistingUDP(t *testing.T) {
	for _, command := range []byte{socks5.AssociateCommand, socks5.UDPTunnelCommand, socks5.UDPNativeCommand} {
		t.Run(fmt.Sprintf("command_%02x", command), func(t *testing.T) {
			key := randomMemberKey(t)
			cfg := Config{Port: reservePort(t), ListenIP: "127.0.0.1", RequireAuth: true, UsersFile: memberUsersFile(t, key), ObfsEnabled: true, ObfsPort: reservePort(t), ObfsPSK: testPSK, ObfsMaxPadding: 256, ObfsMTU: 1400, UDPPort: reserveUDPPort(t), ObfsRequireMemberKey: true}
			s := startServer(t, cfg)
			c := dialMember(t, cfg.ObfsPort, &veil.Roster{Member: veil.Member{ID: "alice", Key: key}})
			defer c.Close()
			_, err := c.Write([]byte{5, 1, 0, 5, command, 0, 1, 0, 0, 0, 0, 0, 0})
			if err != nil {
				t.Fatal(err)
			}
			var reply [12]byte
			if _, err = io.ReadFull(c, reply[:]); err != nil || reply[1] != 0 || reply[3] != 0 {
				t.Fatal("association", reply, err)
			}
			echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				var b [2048]byte
				for {
					n, peer, err := echo.ReadFromUDP(b[:])
					if err != nil {
						return
					}
					_, _ = echo.WriteToUDP(b[:n], peer)
				}
			}()
			body := socksDatagram(&socks5.AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: echo.LocalAddr().(*net.UDPAddr).Port}, bytes.Repeat([]byte{'x'}, 100))
			var udp *net.UDPConn
			var native *nativeudp.Session
			if command != socks5.UDPTunnelCommand {
				port := int(binary.BigEndian.Uint16(reply[10:12]))
				if port == 0 {
					t.Fatal("no UDP port")
				}
				udp, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
				if command == socks5.UDPNativeCommand {
					keys, err := obfs.DatagramKeysOf(c)
					if err != nil {
						t.Fatal(err)
					}
					native = nativeudp.NewSession(keys)
					wire, err := native.Seal(nil, nativeudp.KindProbe, nil)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = udp.Write(wire); err != nil {
						t.Fatal(err)
					}
					var b [2048]byte
					n, err := udp.Read(b[:])
					if err != nil {
						t.Fatal(err)
					}
					packet, err := native.Open(b[:n])
					if err != nil || packet.Kind != nativeudp.KindProbeAck {
						t.Fatal("probe ACK", err)
					}
				}
			}
			send := func() error {
				if native != nil {
					wire, err := native.Seal(nil, nativeudp.KindData, body)
					if err != nil {
						return err
					}
					_, err = udp.Write(wire)
					return err
				}
				if udp != nil {
					_, err := udp.Write(body)
					return err
				}
				_, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...))
				return err
			}
			if err := send(); err != nil {
				t.Fatal(err)
			}
			if udp != nil {
				var b [2048]byte
				n, err := udp.Read(b[:])
				if err != nil {
					t.Fatal(err)
				}
				got := b[:n]
				if native != nil {
					packet, err := native.Open(got)
					if err != nil || packet.Kind != nativeudp.KindData {
						t.Fatal("native echo", err)
					}
					got = packet.Data
				}
				if !bytes.Equal(got, body) {
					t.Fatal("UDP echo mismatch")
				}
			} else {
				var size [2]byte
				if _, err := io.ReadFull(c, size[:]); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, body) {
					t.Fatal("fallback echo", err)
				}
			}
			accounts := followupAccounts(t, cfg.UsersFile)
			for i := range accounts {
				if accounts[i].Username == "alice" {
					accounts[i].ID = "replacement"
					accounts[i].TunnelKey = base64.StdEncoding.EncodeToString(randomMemberKey(t))
					accounts[i].TrafficUsedBytes = 0
					accounts[i].TrafficLimitBytes = 1
				}
			}
			writeUsers(t, cfg.UsersFile, accounts)
			if err := s.ReloadUsers(); err != nil {
				t.Fatal(err)
			}
			// UDP checks the policy on a payload boundary or the first payload after
			// one second. A quiet association does not generate test traffic itself.
			time.Sleep(1100 * time.Millisecond)
			if err := send(); err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, err = io.Copy(io.Discard, c)
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatal("old UDP association was not revoked")
			}
			acc, ok := s.userStore.Lookup("alice")
			if !ok || acc.TrafficUsedBytes != 0 {
				t.Fatalf("replacement inherited UDP traffic: %+v", acc)
			}
		})
	}
}

func TestStaleRosterCannotAuthenticateReplacement(t *testing.T) {
	s, port, key, echo := memberStand(t, true)
	accounts := followupAccounts(t, s.cfg.UsersFile)
	for i := range accounts {
		if accounts[i].Username == "alice" {
			accounts[i].ID = "replacement"
			accounts[i].TunnelKey = base64.StdEncoding.EncodeToString(randomMemberKey(t))
		}
	}
	writeUsers(t, s.cfg.UsersFile, accounts)
	// Leave the old directory in place to cover a prologue resolved before
	// refreshMembers. It must not turn the old key into the new name's rights.
	if err := s.userStore.Reload(s.cfg.UsersFile); err != nil {
		t.Fatal(err)
	}
	c := dialMember(t, port, &veil.Roster{Member: veil.Member{ID: "alice", Key: key}})
	defer c.Close()
	if err := connectAsMember(c, echo); err == nil {
		t.Fatal("stale roster authenticated replacement")
	}
}

func TestControlsUpdatedBeforeAndDuringStartReachEveryNewListener(t *testing.T) {
	cert, key, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Config{Port: "0", ListenIP: "127.0.0.1", Logger: slog.New(slog.DiscardHandler), ObfsEnabled: true, ObfsPort: "0", ObfsPSK: testPSK, ObfsMTU: 1400, WSEnabled: true, WSAddr: "127.0.0.1:0", WSCertFile: cert, WSKeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Stop(); err != nil {
			t.Error(err)
		}
	}()
	for range 2 {
		if err := s.UpdateWhitelist([]string{"192.0.2.7"}); err != nil {
			t.Fatal(err)
		}
		s.UpdateTimeouts(7*time.Second, 8*time.Second)
		s.lifeMu.Lock()
		previous := s.run
		s.lifeMu.Unlock()
		done := make(chan error, 1)
		go func() { done <- s.Start(context.Background()) }()
		for i := 0; i < 50; i++ {
			s.UpdateTimeouts(time.Duration(i+1)*time.Second, 8*time.Second)
			s.UpdateHandshakeTimeout(9 * time.Second)
			s.UpdateSessionTimeouts(10*time.Second, 11*time.Second, 12*time.Second)
		}
		// The previous run leaves its pipelines in place, and a Stop before
		// this Start has begun would stop that run instead of this one.
		started := func() bool {
			s.lifeMu.Lock()
			defer s.lifeMu.Unlock()
			return s.run != previous
		}
		deadline := time.Now().Add(3 * time.Second)
		for (!started() || len(s.allPipelines()) < 3) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		pipelines := s.allPipelines()
		if len(pipelines) != 3 {
			t.Fatal("listeners not ready")
		}
		for _, p := range pipelines {
			got := p.sla()
			if got.ReadIdle != 50*time.Second || got.WriteIdle != 8*time.Second || got.Handshake != 9*time.Second || got.Dial != 10*time.Second || got.FrameBody != 11*time.Second || got.Grace != 12*time.Second {
				t.Fatalf("%s missed latest startup updates: %+v", p.transport, got)
			}
			p.mu.RLock()
			restricted := len(p.whitelist) == 1 && p.whitelist[0].Equal(net.ParseIP("192.0.2.7"))
			p.mu.RUnlock()
			if !restricted {
				t.Fatalf("%s missed whitelist", p.transport)
			}
		}
		if err := s.Stop(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
