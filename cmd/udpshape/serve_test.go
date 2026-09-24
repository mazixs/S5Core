package main

import (
	"net/netip"
	"testing"
	"time"
)

func request(t *testing.T, name string, size int, token [8]byte, seq uint32) []byte {
	t.Helper()
	fm := formByName(name)
	p := make([]byte, size)
	fm.build(p, newFlow(), nil, trailer{token: token, form: fm.id, seq: seq})
	return p
}

func TestTheTokenTableIsBounded(t *testing.T) {
	tab := newTable(4, time.Minute, nil)
	src := netip.MustParseAddrPort("192.0.2.1:5000")
	now := time.Unix(1_000_000, 0)
	for i := range 10 {
		_, _, ok := tab.hit(key{token: [8]byte{byte(i)}, form: 1}, src, 443, 100, now)
		if ok != (i < 4) {
			t.Errorf("token %d admitted = %v with %d of 4 in use", i, ok, len(tab.m))
		}
	}
	if len(tab.m) != 4 || tab.refused != 6 {
		t.Fatalf("%d entries, %d refused", len(tab.m), tab.refused)
	}
	// A test already in the table keeps counting while the table is full.
	if n, _, ok := tab.hit(key{token: [8]byte{0}, form: 1}, src, 443, 100, now); !ok || n != 2 {
		t.Errorf("a live test got count %d, %v", n, ok)
	}
	// Once the others have been idle for the ttl a new test gets in.
	later := now.Add(time.Minute)
	if _, _, ok := tab.hit(key{token: [8]byte{9}, form: 1}, src, 443, 100, later); !ok {
		t.Error("a new test was refused after the ttl")
	}
	if len(tab.m) != 1 {
		t.Errorf("%d entries after expiry, want 1", len(tab.m))
	}
}

func TestAReplyIsAsLongAsItsRequest(t *testing.T) {
	s := &server{table: newTable(64, time.Minute, nil)}
	src := netip.MustParseAddrPort("192.0.2.1:5000")
	out := make([]byte, 1<<16)
	for _, fm := range forms {
		for i, size := range []int{fm.min, 1200, 1500} {
			size, _ = fm.wire(size)
			req := request(t, fm.name, size, [8]byte{fm.id, byte(i)}, 3)
			rep := s.answer(req, src, 443, out, time.Now())
			if len(rep) != len(req) {
				t.Fatalf("%s@%d answered with %d bytes", fm.name, size, len(rep))
			}
			tr, ok := readTrailer(rep)
			if !ok || !tr.reply || tr.seq != 3 || tr.count != 1 || tr.form != fm.id {
				t.Errorf("%s@%d reply trailer %+v, %v", fm.name, size, tr, ok)
			}
		}
	}
}

// Replies are never answered: two servers pointed at each other stay quiet.
func TestTheServerDoesNotAnswerAReply(t *testing.T) {
	s := &server{table: newTable(64, time.Minute, nil)}
	fm := formByName("dtls")
	p := make([]byte, 200)
	fm.build(p, newFlow(), nil, trailer{form: fm.id, reply: true})
	if s.answer(p, netip.MustParseAddrPort("192.0.2.1:5000"), 443, make([]byte, 1<<16), time.Now()) != nil {
		t.Error("a reply was answered")
	}
}

func TestTheAllowListDecidesWhoIsAnswered(t *testing.T) {
	allow, err := parsePrefixes("10.0.0.0/8, 2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{allow: allow, table: newTable(64, time.Minute, nil)}
	out := make([]byte, 1<<16)
	for src, want := range map[string]bool{
		"10.1.2.3:4000":          true,
		"[::ffff:10.9.9.9]:4000": true,
		"[2001:db8::1]:4000":     true,
		"192.0.2.1:4000":         false,
		"[2001:db8::2]:4000":     false,
	} {
		req := request(t, "random", 100, [8]byte{1}, 0)
		got := s.answer(req, netip.MustParseAddrPort(src), 443, out, time.Now()) != nil
		if got != want {
			t.Errorf("%s answered = %v", src, got)
		}
	}
	if len(s.table.m) != 1 {
		t.Errorf("%d tests counted; refused sources must not take table space", len(s.table.m))
	}
}

// The count follows the token, so a NAT rebinding mid-flow does not restart it.
func TestTheCountFollowsTheTokenAcrossAddresses(t *testing.T) {
	tab := newTable(8, time.Minute, nil)
	k := key{token: [8]byte{7}, form: 3}
	now := time.Now()
	tab.hit(k, netip.MustParseAddrPort("192.0.2.1:5000"), 443, 100, now)
	n, _, _ := tab.hit(k, netip.MustParseAddrPort("192.0.2.1:6000"), 443, 100, now)
	if n != 2 || tab.m[k].moves != 1 {
		t.Errorf("count %d, source changes %d", n, tab.m[k].moves)
	}
}
