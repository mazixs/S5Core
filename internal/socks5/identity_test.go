package socks5

import (
	"bytes"
	"testing"
)

// Plan task Ф5-5 moves user identification out of the SOCKS5 handshake and
// into the tunnel: by the time these bytes arrive, the obfuscation layer has
// already checked a MAC under this member's own key. What is left for this
// package is to believe it, and to stop charging a password for the same
// answer.

// refusingStore fails every password. A test that authenticates through it
// and succeeds has proved the password path was not taken.
type refusingStore struct{ asked int }

func (r *refusingStore) Valid(_, _ string) bool {
	r.asked++
	return false
}

func TestATunnelIdentityReplacesThePassword(t *testing.T) {
	req := bytes.NewBuffer([]byte{2, NoAuth, UserPassAuth})
	var resp bytes.Buffer

	store := &refusingStore{}
	s, err := New(&Config{AuthMethods: []Authenticator{UserPassAuthenticator{Credentials: store}}})
	if err != nil {
		t.Fatal(err)
	}

	ctx, err := s.authenticate(&resp, req, "198.51.100.9", "alice", nil)
	if err != nil {
		t.Fatalf("a connection the tunnel had already authenticated was refused: %v", err)
	}
	if ctx.Method != NoAuth {
		t.Errorf("method %d, want no-auth: a member should not be asked for a password", ctx.Method)
	}
	if got := ctx.Payload["Username"]; got != "alice" {
		t.Errorf("the session is accounted to %q, want alice", got)
	}
	if store.asked != 0 {
		t.Errorf("the password store was consulted %d times for a member the tunnel had named", store.asked)
	}
	if out := resp.Bytes(); !bytes.Equal(out, []byte{Socks5Version, NoAuth}) {
		t.Errorf("the server answered %v, want the no-auth method", out)
	}
}

// A client from before this existed offers only user/pass. It must keep
// working, and it must keep being checked: the identity is an offer.
func TestAMemberThatInsistsOnAPasswordStillGetsOne(t *testing.T) {
	req := bytes.NewBuffer([]byte{1, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	var resp bytes.Buffer

	s, err := New(&Config{AuthMethods: []Authenticator{
		UserPassAuthenticator{Credentials: StaticCredentials{"foo": "bar"}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	ctx, err := s.authenticate(&resp, req, "198.51.100.9", "alice", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ctx.Method != UserPassAuth {
		t.Errorf("method %d, want user/pass", ctx.Method)
	}
	if got := ctx.Payload["Username"]; got != "foo" {
		t.Errorf("username %q, want foo", got)
	}
}

// And a connection the tunnel does not know is unaffected: the plain
// listener has no tunnel under it at all.
func TestWithoutATunnelIdentityNothingChanges(t *testing.T) {
	req := bytes.NewBuffer([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	var resp bytes.Buffer

	store := &refusingStore{}
	s, err := New(&Config{AuthMethods: []Authenticator{UserPassAuthenticator{Credentials: store}}})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.authenticate(&resp, req, "198.51.100.9", "", nil); err == nil {
		t.Fatal("a connection with no tunnel identity and a bad password was accepted")
	}
	if store.asked == 0 {
		t.Error("the password store was not consulted for a connection nobody had authenticated")
	}
}
