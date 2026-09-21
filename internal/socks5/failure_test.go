package socks5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestAuthFailuresKeepTheirOperationAndCause(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		op    string
		kind  FailureKind
		cause error
	}{
		{"missing header", nil, "header_read", FailureClosed, io.EOF},
		{"short username", []byte{1, 2, 'a'}, "username_read", FailureClosed, io.ErrUnexpectedEOF},
		{"missing password length", []byte{1, 1, 'a'}, "password_length_read", FailureClosed, io.EOF},
		{"short password", []byte{1, 1, 'a', 2, 'x'}, "password_read", FailureClosed, io.ErrUnexpectedEOF},
		{"bad version", []byte{9, 0}, "header_read", FailureProtocol, nil},
		{"wrong password", []byte{1, 1, 'a', 1, 'x'}, "verify", FailureAuth, ErrUserAuthFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := UserPassAuthenticator{Credentials: StaticCredentials{"a": "b"}}
			var reply bytes.Buffer
			_, err := a.Authenticate(bytes.NewReader(tc.input), &reply, "")
			var ce *ConnError
			if !errors.As(err, &ce) || ce.Stage != "auth" || ce.Op != tc.op || ce.Kind != tc.kind {
				t.Fatalf("classification: %v", err)
			}
			if tc.cause != nil && !errors.Is(err, tc.cause) {
				t.Fatalf("lost cause %v: %v", tc.cause, err)
			}
		})
	}
}

func TestFailureClassificationPreservesWrappedCauses(t *testing.T) {
	for _, tc := range []struct {
		cause error
		kind  FailureKind
	}{
		{os.ErrDeadlineExceeded, FailureTimeout},
		{context.DeadlineExceeded, FailureTimeout},
		{context.Canceled, FailureCanceled},
		{syscall.ECONNRESET, FailureClosed},
		{syscall.EPIPE, FailureClosed},
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, FailureNetwork},
		{ErrSessionNotAllowed, FailurePolicy},
	} {
		err := connFailure("auth", "result_write", tc.cause)
		var ce *ConnError
		if !errors.As(err, &ce) || ce.Kind != tc.kind || !errors.Is(err, tc.cause) {
			t.Fatalf("classification %s lost for %v: %v", tc.kind, tc.cause, err)
		}
	}
}

type brokenReply struct{ err error }

func (b brokenReply) Write([]byte) (int, error) { return 0, b.err }
func (b brokenReply) RemoteAddr() net.Addr      { return &net.TCPAddr{} }

type failingResolver struct{ err error }

func (r failingResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, r.err
}

// The failure reply must not erase the failure which made it necessary.
func TestDestinationFailureSurvivesAClientThatCannotReadTheReply(t *testing.T) {
	for _, stage := range []string{"resolve", "connect"} {
		t.Run(stage, func(t *testing.T) {
			cause := &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
			srv, err := New(&Config{
				Resolver: failingResolver{cause},
				Dial:     func(context.Context, string, string) (net.Conn, error) { return nil, cause },
			})
			if err != nil {
				t.Fatal(err)
			}
			dest := &AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 1}
			if stage == "resolve" {
				dest.FQDN = "example.invalid"
			}
			err = srv.handleRequest(context.Background(), &Request{Command: ConnectCommand, DestAddr: dest}, brokenReply{io.ErrClosedPipe})
			var ce *ConnError
			if !errors.As(err, &ce) || ce.Stage != "dial" || ce.Op != stage || ce.Kind != FailureNetwork {
				t.Fatalf("lost primary classification: %v", err)
			}
			if !errors.Is(err, cause) || !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("both causes must survive: %v", err)
			}
		})
	}
}

func TestJoinedFailuresHaveSafeDiagnosticCodes(t *testing.T) {
	err := errors.Join(
		connFailure("dial", "connect", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}),
		connFailure("request", "reply_write", io.ErrClosedPipe),
	)
	codes := failureCodes(err)
	if len(codes) != 2 || codes[0] != "dial.connect:network" || codes[1] != "request.reply_write:peer_closed" {
		t.Fatalf("lost joined classification: %v", codes)
	}
}
