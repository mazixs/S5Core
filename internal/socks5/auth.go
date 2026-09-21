package socks5

import (
	"fmt"
	"io"
	"net"
)

const (
	NoAuth          = uint8(0)
	noAcceptable    = uint8(255)
	UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
)

var (
	ErrUserAuthFailed  = fmt.Errorf("user authentication failed")
	ErrNoSupportedAuth = fmt.Errorf("no supported authentication mechanism")
)

// A Request encapsulates authentication state provided
// during negotiation
type AuthContext struct {
	// Provided auth method
	Method uint8
	// Payload provided during negotiation.
	// Keys depend on the used auth method.
	// For UserPassauth contains Username
	Payload map[string]string
}

type Authenticator interface {
	// Authenticate reads the method's exchange off reader and answers on
	// writer. source identifies where the connection came from; only rate
	// limiting uses it, and it is never logged.
	Authenticate(reader io.Reader, writer io.Writer, source string) (*AuthContext, error)
	GetCode() uint8
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode
type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) GetCode() uint8 {
	return NoAuth
}

func (a NoAuthAuthenticator) Authenticate(reader io.Reader, writer io.Writer, _ string) (*AuthContext, error) {
	_, err := writer.Write([]byte{Socks5Version, NoAuth})
	return &AuthContext{NoAuth, nil}, err
}

// UserPassAuthenticator is used to handle username/password based
// authentication
type UserPassAuthenticator struct {
	Credentials CredentialStore
}

func (a UserPassAuthenticator) GetCode() uint8 {
	return UserPassAuth
}

func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer, source string) (*AuthContext, error) {
	// Tell the client to use user/pass auth
	if _, err := writer.Write([]byte{Socks5Version, UserPassAuth}); err != nil {
		return nil, err
	}

	// Get the version and username length
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}

	// Ensure we are compatible
	if header[0] != userAuthVersion {
		return nil, fmt.Errorf("unsupported auth version: %v", header[0])
	}

	// Get the user name
	userLen := int(header[1])
	var userBuf [256]byte
	if _, err := io.ReadFull(reader, userBuf[:userLen]); err != nil {
		return nil, err
	}

	// Get the password length
	if _, err := io.ReadFull(reader, header[:1]); err != nil {
		return nil, err
	}

	// Get the password
	passLen := int(header[0])
	var passBuf [256]byte
	if _, err := io.ReadFull(reader, passBuf[:passLen]); err != nil {
		return nil, err
	}

	// Verify the password
	userStr := string(userBuf[:userLen])
	passStr := string(passBuf[:passLen])
	if validFrom(a.Credentials, userStr, passStr, source) {
		if _, err := writer.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return nil, err
		}
	} else {
		if _, err := writer.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return nil, err
		}
		return nil, ErrUserAuthFailed
	}

	// Done
	return &AuthContext{UserPassAuth, map[string]string{"Username": userStr}}, nil
}

// tunnelIdentity is who the transport says this connection belongs to, or
// the empty string when it does not know.
func (s *Server) tunnelIdentity(conn net.Conn) string {
	if s.config.TunnelIdentity == nil {
		return ""
	}
	return s.config.TunnelIdentity(conn)
}

// tunnelIdentityAllowed asks the account behind a tunnel identity whether it
// may still connect. A server that configures no SessionStatus has no opinion
// and every identity stands.
func (s *Server) tunnelIdentityAllowed(identity string) bool {
	if s.config.SessionStatus == nil {
		return true
	}
	return s.config.SessionStatus(identity) == SessionAllowed
}

// authenticate is used to handle connection authentication.
//
// identity, when not empty, is the member the transport underneath already
// authenticated: the password step is then skipped entirely and that name is
// what the session is accounted to. See Config.TunnelIdentity.
//
// handshake, when not nil, is the phase timer covering method negotiation: it
// is closed as soon as a method is picked, so the cost of verifying the
// credentials lands in its own phase and not in the handshake.
func (s *Server) authenticate(conn io.Writer, bufConn io.Reader, source, identity string, handshake *phaseTimer) (*AuthContext, error) {
	// Get the methods
	methods, err := readMethods(bufConn)
	if err != nil {
		handshake.end(false)
		return nil, fmt.Errorf("failed to get auth methods: %w", err)
	}

	// The tunnel says who this is, but not whether that account may still
	// connect. The two questions are answered at different times: the member
	// directory is a snapshot rebuilt when accounts change, while a quota
	// runs out, a validity window ends and an account is disabled between
	// rebuilds. Without this the stale snapshot was the whole check, and an
	// account that the password path would have turned away walked in under
	// NoAuth (F01 in docs/reports/code-quality-audit-2026-09-20.md).
	//
	// An identity that may not connect is dropped rather than refused
	// outright: it is an offer, and withdrawing it leaves the connection
	// exactly where a client with no tunnel key stands. A client that offers
	// only NoAuth then gets "no acceptable methods", and one that offers a
	// password gets it checked - by a credential store that turns the same
	// account away for the same reason.
	if identity != "" && !s.tunnelIdentityAllowed(identity) {
		s.config.Logger.Debug("socks: the tunnel identity may no longer connect",
			"identity", identity)
		identity = ""
	}

	// The tunnel has already said who this is, and said it with a MAC under
	// that member's own key. Asking for a password on top would verify a
	// weaker secret at a higher price.
	if identity != "" {
		for _, method := range methods {
			if method != NoAuth {
				continue
			}
			handshake.end(true)
			auth := s.startPhase(PhaseAuth)
			_, err := conn.Write([]byte{Socks5Version, NoAuth})
			auth.end(err == nil)
			if err != nil {
				return nil, err
			}
			return &AuthContext{NoAuth, map[string]string{"Username": identity}}, nil
		}
		// A member whose client insists on a password still gets one
		// checked below: the identity is an offer, not a requirement, and
		// a client from before this existed must keep working.
	}

	// Select a usable method
	for _, method := range methods {
		cator, found := s.authMethods[method]
		if found {
			handshake.end(true)
			auth := s.startPhase(PhaseAuth)
			authCtx, err := cator.Authenticate(bufConn, conn, source)
			auth.end(err == nil)
			return authCtx, err
		}
	}

	// No usable method found
	handshake.end(false)
	return nil, noAcceptableAuth(conn)
}

// noAcceptableAuth is used to handle when we have no eligible
// authentication mechanism
func noAcceptableAuth(conn io.Writer) error {
	_, _ = conn.Write([]byte{Socks5Version, noAcceptable})
	return ErrNoSupportedAuth
}

// readMethods is used to read the number of methods
// and proceeding auth methods
func readMethods(r io.Reader) ([]byte, error) {
	var header [1]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	_, err := io.ReadFull(r, methods)
	return methods, err
}
