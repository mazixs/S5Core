package socks5

import (
	"fmt"
	"io"
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
	Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error)
	GetCode() uint8
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode
type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) GetCode() uint8 {
	return NoAuth
}

func (a NoAuthAuthenticator) Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error) {
	_, err := writer.Write([]byte{socks5Version, NoAuth})
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

func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error) {
	// Tell the client to use user/pass auth
	if _, err := writer.Write([]byte{socks5Version, UserPassAuth}); err != nil {
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
	if a.Credentials.Valid(userStr, passStr) {
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

// authenticate is used to handle connection authentication
func (s *Server) authenticate(conn io.Writer, bufConn io.Reader) (*AuthContext, error) {
	// Get the methods
	methods, err := readMethods(bufConn)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth methods: %v", err)
	}

	// Select a usable method
	for _, method := range methods {
		cator, found := s.authMethods[method]
		if found {
			return cator.Authenticate(bufConn, conn)
		}
	}

	// No usable method found
	return nil, noAcceptableAuth(conn)
}

// noAcceptableAuth is used to handle when we have no eligible
// authentication mechanism
func noAcceptableAuth(conn io.Writer) error {
	_, _ = conn.Write([]byte{socks5Version, noAcceptable})
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
