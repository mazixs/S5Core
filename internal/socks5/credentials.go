package socks5

// CredentialStore is used to support user/pass authentication
type CredentialStore interface {
	Valid(user, password string) bool
}

// SourcedCredentialStore is a credential store that also wants to know where
// the attempt came from.
//
// Rate limiting needs the source and nothing else does: a brute-force run is
// a property of the client, not of the account it happens to be guessing.
// Keying a lockout on the user name gets both halves wrong - a distributed
// run from a thousand addresses is never slowed down, and anyone who knows a
// user name can lock its owner out with a handful of wrong passwords.
//
// The source is an opaque string chosen by the caller (this package passes
// the client address). It is used as a map key and is never logged.
type SourcedCredentialStore interface {
	CredentialStore
	ValidFrom(user, password, source string) bool
}

// validFrom checks credentials through the source-aware path when the store
// supports it, and falls back to the plain one when it does not.
func validFrom(store CredentialStore, user, password, source string) bool {
	if s, ok := store.(SourcedCredentialStore); ok {
		return s.ValidFrom(user, password, source)
	}
	return store.Valid(user, password)
}

// StaticCredentials enables using a map directly as a credential store
type StaticCredentials map[string]string

func (s StaticCredentials) Valid(user, password string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return password == pass
}
