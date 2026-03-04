package userstore

// CredentialAdapter wraps a Store to implement the socks5.CredentialStore interface.
type CredentialAdapter struct {
	store *Store
}

// NewCredentialAdapter creates a CredentialStore backed by the given Store.
func NewCredentialAdapter(store *Store) *CredentialAdapter {
	return &CredentialAdapter{store: store}
}

// Valid implements socks5.CredentialStore. It checks username/password
// and all business rules (enabled, TTL, traffic limit).
func (a *CredentialAdapter) Valid(user, password string) bool {
	return a.store.IsValid(user, password)
}
