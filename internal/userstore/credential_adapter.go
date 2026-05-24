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
// After a successful validation with a legacy plaintext password, it triggers
// a lazy migration to Argon2id.
func (a *CredentialAdapter) Valid(user, password string) bool {
	if !a.store.IsValid(user, password) {
		return false
	}
	// Lazy migration: hash plaintext password on first successful use.
	a.store.MigratePassword(user, password)
	return true
}
