package s5server

import (
	"fmt"

	"github.com/mazixs/S5Core/internal/identity"
)

// Plan task Ф6-3: management actions used to be available to anyone holding a
// *Server. For a program that embeds the server that is the right answer -
// holding the pointer means owning the process - but it is the wrong answer
// for the thing that pointer is usually behind: a control panel or an API,
// where the request arrives on behalf of an account and the account is not
// the process.
//
// So the management API comes in two forms. Server.AddUser and friends are
// the owner's: unchecked, because a caller who can call them can also call
// Stop. Server.As(name) returns the same actions bound to an account, and
// each one is checked against that account's role first.

// Admin is the management API acting on behalf of one account. Every method
// re-reads the account and checks its role before it does anything, and
// returns an *identity.ErrNotAllowed when the role does not have the
// permission.
//
// The handle holds a name, not a role. It used to hold a copy of the
// identity, which made it a capability: once issued it kept the permissions
// it was issued with, so an admin who demoted itself - or an account that was
// deleted outright - went on managing the server through the handle it
// already had. A handle is not a session and grants nothing on its own; the
// store is asked every time.
type Admin struct {
	srv  *Server
	name string
}

// As returns the management API bound to an account. It fails when
// authentication is off or the account does not exist - a caller must not be
// able to turn an unknown name into permissions.
func (s *Server) As(username string) (*Admin, error) {
	if s.userStore == nil {
		return nil, fmt.Errorf("authentication is not enabled, so there is nobody to act as")
	}
	if _, ok := s.userStore.Identity(username); !ok {
		return nil, fmt.Errorf("account %q does not exist", username)
	}
	return &Admin{srv: s, name: username}, nil
}

// Name is the account this handle acts as. It is what the handle holds, and
// it never changes.
func (a *Admin) Name() string { return a.name }

// actor re-reads the account from the store. An account that no longer
// exists, or one that has been disabled or has run out of time, is nobody:
// management is an action of the account, and an account that may not pass
// traffic may not run the server either.
func (a *Admin) actor() (Account, error) {
	if a.srv.userStore == nil {
		return Account{}, fmt.Errorf("authentication is not enabled")
	}
	actor, ok := a.srv.userStore.Identity(a.name)
	if !ok {
		return Account{}, fmt.Errorf("account %q no longer exists", a.name)
	}
	if !actor.Policy.Enabled {
		return Account{}, fmt.Errorf("account %q is disabled", a.name)
	}
	return actor, nil
}

// authorize is the check every method runs: who is this now, and may it do
// this now.
func (a *Admin) authorize(action Action) error {
	actor, err := a.actor()
	if err != nil {
		return err
	}
	return identity.Authorize(actor.Role, action)
}

// Actor is the account this handle acts as, as the store has it now, without
// its key. It fails once the account is gone or disabled.
func (a *Admin) Actor() (Account, error) {
	actor, err := a.actor()
	if err != nil {
		return Account{}, err
	}
	actor.Key = nil
	return actor, nil
}

// Role is what this account may do now. It fails once the account is gone or
// disabled, and the error is the answer rather than a detail: a panel that
// got RoleUser back would show a working, least-privileged session to
// somebody whose account no longer exists.
func (a *Admin) Role() (Role, error) {
	actor, err := a.actor()
	if err != nil {
		return "", err
	}
	return actor.Role, nil
}

// Can reports whether this account may perform an action, without performing
// it. A panel uses it to decide what to show.
func (a *Admin) Can(action Action) bool { return a.authorize(action) == nil }

// AddUser creates an account. Requires the admin role.
func (a *Admin) AddUser(username, password string) error {
	if err := a.authorize(ManageAccountsAction); err != nil {
		return err
	}
	return a.srv.AddUser(username, password)
}

// RemoveUser deletes an account. Requires the admin role.
func (a *Admin) RemoveUser(username string) error {
	if err := a.authorize(ManageAccountsAction); err != nil {
		return err
	}
	return a.srv.RemoveUser(username)
}

// SetRole changes what an account may do. Requires the admin role, which is
// also what stops an operator from promoting itself.
func (a *Admin) SetRole(username string, role Role) error {
	if err := a.authorize(ManageAccountsAction); err != nil {
		return err
	}
	return a.srv.SetRole(username, role)
}

// Accounts lists the accounts: names, roles and policies, without password
// hashes and without tunnel keys. Requires the operator role or better.
//
// The keys used to come with the list, which made "may see the accounts" mean
// "holds every member's tunnel key". A key is what a member is on the wire,
// so anyone with the list could raise a tunnel as anyone else, including the
// admins - and the role that was supposed to be read-only was the one that
// could do it. Handing a key out is a separate action with a separate
// permission; see TunnelKey.
func (a *Admin) Accounts() ([]Account, error) {
	if err := a.authorize(ViewAccountsAction); err != nil {
		return nil, err
	}
	if a.srv.userStore == nil {
		return nil, fmt.Errorf("authentication is not enabled")
	}
	accounts := a.srv.userStore.Identities()
	for i := range accounts {
		accounts[i].Key = nil
	}
	return accounts, nil
}

// TunnelKey returns one account's tunnel key, for handing to that account's
// client as OBFS_MEMBER_KEY. Requires the admin role: the key is the account
// on the wire, so giving it out is managing accounts, not viewing them.
func (a *Admin) TunnelKey(username string) ([]byte, error) {
	if err := a.authorize(ManageAccountsAction); err != nil {
		return nil, err
	}
	if a.srv.userStore == nil {
		return nil, fmt.Errorf("authentication is not enabled")
	}
	account, ok := a.srv.userStore.Identity(username)
	if !ok {
		return nil, fmt.Errorf("account %q does not exist", username)
	}
	if len(account.Key) == 0 {
		return nil, fmt.Errorf("account %q has no tunnel key", username)
	}
	// A copy: the caller must not be able to edit the directory's view of
	// who this member is.
	return append([]byte(nil), account.Key...), nil
}

// UpdateWhitelist changes which client addresses may connect. Requires the
// operator role or better.
func (a *Admin) UpdateWhitelist(ips []string) error {
	if err := a.authorize(ManageServerAction); err != nil {
		return err
	}
	return a.srv.UpdateWhitelist(ips)
}

// ReloadUsers re-reads the accounts file. Requires the operator role or
// better.
func (a *Admin) ReloadUsers() error {
	if err := a.authorize(ManageServerAction); err != nil {
		return err
	}
	return a.srv.ReloadUsers()
}
