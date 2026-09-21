package s5server

import "github.com/mazixs/S5Core/internal/identity"

// The account model, re-exported for the applications that embed this SDK.
//
// Roles, actions and accounts are defined in internal/identity, where the
// connection path uses them, and an internal package is by definition not
// importable from outside this module. Without the aliases below, half of the
// Admin API could be called from the repository's own tests and from nowhere
// else: Can and SetRole take values an external caller had no way to
// construct, and Accounts returned a slice whose element type could not be
// named. The aliases - not new types - keep that one model, so a value passed
// in here is the same value the server checks.

// Role is what an account may do beyond passing traffic.
type Role = identity.Role

// The roles, in the order of what they may do. An account's role is the
// "role" field of USERS_FILE; an empty field is RoleUser.
const (
	// RoleUser passes traffic and nothing else.
	RoleUser = identity.RoleUser
	// RoleOperator may read the account list and change the running server,
	// but may not create, remove or re-role accounts.
	RoleOperator = identity.RoleOperator
	// RoleAdmin may do everything, including handing out roles.
	RoleAdmin = identity.RoleAdmin
)

// ParseRole turns the "role" field of an account file into a Role, and fails
// on anything else. An unknown role is refused rather than downgraded: a
// typo must not quietly become a permission.
func ParseRole(s string) (Role, error) { return identity.ParseRole(s) }

// Action is one thing that can be asked of the server. The table of which
// role may do what is closed and lives in internal/identity.
type Action = identity.Action

const (
	// ConnectAction is using the proxy, which every known role may do.
	ConnectAction = identity.ConnectAction
	// ViewAccountsAction is reading the account list - names, roles, quotas
	// and how much of them is spent, never keys or password hashes.
	ViewAccountsAction = identity.ViewAccountsAction
	// ManageAccountsAction is creating, removing and re-roling accounts, and
	// reading a tunnel key.
	ManageAccountsAction = identity.ManageAccountsAction
	// ManageServerAction is changing the running server: the client
	// whitelist, and reloading the account file.
	ManageServerAction = identity.ManageServerAction
)

// Account is an account as the tunnel knows it: a name, a role, a policy and
// - inside the server - a tunnel key. Every Account handed out by this package
// has an empty Key; ask Admin.TunnelKey for one, which costs the admin role.
type Account = identity.Identity

// Policy is what an account may spend: whether it is enabled, the dates it is
// valid between, and its traffic limit. It is deliberately separate from Role:
// a role says what someone may do, a policy says how much.
type Policy = identity.Policy

// ErrNotAllowed is what an Admin operation returns when the account behind the
// handle may not do what was asked. It carries the role and the action, so a
// caller can tell "you may not" from "the server could not".
type ErrNotAllowed = identity.ErrNotAllowed
