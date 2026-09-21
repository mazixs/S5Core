package identity

import (
	"errors"
	"testing"
	"time"
)

// The permission table is the whole of the authorisation system, so it is
// written out here in full rather than derived: a test that recomputes Can
// from the same switch proves nothing.
func TestWhatEachRoleMayDo(t *testing.T) {
	want := map[Role]map[Action]bool{
		RoleUser: {
			ConnectAction:        true,
			ViewAccountsAction:   false,
			ManageAccountsAction: false,
			ManageServerAction:   false,
		},
		RoleOperator: {
			ConnectAction:        true,
			ViewAccountsAction:   true,
			ManageAccountsAction: false,
			ManageServerAction:   true,
		},
		RoleAdmin: {
			ConnectAction:        true,
			ViewAccountsAction:   true,
			ManageAccountsAction: true,
			ManageServerAction:   true,
		},
	}
	for role, actions := range want {
		for action, allowed := range actions {
			if got := role.Can(action); got != allowed {
				t.Errorf("%q may %s: got %v, want %v", role, action, got, allowed)
			}
			err := Authorize(role, action)
			if allowed && err != nil {
				t.Errorf("Authorize(%q, %s) = %v, want nil", role, action, err)
			}
			if !allowed && err == nil {
				t.Errorf("Authorize(%q, %s) = nil, want a refusal", role, action)
			}
		}
	}
}

// Every role passes traffic. A role is about management; whether bytes flow
// is the policy's business, and confusing the two would mean an operator
// account that cannot use the proxy it operates.
func TestEveryRoleMayConnect(t *testing.T) {
	for _, r := range []Role{RoleUser, RoleOperator, RoleAdmin} {
		if err := Authorize(r, ConnectAction); err != nil {
			t.Errorf("role %q may not connect: %v", r, err)
		}
	}
}

// An unknown role is not a role, so it gets nothing - not even connecting.
// This is what makes a typo in users.json fail closed if it ever reaches
// memory without going through ParseRole.
func TestAnUnknownRoleMayDoNothing(t *testing.T) {
	bogus := Role("superadmin")
	for _, a := range []Action{ConnectAction, ViewAccountsAction, ManageAccountsAction, ManageServerAction} {
		if bogus.Can(a) {
			t.Errorf("an unknown role was allowed to %s", a)
		}
	}
}

func TestARefusalNamesTheRoleAndTheAction(t *testing.T) {
	err := Authorize(RoleOperator, ManageAccountsAction)
	var refused *ErrNotAllowed
	if !errors.As(err, &refused) {
		t.Fatalf("got %T (%v), want *ErrNotAllowed", err, err)
	}
	if refused.Role != RoleOperator || refused.Action != ManageAccountsAction {
		t.Fatalf("the refusal says role %q action %s, want operator / manage accounts",
			refused.Role, refused.Action)
	}
}

func TestParseRole(t *testing.T) {
	cases := []struct {
		in      string
		want    Role
		wantErr bool
	}{
		// An account file written before roles existed has no role field,
		// and every account in it is a user.
		{in: "", want: RoleUser},
		{in: "user", want: RoleUser},
		{in: "operator", want: RoleOperator},
		{in: "admin", want: RoleAdmin},
		{in: "Admin", wantErr: true},
		{in: "root", wantErr: true},
		{in: " admin", wantErr: true},
	}
	for _, c := range cases {
		got, err := ParseRole(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseRole(%q) = %q, want an error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRole(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseRole(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAPolicySaysHowMuchNotWhat(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		name string
		p    Policy
		want bool
	}{
		{"an ordinary account", Policy{Enabled: true}, true},
		{"disabled", Policy{}, false},
		{"expired", Policy{Enabled: true, ValidUntil: &past}, false},
		{"not yet active", Policy{Enabled: true, ValidFrom: &future}, false},
		{"within its window", Policy{Enabled: true, ValidFrom: &past, ValidUntil: &future}, true},
		{"quota spent", Policy{Enabled: true, TrafficLimitBytes: 10, TrafficUsedBytes: 10}, false},
		{"quota left", Policy{Enabled: true, TrafficLimitBytes: 10, TrafficUsedBytes: 9}, true},
		{"no quota at all", Policy{Enabled: true, TrafficUsedBytes: 1 << 40}, true},
	}
	for _, c := range cases {
		if got := c.p.Allows(now); got != c.want {
			t.Errorf("%s: Allows = %v, want %v", c.name, got, c.want)
		}
	}
}

// The split is the point of the task: an identity has no password in it and a
// credential has nothing else.
func TestAnIdentityCarriesNoPassword(t *testing.T) {
	id := Identity{ID: "1", Name: "alice", Key: make([]byte, 32), Role: RoleAdmin}
	if !id.HasKey() {
		t.Fatal("an identity with a 32-byte key says it has none")
	}
	if (Identity{}).HasKey() {
		t.Fatal("an identity without a key says it has one")
	}
	if !(Credential{Hash: "$argon2id$..."}).HasPassword() {
		t.Fatal("a credential with a hash says it has no password")
	}
	if (Credential{}).HasPassword() {
		t.Fatal("a credential without a hash says it has one")
	}
}
