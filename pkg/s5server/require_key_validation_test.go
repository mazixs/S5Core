package s5server

import "testing"

func TestRequiringAMemberKeyNeedsAnAuthenticatedDirectory(t *testing.T) {
	for _, cfg := range []Config{
		{ObfsRequireMemberKey: true},
		{ObfsRequireMemberKey: true, RequireAuth: true},
		{ObfsRequireMemberKey: true, UsersFile: "not-opened"},
	} {
		if _, err := NewServer(cfg); err == nil {
			t.Fatalf("anonymous startup accepted: %+v", cfg)
		}
	}
}
