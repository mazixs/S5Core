package s5server_test

import (
	"fmt"

	"github.com/mazixs/S5Core/pkg/s5server"
)

func ExampleDefaultConfig() {
	cfg := s5server.DefaultConfig()
	cfg.Port = "1081"

	fmt.Println(cfg.ListenIP, cfg.Port, cfg.RequireAuth, cfg.ReadTimeout)
	// Output: 0.0.0.0 1081 true 30s
}

func ExampleParseRole() {
	for _, field := range []string{"", "operator", "root"} {
		role, err := s5server.ParseRole(field)
		if err != nil {
			fmt.Println("refused:", err)
			continue
		}
		fmt.Println(role, role.Can(s5server.ViewAccountsAction))
	}
	// Output:
	// user false
	// operator true
	// refused: identity: unknown role "root", want one of user, operator, admin
}
