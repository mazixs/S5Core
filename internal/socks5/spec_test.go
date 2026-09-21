package socks5

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// The UDP-over-TCP framing used to live in three places - here, in
// cmd/s5client/udp_client.go and in the tests - and was written down in none.
// Plan task Ф5-1 moved it into docs/veil-spec.md, section 10. This test keeps
// the document honest about the one constant a second implementation cannot
// guess.
func TestTheSpecificationStatesTheUDPTunnelCommand(t *testing.T) {
	b, err := os.ReadFile("../../docs/veil-spec.md")
	if err != nil {
		t.Fatalf("the format specification is missing: %v", err)
	}
	spec := string(b)

	cmd := fmt.Sprintf("`0x%02X`", UDPTunnelCommand)
	if !strings.Contains(spec, cmd) {
		t.Errorf("the UDP tunnel command %s is not named in the specification", cmd)
	}
	// The command exists because it replaces the RFC one; a document that
	// names the replacement without the original does not explain the rewrite
	// the client performs.
	if orig := fmt.Sprintf("`0x%02X`", AssociateCommand); !strings.Contains(spec, orig) {
		t.Errorf("the specification names %s but not the RFC 1928 ASSOCIATE command %s it replaces", cmd, orig)
	}
}
