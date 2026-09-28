package udpbuf

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Where the relay opens UDP sockets. Each takes datagrams it does not pace,
// so each goes through this package; the server that made Ч-2 a finding
// simply never asked for a buffer.
var socketPackages = []string{
	"internal/socks5",
	"pkg/nativeudp",
	"pkg/s5server",
	"cmd/s5client",
}

func TestEveryRelaySocketIsGrown(t *testing.T) {
	for _, dir := range socketPackages {
		files, err := filepath.Glob(filepath.Join("..", "..", dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: no Go files (%v)", dir, err)
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			src, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, file, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if opensUDP(sel, call) {
					t.Errorf("%s: %s opens a UDP socket past udpbuf", fset.Position(call.Pos()), sel.Sel.Name)
				}
				return true
			})
		}
	}
}

func opensUDP(sel *ast.SelectorExpr, call *ast.CallExpr) bool {
	pkg, _ := sel.X.(*ast.Ident)
	fromNet := pkg != nil && pkg.Name == "net"
	switch sel.Sel.Name {
	case "ListenUDP", "DialUDP", "ListenMulticastUDP":
		return fromNet
	case "ListenPacket":
		return true
	case "Dial", "DialTimeout":
		if !fromNet || len(call.Args) == 0 {
			return false
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		return ok && strings.HasPrefix(strings.Trim(lit.Value, "\"`"), "udp")
	}
	return false
}
