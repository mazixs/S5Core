package s5server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// This package is the SDK: the thing an external Go application imports. An
// external application cannot import internal/..., so a type from there in an
// exported signature is a method nobody outside this module can call - it
// compiles here, it is covered by the tests here, and it is unusable where it
// was meant to be used.
//
// That is what happened to Admin.Can and Admin.SetRole: they took
// identity.Action and identity.Role, and Accounts returned
// []identity.Identity, so the half of the account API that F07 and F08 had
// just fixed could not be reached from outside. The aliases in identity.go
// are the fix; this test is what keeps the next signature from undoing it.
//
// Aliases themselves are exempt and are the intended way through: "type
// Account = identity.Identity" gives the outside world a name for the type,
// and it stays the same type the server checks.
func TestNoExportedSignatureNamesAnInternalType(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	files := map[string]*ast.File{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files[name] = parsed
	}
	if len(files) == 0 {
		t.Fatal("no source files found; this test parses the package it lives in")
	}

	for name, file := range files {
		internal := internalImports(file)
		if len(internal) == 0 {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch decl := n.(type) {
			case *ast.FuncDecl:
				if !exportedFunc(decl) {
					return false
				}
				checkSignature(t, fset, name, internal, decl.Name.Name, decl.Type)
				// The body may name whatever it likes.
				return false
			case *ast.TypeSpec:
				if decl.Assign.IsValid() || !decl.Name.IsExported() {
					// An alias is the sanctioned way to expose an internal
					// type; an unexported type is not part of the contract.
					return false
				}
				st, ok := decl.Type.(*ast.StructType)
				if !ok {
					return false
				}
				for _, field := range st.Fields.List {
					if !exportedField(field) {
						continue
					}
					checkType(t, fset, name, internal, "field of "+decl.Name.Name, field.Type)
				}
				return false
			}
			return true
		})
	}
}

// internalImports maps the local name of every internal import in the file to
// its path.
func internalImports(file *ast.File) map[string]string {
	found := map[string]string{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		if !strings.Contains(path, "/internal/") {
			continue
		}
		local := path[strings.LastIndex(path, "/")+1:]
		if spec.Name != nil {
			local = spec.Name.Name
		}
		found[local] = path
	}
	return found
}

// exportedFunc reports whether this declaration is reachable from outside the
// package: an exported function, or a method on an exported type.
func exportedFunc(decl *ast.FuncDecl) bool {
	if decl.Recv == nil {
		return decl.Name.IsExported()
	}
	if !decl.Name.IsExported() {
		return false
	}
	recv := decl.Recv.List[0].Type
	if star, ok := recv.(*ast.StarExpr); ok {
		recv = star.X
	}
	ident, ok := recv.(*ast.Ident)
	return ok && ident.IsExported()
}

func exportedField(field *ast.Field) bool {
	if len(field.Names) == 0 {
		return true // embedded
	}
	for _, n := range field.Names {
		if n.IsExported() {
			return true
		}
	}
	return false
}

func checkSignature(t *testing.T, fset *token.FileSet, file string, internal map[string]string, what string, sig *ast.FuncType) {
	t.Helper()
	for _, list := range []*ast.FieldList{sig.Params, sig.Results, sig.TypeParams} {
		if list == nil {
			continue
		}
		for _, field := range list.List {
			checkType(t, fset, file, internal, what, field.Type)
		}
	}
}

func checkType(t *testing.T, fset *token.FileSet, file string, internal map[string]string, what string, expr ast.Expr) {
	t.Helper()
	ast.Inspect(expr, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if path, ok := internal[ident.Name]; ok {
			t.Errorf("%s: %s names %s.%s, and %s cannot be imported from outside this module; "+
				"add an alias in identity.go and use that instead",
				fset.Position(sel.Pos()), what, ident.Name, sel.Sel.Name, path)
			_ = file
		}
		return true
	})
}
